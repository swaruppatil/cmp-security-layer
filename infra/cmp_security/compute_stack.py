"""Compute: ECS Fargate cluster, the ml-service (service discovery), the gateway (internal ALB),
autoscaling, log groups, alarms, and the gateway's access to CMP's Kafka (MSK) when configured.

Images are built from this repository by CDK assets (ARM64). The ml-service image is the prebuilt
one (``ml-service/Dockerfile.prebuilt``): it ships the bundles ``ml-service/models/current.json`` and
``ml-service/models/tool/current.json`` name and the model caches from ``ml-service/.cache``, so a
deploy copies and pushes about 1 GB instead of training for 20 to 30 minutes. Train and evaluate
locally first (``ml-service/training/train.py``), then deploy.
"""

from __future__ import annotations

from pathlib import Path

from aws_cdk import CfnOutput, Duration, Stack, Tags
from aws_cdk import aws_cloudwatch as cw
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs
from aws_cdk import aws_servicediscovery as sd
from constructs import Construct

from cmp_security.config import EnvConfig
from cmp_security.data_stack import DataStack
from cmp_security.network_stack import NetworkStack

REPO_ROOT = Path(__file__).resolve().parents[2]
# Transformer view served in the image: the int8 build of the model the bundles were trained with
# (app/transformer.py REGISTRY); its files must be in ml-service/.cache/transformers/<name>/.
ML_TRANSFORMER = "horizon-small-int8"


def _task_roles(scope: Construct, cfg: EnvConfig, name: str) -> dict[str, iam.Role]:
    """Task and execution roles with explicit names (``<iam_role_prefix><prefix>-<name>-task|exec``).

    CDK grants the pull/log/secret permissions on the execution role and the service's own
    permissions on the task role exactly as it does for the roles it would generate itself.
    """
    principal = iam.ServicePrincipal("ecs-tasks.amazonaws.com")
    base = f"{cfg.iam_role_prefix}{cfg.prefix}-{name}"
    return {
        "task_role": iam.Role(scope, f"{name}-task-role", role_name=f"{base}-task", assumed_by=principal),
        "execution_role": iam.Role(
            scope, f"{name}-exec-role", role_name=f"{base}-exec", assumed_by=principal
        ),
    }


ARM64 = ecs.RuntimePlatform(
    cpu_architecture=ecs.CpuArchitecture.ARM64, operating_system_family=ecs.OperatingSystemFamily.LINUX
)


def _health(port: int, path: str = "/health") -> ecs.HealthCheck:
    cmd = (
        f"python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:{port}{path}')"
        '.status==200 else 1)"'
    )
    return ecs.HealthCheck(
        command=["CMD-SHELL", cmd],
        interval=Duration.seconds(10),
        timeout=Duration.seconds(3),
        retries=5,
        start_period=Duration.seconds(90),
    )


class ComputeStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        cfg: EnvConfig,
        network: NetworkStack,
        data: DataStack,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cfg = cfg
        retention = _retention(cfg.log_retention_days)

        cluster = ecs.Cluster(
            self,
            "Cluster",
            cluster_name=f"{cfg.prefix}-security",
            vpc=network.vpc,
            container_insights_v2=ecs.ContainerInsights.ENABLED,
        )
        private = network.private_selection

        # ---------------------------------------------------------------- ml-service
        # Prebuilt image: the bundles in ml-service/models (current.json) and the model caches in
        # ml-service/.cache, with the int8 build of the transformer view; nothing is trained or
        # downloaded during the deploy (see ml-service/Dockerfile.prebuilt).
        ml_image = ecs.ContainerImage.from_asset(
            str(REPO_ROOT),
            file="ml-service/Dockerfile.prebuilt",
            platform=ecr_assets.Platform.LINUX_ARM64,
            build_args={"TRANSFORMER": ML_TRANSFORMER},
            exclude=[
                "gateway",
                "mock-ai",
                "datasets",
                "docs",
                "infra",
                "ml-service/.venv",
                "ml-service/evaluation",
                "ml-service/training",
                "ml-service/tests",
                "ml-service/.cache/.locks",
                "ml-service/.cache/models--Qdrant--all-MiniLM-L6-v2-onnx",
                "ml-service/.cache/transformers/horizon-small",
                "**/__pycache__",
                "**/.pytest_cache",
            ],
        )
        ml_task = ecs.FargateTaskDefinition(
            self,
            "MlTask",
            cpu=cfg.ml.cpu,
            memory_limit_mib=cfg.ml.memory_mib,
            runtime_platform=ARM64,
            **_task_roles(self, cfg, "ml"),
        )
        ml_task.add_container(
            "ml-service",
            image=ml_image,
            port_mappings=[ecs.PortMapping(container_port=8000)],
            environment={
                # ONNX threads per scoring call: one per vCPU (Graviton is about 3x slower per core
                # than a workstation; a 4-text call took 520 ms on 2 vCPU with 2 threads).
                "ML_EMBED_THREADS": str(max(2, cfg.ml.cpu // 1024)),
                "ML_KEEP_WARM_SECONDS": "1",
                "ML_TRANSFORMER_NAME": ML_TRANSFORMER,
                "ML_LOG_LEVEL": "info",
                "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1",
            },
            health_check=_health(8000),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="ml",
                log_group=logs.LogGroup(
                    self, "MlLogs", log_group_name=f"/{cfg.prefix}/ml-service", retention=retention
                ),
            ),
        )
        self.ml_service = ecs.FargateService(
            self,
            "MlService",
            service_name=f"{cfg.prefix}-ml-service",
            cluster=cluster,
            task_definition=ml_task,
            desired_count=cfg.ml.desired,
            security_groups=[network.sg_ml],
            vpc_subnets=private,
            min_healthy_percent=100,
            max_healthy_percent=200,
            circuit_breaker=ecs.DeploymentCircuitBreaker(enable=True, rollback=True),
            cloud_map_options=ecs.CloudMapOptions(
                name="ml",
                cloud_map_namespace=network.namespace,
                dns_record_type=sd.DnsRecordType.A,
                dns_ttl=Duration.seconds(10),
            ),
        )
        ml_scaling = self.ml_service.auto_scale_task_count(
            min_capacity=cfg.ml.min_tasks, max_capacity=cfg.ml.max_tasks
        )
        ml_scaling.scale_on_cpu_utilization("MlCpu", target_utilization_percent=55)
        ml_url = f"http://ml.{cfg.dns_namespace}:8000"

        # ---------------------------------------------------------------- mock AI app (test phase)
        upstream_url = "http://localhost:9000"
        if cfg.deploy_mock_ai:
            sg_upstream = ec2.SecurityGroup(
                self, "UpstreamSg", vpc=network.vpc, description="mock AI app", allow_all_outbound=True
            )
            sg_upstream.add_ingress_rule(network.sg_gateway, ec2.Port.tcp(9000), "gateway to mock AI")
            mock_task = ecs.FargateTaskDefinition(
                self,
                "MockAiTask",
                cpu=256,
                memory_limit_mib=512,
                runtime_platform=ARM64,
                **_task_roles(self, cfg, "mock-ai"),
            )
            mock_task.add_container(
                "mock-ai",
                image=ecs.ContainerImage.from_asset(
                    str(REPO_ROOT / "mock-ai"), platform=ecr_assets.Platform.LINUX_ARM64
                ),
                port_mappings=[ecs.PortMapping(container_port=9000)],
                health_check=_health(9000),
                logging=ecs.LogDrivers.aws_logs(
                    stream_prefix="mock",
                    log_group=logs.LogGroup(
                        self, "MockLogs", log_group_name=f"/{cfg.prefix}/mock-ai", retention=retention
                    ),
                ),
            )
            ecs.FargateService(
                self,
                "MockAiService",
                service_name=f"{cfg.prefix}-mock-ai",
                cluster=cluster,
                task_definition=mock_task,
                desired_count=1,
                security_groups=[sg_upstream],
                vpc_subnets=private,
                min_healthy_percent=0,
                max_healthy_percent=200,
                circuit_breaker=ecs.DeploymentCircuitBreaker(enable=True, rollback=True),
                cloud_map_options=ecs.CloudMapOptions(
                    name="mock-ai", cloud_map_namespace=network.namespace, dns_record_type=sd.DnsRecordType.A
                ),
            )
            upstream_url = f"http://mock-ai.{cfg.dns_namespace}:9000"

        # ---------------------------------------------------------------- gateway
        gw_image = ecs.ContainerImage.from_asset(
            str(REPO_ROOT / "gateway"),
            platform=ecr_assets.Platform.LINUX_ARM64,
            exclude=[".venv", "**/__pycache__", "**/.pytest_cache", ".mypy_cache"],
        )
        gw_task = ecs.FargateTaskDefinition(
            self,
            "GatewayTask",
            cpu=cfg.gateway.cpu,
            memory_limit_mib=cfg.gateway.memory_mib,
            runtime_platform=ARM64,
            **_task_roles(self, cfg, "gateway"),
        )
        never_ban = ",".join(["127.0.0.0/8", "::1/128", cfg.cidr, *cfg.never_ban_cidrs])
        kafka_env: dict[str, str] = {}
        if cfg.kafka_enabled and cfg.kafka_bootstrap_servers:
            kafka_env = {
                "KAFKA_BOOTSTRAP_SERVERS": cfg.kafka_bootstrap_servers,
                "KAFKA_TOPIC": cfg.kafka_topic,
                "KAFKA_TOPICS_ALLOWED": ",".join(cfg.kafka_topics_allowed),
                "KAFKA_SECURITY_PROTOCOL": cfg.kafka_security_protocol,
                "KAFKA_SASL_MECHANISM": "AWS_MSK_IAM",
                "KAFKA_AWS_REGION": cfg.region,
            }
        gw_task.add_container(
            "gateway",
            image=gw_image,
            port_mappings=[ecs.PortMapping(container_port=8080)],
            environment={
                "REDIS_URL": data.redis_url,
                "DATABASE_HOST": data.db.db_instance_endpoint_address,
                "DATABASE_PORT": data.db.db_instance_endpoint_port,
                "DATABASE_USER": "sec",
                "DATABASE_NAME": "securitylayer",
                "ML_URL": ml_url,
                "ML_TIMEOUT_MS": str(cfg.ml_timeout_ms),
                "UPSTREAM_AI_URL": upstream_url,
                **kafka_env,
                "TRUSTED_PROXY_COUNT": "1",
                "NEVER_BAN_CIDRS": never_ban,
                "AUDIT_WORKER_ENABLED": "true",
                "LOG_LEVEL": "info",
                # CMP's enricher key, created at start-up from the generated secret (data stack).
                "BOOTSTRAP_API_KEY_NAME": "cmp-enricher",
                "BOOTSTRAP_API_KEY_SCOPES": "inspect",
            },
            secrets={
                "ADMIN_API_KEY": ecs.Secret.from_secrets_manager(data.admin_api_key),
                "BOOTSTRAP_API_KEY": ecs.Secret.from_secrets_manager(data.enricher_api_key, "secret"),
                "BOOTSTRAP_API_KEY_PREFIX": ecs.Secret.from_secrets_manager(data.enricher_api_key, "prefix"),
                "IDENTITY_HASH_KEY": ecs.Secret.from_secrets_manager(data.identity_hash_key),
                "DASHBOARD_DB_PASSWORD": ecs.Secret.from_secrets_manager(data.dashboard_db_password),
                "DATABASE_PASSWORD": ecs.Secret.from_secrets_manager(data.db.secret, "password"),  # type: ignore[arg-type]
            },
            health_check=_health(8080),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="gw",
                log_group=logs.LogGroup(
                    self, "GatewayLogs", log_group_name=f"/{cfg.prefix}/gateway", retention=retention
                ),
            ),
        )
        self.gateway_service = ecs.FargateService(
            self,
            "GatewayService",
            service_name=f"{cfg.prefix}-gateway",
            cluster=cluster,
            task_definition=gw_task,
            desired_count=cfg.gateway.desired,
            security_groups=[network.sg_gateway],
            vpc_subnets=private,
            min_healthy_percent=100,
            max_healthy_percent=200,
            circuit_breaker=ecs.DeploymentCircuitBreaker(enable=True, rollback=True),
            health_check_grace_period=Duration.seconds(120),
            enable_execute_command=cfg.enable_exec,
            cloud_map_options=ecs.CloudMapOptions(
                name="gateway", cloud_map_namespace=network.namespace, dns_record_type=sd.DnsRecordType.A
            ),
        )
        self.gateway_service.node.add_dependency(self.ml_service)
        if cfg.enable_exec:  # ECS Exec: run the scenario / coverage scripts from inside the VPC
            gw_task.task_role.add_to_principal_policy(
                iam.PolicyStatement(
                    actions=[
                        "ssmmessages:CreateControlChannel",
                        "ssmmessages:CreateDataChannel",
                        "ssmmessages:OpenControlChannel",
                        "ssmmessages:OpenDataChannel",
                    ],
                    resources=["*"],
                )
            )

        # Kafka (MSK, IAM auth): the task role may connect and write to the topic; the MSK security
        # group must admit the gateway on the IAM port.
        if (
            cfg.kafka_bootstrap_servers
            and cfg.kafka_cluster_arn
            and cfg.kafka_security_protocol == "SASL_SSL"
        ):
            arn = cfg.kafka_cluster_arn  # arn:aws:kafka:<region>:<acct>:cluster/<name>/<uuid>
            topic_arn = arn.replace(":cluster/", ":topic/") + f"/{cfg.kafka_topic}"
            gw_task.task_role.add_to_principal_policy(
                iam.PolicyStatement(
                    actions=["kafka-cluster:Connect", "kafka-cluster:DescribeCluster"], resources=[arn]
                )
            )
            gw_task.task_role.add_to_principal_policy(
                iam.PolicyStatement(
                    actions=["kafka-cluster:DescribeTopic", "kafka-cluster:WriteData"], resources=[topic_arn]
                )
            )
        if cfg.kafka_enabled and cfg.kafka_security_group_id:
            msk_sg = ec2.SecurityGroup.from_security_group_id(self, "MskSg", cfg.kafka_security_group_id)
            port = 9098 if cfg.kafka_security_protocol == "SASL_SSL" else 9092
            msk_sg.add_ingress_rule(network.sg_gateway, ec2.Port.tcp(port), "gateway to MSK")

        # Internal load balancer in front of the gateway.
        self.alb = elbv2.ApplicationLoadBalancer(
            self,
            "Alb",
            load_balancer_name=f"{cfg.prefix}-gateway",
            vpc=network.vpc,
            internet_facing=False,
            security_group=network.sg_alb,
            vpc_subnets=private,
        )
        target_group = elbv2.ApplicationTargetGroup(
            self,
            "GatewayTargets",
            vpc=network.vpc,
            port=8080,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.IP,
            targets=[self.gateway_service],
            deregistration_delay=Duration.seconds(30),
            health_check=elbv2.HealthCheck(
                path="/ready",
                interval=Duration.seconds(15),
                healthy_threshold_count=2,
                unhealthy_threshold_count=3,
            ),
        )
        if cfg.alb_certificate_arn:
            listener = self.alb.add_listener(
                "Https",
                port=443,
                certificates=[elbv2.ListenerCertificate.from_arn(cfg.alb_certificate_arn)],
                default_target_groups=[target_group],
            )
            self.alb.add_listener(
                "HttpRedirect",
                port=80,
                default_action=elbv2.ListenerAction.redirect(port="443", protocol="HTTPS"),
            )
        else:
            listener = self.alb.add_listener("Http", port=80, default_target_groups=[target_group])

        # /admin/* only from the admin CIDRs; everyone else gets 403 at the load balancer.
        if cfg.admin_cidrs:
            listener.add_action(
                "AdminAllowed",
                priority=10,
                conditions=[
                    elbv2.ListenerCondition.path_patterns(["/admin/*"]),
                    elbv2.ListenerCondition.source_ips(cfg.admin_cidrs),
                ],
                action=elbv2.ListenerAction.forward([target_group]),
            )
        listener.add_action(
            "AdminDenied",
            priority=20,
            conditions=[elbv2.ListenerCondition.path_patterns(["/admin/*"])],
            action=elbv2.ListenerAction.fixed_response(
                403, content_type="application/json", message_body='{"error":"forbidden"}'
            ),
        )

        gw_scaling = self.gateway_service.auto_scale_task_count(
            min_capacity=cfg.gateway.min_tasks, max_capacity=cfg.gateway.max_tasks
        )
        gw_scaling.scale_on_cpu_utilization("GatewayCpu", target_utilization_percent=60)
        gw_scaling.scale_on_request_count(
            "GatewayRequests", requests_per_target=300, target_group=target_group
        )

        # ---------------------------------------------------------------- test runner (test phase)
        if cfg.enable_exec:
            runner_task = ecs.FargateTaskDefinition(
                self,
                "TestRunnerTask",
                cpu=512,
                memory_limit_mib=1024,
                runtime_platform=ARM64,
                **_task_roles(self, cfg, "test-runner"),
            )
            runner_task.task_role.add_to_principal_policy(
                iam.PolicyStatement(
                    actions=[
                        "ssmmessages:CreateControlChannel",
                        "ssmmessages:CreateDataChannel",
                        "ssmmessages:OpenControlChannel",
                        "ssmmessages:OpenDataChannel",
                    ],
                    resources=["*"],
                )
            )
            runner_task.add_container(
                "test-runner",
                image=ecs.ContainerImage.from_asset(
                    str(REPO_ROOT),
                    file="infra/testrunner.Dockerfile",
                    platform=ecr_assets.Platform.LINUX_ARM64,
                    exclude=[
                        "gateway/.venv",
                        "ml-service",
                        "infra/cdk.out",
                        "infra/.venv",
                        "**/__pycache__",
                        "**/.pytest_cache",
                        "datasets/public/raw",
                        "datasets/external/raw",
                    ],
                ),
                environment={
                    "GATEWAY_URL": f"http://{self.alb.load_balancer_dns_name}",
                    "ML_PUBLIC_URL": ml_url,
                },
                secrets={"ADMIN_API_KEY": ecs.Secret.from_secrets_manager(data.admin_api_key)},
                logging=ecs.LogDrivers.aws_logs(
                    stream_prefix="runner",
                    log_group=logs.LogGroup(
                        self, "RunnerLogs", log_group_name=f"/{cfg.prefix}/test-runner", retention=retention
                    ),
                ),
            )
            ecs.FargateService(
                self,
                "TestRunnerService",
                service_name=f"{cfg.prefix}-test-runner",
                cluster=cluster,
                task_definition=runner_task,
                desired_count=1,
                security_groups=[network.sg_gateway],  # may call the ALB, the ML service and the stores
                vpc_subnets=private,
                min_healthy_percent=0,
                max_healthy_percent=100,
                enable_execute_command=True,
            )

        # ---------------------------------------------------------------- alarms (no action wired; add an SNS topic per env)
        cw.Alarm(
            self,
            "UnhealthyTargets",
            metric=target_group.metrics.unhealthy_host_count(),
            threshold=1,
            evaluation_periods=2,
            alarm_description=f"{cfg.prefix}: gateway targets failing /ready",
        )
        cw.Alarm(
            self,
            "Alb5xx",
            metric=self.alb.metrics.http_code_elb(
                elbv2.HttpCodeElb.ELB_5XX_COUNT, period=Duration.minutes(1)
            ),
            threshold=10,
            evaluation_periods=3,
            alarm_description=f"{cfg.prefix}: load balancer 5xx",
        )

        # ---------------------------------------------------------------- outputs
        self.alb_dns = self.alb.load_balancer_dns_name
        CfnOutput(
            self, "GatewayUrl", value=f"{'https' if cfg.alb_certificate_arn else 'http'}://{self.alb_dns}"
        )
        CfnOutput(self, "MlServiceUrl", value=ml_url, description="inside the VPC only")
        CfnOutput(
            self,
            "EnricherApiKeySecret",
            value=data.enricher_api_key.secret_name,
            description="Secrets Manager secret CMP's enricher reads its gateway key from",
        )
        CfnOutput(self, "AdminApiKeySecret", value=data.admin_api_key.secret_name)
        CfnOutput(self, "ModelsBucket", value=data.models_bucket.bucket_name)

        for key, value in cfg.tags.items():
            Tags.of(self).add(key, value)


def _retention(days: int) -> logs.RetentionDays:
    table = {
        1: logs.RetentionDays.ONE_DAY,
        3: logs.RetentionDays.THREE_DAYS,
        5: logs.RetentionDays.FIVE_DAYS,
        7: logs.RetentionDays.ONE_WEEK,
        14: logs.RetentionDays.TWO_WEEKS,
        30: logs.RetentionDays.ONE_MONTH,
        60: logs.RetentionDays.TWO_MONTHS,
        90: logs.RetentionDays.THREE_MONTHS,
        180: logs.RetentionDays.SIX_MONTHS,
        365: logs.RetentionDays.ONE_YEAR,
    }
    return table.get(days, logs.RetentionDays.ONE_MONTH)
