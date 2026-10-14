"""Per-environment settings for the CDK app.

One ``EnvConfig`` per environment:

* **dev** (the default): the security layer deployed into CMP's ARC VPC in the AC-CCT-INT account as
  a standalone test deployment: mock AI app and test runner included, **no connection to CMP** (no
  Kafka publishing, no Lambda access) until the deployment is verified on the server. The ARC values
  (MSK brokers, topic, Lambda security groups) are recorded here for the later integration step.
  Values come from ``ac-cct-channel-manager-proxy/configs/config-arc.ini`` and the account (2026-10-14).
* **sandbox**: the same layer in its own VPC, for working on the gateway without CMP's network.
* **prod**: template to fill from ``environment-infrastructure.md``.

Stack and resource names carry ``prefix`` (``security-layer-<env>``) so they cannot collide with other
teams' resources in the shared account.

Everything that differs between environments lives here; the stacks read only this object.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ServiceSize:
    cpu: int  # Fargate CPU units (256 = 0.25 vCPU)
    memory_mib: int
    desired: int
    min_tasks: int
    max_tasks: int


@dataclass(frozen=True)
class EnvConfig:
    name: str  # prefixes every stack and resource name
    account: str | None  # None: resolved from the CLI profile at deploy
    region: str
    dns_namespace: str  # private DNS namespace for service discovery (ml.<namespace>)
    gateway: ServiceSize
    ml: ServiceSize
    # ---- network: either join an existing VPC (CMP's) or create one
    existing_vpc_id: str | None = None
    existing_vpc_cidr: str | None = None
    existing_private_subnet_ids: list[str] = field(default_factory=list)
    existing_availability_zones: list[str] = field(default_factory=list)
    # Reuse an existing Cloud Map namespace with that name instead of creating one (its id and ARN).
    # Needed when a namespace outlived a rolled-back stack: a VPC cannot have two private hosted zones
    # with the same name, and the deploying role cannot delete namespaces in the shared account.
    existing_namespace_id: str | None = None
    existing_namespace_arn: str | None = None
    vpc_cidr: str = "10.42.0.0/16"  # used only when creating a VPC
    max_azs: int = 2
    # Interface endpoints to create: "ecr.api", "ecr.dkr", "logs", "secretsmanager", "sts" (the S3
    # gateway endpoint is always added when the VPC is created). Empty for a VPC that has egress.
    create_vpc_endpoints: list[str] = field(default_factory=list)
    # Security groups allowed to call the gateway through the ALB (CMP's Lambdas). The VPC CIDR is
    # allowed as well when the VPC is created by this app.
    caller_security_group_ids: list[str] = field(default_factory=list)
    # Test phase: the mock AI app (proxy-mode target for the scenario suite) and ECS Exec on the
    # gateway so the test scripts run from inside the VPC.
    deploy_mock_ai: bool = False
    enable_exec: bool = False
    # ---- Kafka: the topic CMP's enricher publishes customer messages to. ``kafka_enabled`` is the
    # integration switch: False keeps the values recorded but the gateway publishes nothing.
    kafka_enabled: bool = False
    kafka_bootstrap_servers: str | None = None
    kafka_topic: str = "ac-cct-cmp-inbound-messages-arc"
    # Other topics the enricher may name per contact (publish.topic): the bravo inbound topic.
    kafka_topics_allowed: list[str] = field(default_factory=list)
    kafka_security_protocol: str = "PLAINTEXT"  # PLAINTEXT (9092, as CMP's Lambdas) | SASL_SSL (IAM, 9098)
    kafka_cluster_arn: str | None = None  # IAM policy for SASL_SSL/IAM only
    kafka_security_group_id: str | None = None  # only when the MSK SG does not already admit the VPC
    # ---- ElastiCache
    redis_node_type: str = "cache.t4g.micro"
    redis_multi_az: bool = False
    # ---- RDS
    db_instance_class: str = "t4g.micro"
    db_multi_az: bool = False
    db_backup_days: int = 7
    db_deletion_protection: bool = False
    # ---- IAM: every role this app creates is named "<iam_role_prefix><prefix>-<service>-task|exec".
    # The shared accounts' service control policy only allows creating roles whose name starts with
    # the account's prefix ("ac-cct-" in AC-CCT-INT); an unprefixed name is denied at deploy.
    iam_role_prefix: str = ""
    # Managed policy (name, in the target account) applied as the permissions boundary of every role
    # this app creates. The shared accounts' service control policy denies iam:CreateRole without it
    # (Control Tower customisation "cfct"); roles created by other CMP stacks carry the same one.
    iam_permissions_boundary: str | None = None
    # ---- exposure
    alb_certificate_arn: str | None = None  # None: plain HTTP 80 on the internal ALB
    admin_cidrs: list[str] = field(default_factory=list)  # who may call /admin/* through the ALB
    # ---- gateway settings that depend on the environment
    never_ban_cidrs: list[str] = field(default_factory=list)  # CMP egress ranges; the VPC CIDR is added
    ml_timeout_ms: int = 150
    log_retention_days: int = 30
    destroy_data_on_delete: bool = False  # cdk destroy removes stores and their data
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def cidr(self) -> str:
        return self.existing_vpc_cidr or self.vpc_cidr

    @property
    def prefix(self) -> str:
        return f"security-layer-{self.name}"


# CMP ARC environment, AC-CCT-INT account (982081066747), ca-central-1. Shared INT MSK cluster.
ARC_VPC_ID = "vpc-0761edb89dad92a02"
ARC_VPC_CIDR = "10.111.192.0/22"
ARC_PRIVATE_SUBNETS = {  # AC-CCT-INT-vpc-01-private-*
    "ca-central-1a": "subnet-0d18260c4ab214b73",
    "ca-central-1b": "subnet-0b41d8610a3d0bc54",
    "ca-central-1d": "subnet-09fb607cb53831fd4",
}
ARC_LAMBDA_SGS = {
    "message-metadata-enrich": "sg-094110f3618448c8c",
    "ai-agent": "sg-0cc3b2b6b9da27f6a",
    "message-processor": "sg-0e676b6c0904ac06c",
    "start-chat": "sg-0f692940dad2cdfbc",
    "idv-callback": "sg-0018c5217f489c511",
}
INT_MSK_BOOTSTRAP_PLAINTEXT = (
    "b-1.accctmskintcac1.z22bz6.c3.kafka.ca-central-1.amazonaws.com:9092,"
    "b-2.accctmskintcac1.z22bz6.c3.kafka.ca-central-1.amazonaws.com:9092,"
    "b-3.accctmskintcac1.z22bz6.c3.kafka.ca-central-1.amazonaws.com:9092"
)
INT_MSK_CLUSTER_ARN = (
    "arn:aws:kafka:ca-central-1:982081066747:cluster/ac-cct-msk-int-cac1/"
    "99453162-03e2-45f0-96c1-45d24ab24a86-3"
)

DEV = EnvConfig(
    name="dev",
    account="982081066747",
    region="ca-central-1",
    dns_namespace="dev.security-layer.local",
    # Left behind by the first (rolled-back) network stack on 2026-10-14; reused rather than recreated.
    existing_namespace_id="ns-tu3bl2ig5kbngcfq",
    existing_namespace_arn=(
        "arn:aws:servicediscovery:ca-central-1:982081066747:namespace/ns-tu3bl2ig5kbngcfq"
    ),
    gateway=ServiceSize(cpu=512, memory_mib=1024, desired=1, min_tasks=1, max_tasks=3),
    # 4 vCPU: measured on Fargate Graviton, 2 vCPU scored one text in ~83 ms and four texts in ~520 ms,
    # which overran the gateway's ML budget on multi-segment messages.
    ml=ServiceSize(cpu=4096, memory_mib=8192, desired=1, min_tasks=1, max_tasks=2),
    existing_vpc_id=ARC_VPC_ID,
    existing_vpc_cidr=ARC_VPC_CIDR,
    existing_private_subnet_ids=list(ARC_PRIVATE_SUBNETS.values()),
    existing_availability_zones=list(ARC_PRIVATE_SUBNETS.keys()),
    # The VPC routes 0.0.0.0/0 through a transit gateway and already has ecr.api, s3, secretsmanager
    # and sts endpoints: nothing to add.
    create_vpc_endpoints=[],
    # Integration with ARC CMP (switched on 2026-10-15 after the standalone tests passed): the ARC
    # Lambdas may call the gateway, and it publishes passed messages to the inbound topic the enricher
    # names per contact (default or bravo). The enricher side is config-arc.ini of the CMP repo
    # (security_gateway_* keys), first in monitor mode.
    caller_security_group_ids=list(ARC_LAMBDA_SGS.values()),
    deploy_mock_ai=True,  # still used by the scenario suite's proxy-mode checks
    enable_exec=True,  # test runner stays for the integration tests
    kafka_enabled=True,
    kafka_bootstrap_servers=INT_MSK_BOOTSTRAP_PLAINTEXT,
    kafka_topic="ac-cct-cmp-inbound-messages-arc",
    kafka_topics_allowed=["ac-cct-cmp-inbound-messages-bravo-arc"],
    # The cluster allows unauthenticated 9092 from 10.0.0.0/8, which is how CMP's Lambdas publish.
    kafka_security_protocol="PLAINTEXT",
    kafka_cluster_arn=INT_MSK_CLUSTER_ARN,
    kafka_security_group_id=None,  # sg-089ac2b116b37e120 already admits 10.0.0.0/8 on 9092
    redis_node_type="cache.t4g.micro",
    redis_multi_az=False,
    db_instance_class="t4g.micro",
    db_multi_az=False,
    db_backup_days=7,
    db_deletion_protection=False,
    iam_role_prefix="ac-cct-",
    iam_permissions_boundary="cfct-permission-boundary-policy",
    alb_certificate_arn=None,  # ACM cert for security-gateway.dev.ac-cct-int.cloud.aircanada.com once issued
    admin_cidrs=[ARC_VPC_CIDR],  # the test runner (and anything else in the VPC) may use /admin
    never_ban_cidrs=[],
    ml_timeout_ms=400,  # Fargate ML latency, see the ml ServiceSize note; 150 locally
    log_retention_days=14,
    destroy_data_on_delete=True,
    tags={"project": "cmp-security-layer", "environment": "dev", "owner": "security"},
)

SANDBOX = EnvConfig(
    name="sandbox",
    account=None,
    region="ca-central-1",
    dns_namespace="sandbox.security-layer.local",
    gateway=ServiceSize(cpu=512, memory_mib=1024, desired=1, min_tasks=1, max_tasks=3),
    ml=ServiceSize(cpu=2048, memory_mib=4096, desired=1, min_tasks=1, max_tasks=2),
    vpc_cidr="10.42.0.0/16",
    max_azs=2,
    create_vpc_endpoints=["ecr.api", "ecr.dkr", "logs", "secretsmanager", "sts"],
    deploy_mock_ai=True,
    enable_exec=True,
    admin_cidrs=["10.42.0.0/16"],
    log_retention_days=14,
    destroy_data_on_delete=True,
    tags={"project": "cmp-security-layer", "environment": "sandbox", "owner": "security"},
)

PROD = EnvConfig(
    name="prod",
    account=None,
    region="ca-central-1",
    dns_namespace="prod.security-layer.local",
    gateway=ServiceSize(cpu=512, memory_mib=1024, desired=2, min_tasks=2, max_tasks=6),
    ml=ServiceSize(cpu=2048, memory_mib=4096, desired=2, min_tasks=2, max_tasks=4),
    # Fill from environment-infrastructure.md (AC-CCT-PROD 992270666036, MSK ac-cct-msk-prod-cac1,
    # topic ac-cct-cmp-inbound-messages-prod) and the prod Lambda security groups.
    existing_vpc_id=None,
    kafka_bootstrap_servers=None,
    kafka_topic="ac-cct-cmp-inbound-messages-prod",
    kafka_security_protocol="SASL_SSL",
    redis_node_type="cache.m7g.large",
    redis_multi_az=True,
    db_instance_class="m7g.large",
    db_multi_az=True,
    db_backup_days=7,
    db_deletion_protection=True,
    alb_certificate_arn=None,
    admin_cidrs=[],
    log_retention_days=90,
    destroy_data_on_delete=False,
    tags={"project": "cmp-security-layer", "environment": "prod", "owner": "security"},
)

ENVIRONMENTS: dict[str, EnvConfig] = {c.name: c for c in (DEV, SANDBOX, PROD)}
DEFAULT_ENV = DEV.name
