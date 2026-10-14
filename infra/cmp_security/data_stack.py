"""Data: ElastiCache (Redis), RDS PostgreSQL, Secrets Manager secrets, S3 bucket for model artifacts.

The gateway reads Redis and PostgreSQL; nothing durable lives in a container. Secrets are generated
here and injected into the task definitions by the compute stack.
"""

from __future__ import annotations

import hashlib
import json

from aws_cdk import Duration, RemovalPolicy, Stack, Tags
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_elasticache as elasticache
from aws_cdk import aws_rds as rds
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as sm
from constructs import Construct

from cmp_security.config import EnvConfig
from cmp_security.network_stack import NetworkStack


def _selection_kwargs(network: NetworkStack) -> dict[str, object]:
    sel = network.private_selection
    return {"subnets": sel.subnets} if sel.subnets else {"subnet_type": sel.subnet_type}


class DataStack(Stack):
    def __init__(
        self, scope: Construct, construct_id: str, cfg: EnvConfig, network: NetworkStack, **kwargs: object
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cfg = cfg
        removal = RemovalPolicy.DESTROY if cfg.destroy_data_on_delete else RemovalPolicy.RETAIN
        private = network.vpc.select_subnets(**_selection_kwargs(network))

        # ---------------------------------------------------------------- secrets
        def generated(cid: str, name: str, length: int = 48) -> sm.Secret:
            return sm.Secret(
                self,
                cid,
                secret_name=cfg.secret_name(name),
                description=f"{cfg.prefix} {name}",
                generate_secret_string=sm.SecretStringGenerator(
                    exclude_punctuation=True, password_length=length, include_space=False
                ),
                removal_policy=removal,
            )

        self.admin_api_key = generated("AdminApiKey", "admin-api-key")
        self.identity_hash_key = generated("IdentityHashKey", "identity-hash-key", 64)
        self.dashboard_db_password = generated("DashboardDbPassword", "dashboard-db-password", 32)
        # Caller key for CMP's enricher, generated here so no one has to copy a key around: JSON
        # {"prefix": <10 hex>, "secret": <random>}. The gateway creates the key
        # ``cmpsk_<prefix>_<secret>`` at start-up (BOOTSTRAP_API_KEY + BOOTSTRAP_API_KEY_PREFIX) and
        # the enricher composes the same string from the same secret. The prefix is public (it is
        # how the gateway indexes keys) and fixed per environment so a redeploy keeps the key.
        self.enricher_key_prefix = hashlib.sha256(f"{cfg.prefix}/cmp-enricher".encode()).hexdigest()[:10]
        self.enricher_api_key = sm.Secret(
            self,
            "EnricherApiKey",
            secret_name=cfg.secret_name("cmp-enricher-api-key"),
            description=f"{cfg.prefix} caller key for CMP's enricher (prefix + secret)",
            generate_secret_string=sm.SecretStringGenerator(
                secret_string_template=json.dumps({"prefix": self.enricher_key_prefix}),
                generate_string_key="secret",
                exclude_punctuation=True,
                password_length=43,
                include_space=False,
            ),
            removal_policy=removal,
        )

        # ---------------------------------------------------------------- Redis
        subnet_group = elasticache.CfnSubnetGroup(
            self,
            "RedisSubnets",
            description=f"{cfg.prefix} redis subnets",
            subnet_ids=private.subnet_ids,
            cache_subnet_group_name=cfg.rn("redis"),
        )
        if cfg.redis_multi_az:
            group = elasticache.CfnReplicationGroup(
                self,
                "Redis",
                replication_group_id=cfg.rn("redis"),
                replication_group_description=f"{cfg.prefix} security gateway state",
                engine="redis",
                engine_version="7.1",
                cache_node_type=cfg.redis_node_type,
                num_cache_clusters=2,
                multi_az_enabled=True,
                automatic_failover_enabled=True,
                transit_encryption_enabled=True,
                at_rest_encryption_enabled=True,
                cache_subnet_group_name=subnet_group.cache_subnet_group_name,
                security_group_ids=[network.sg_redis.security_group_id],
            )
            group.node.add_dependency(subnet_group)
            group.apply_removal_policy(removal)
            self.redis_url = (
                f"rediss://{group.attr_primary_end_point_address}:{group.attr_primary_end_point_port}"
            )
        else:
            node = elasticache.CfnCacheCluster(
                self,
                "Redis",
                cluster_name=cfg.rn("redis"),
                engine="redis",
                engine_version="7.1",
                cache_node_type=cfg.redis_node_type,
                num_cache_nodes=1,
                cache_subnet_group_name=subnet_group.cache_subnet_group_name,
                vpc_security_group_ids=[network.sg_redis.security_group_id],
            )
            node.node.add_dependency(subnet_group)
            node.apply_removal_policy(removal)
            self.redis_url = f"redis://{node.attr_redis_endpoint_address}:{node.attr_redis_endpoint_port}"

        # ---------------------------------------------------------------- PostgreSQL
        self.db = rds.DatabaseInstance(
            self,
            "Postgres",
            instance_identifier=cfg.rn("postgres"),
            engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_16),
            instance_type=ec2.InstanceType(cfg.db_instance_class),
            vpc=network.vpc,
            vpc_subnets=network.private_selection,
            security_groups=[network.sg_db],
            credentials=rds.Credentials.from_generated_secret("sec", secret_name=cfg.secret_name("postgres")),
            database_name="securitylayer",  # "security" is a reserved word for RDS PostgreSQL
            multi_az=cfg.db_multi_az,
            allocated_storage=20 if not cfg.db_multi_az else 100,
            storage_type=rds.StorageType.GP3,
            storage_encrypted=True,
            backup_retention=Duration.days(cfg.db_backup_days),
            deletion_protection=cfg.db_deletion_protection,
            removal_policy=removal,
            cloudwatch_logs_exports=["postgresql"],
            auto_minor_version_upgrade=True,
        )

        # ---------------------------------------------------------------- model artifacts
        self.models_bucket = s3.Bucket(
            self,
            "Models",
            bucket_name=None,  # generated: bucket names are global
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=removal,
            # No auto_delete_objects: it adds a custom-resource provider whose IAM role CDK names
            # itself, which the shared accounts' role-naming policy rejects (see iam_role_prefix).
            # Empty the bucket by hand before `cdk destroy` when destroy_data_on_delete is set.
            auto_delete_objects=False,
        )

        for key, value in cfg.tags.items():
            Tags.of(self).add(key, value)
