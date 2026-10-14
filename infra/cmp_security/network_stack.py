"""Network: the VPC (joined or created), VPC endpoints, security groups, service-discovery namespace.

``dev`` joins CMP's existing ARC VPC (private subnets with transit-gateway egress); once the
integration is switched on, the ARC Lambdas reach the gateway's internal load balancer directly and
the gateway reaches the INT MSK brokers. ``sandbox`` creates its own VPC with no NAT and interface
endpoints instead.
"""

from __future__ import annotations

from aws_cdk import Stack, Tags
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_servicediscovery as sd
from constructs import Construct

from cmp_security.config import EnvConfig

ENDPOINT_SERVICES = {
    "ecr.api": ec2.InterfaceVpcEndpointAwsService.ECR,
    "ecr.dkr": ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
    "logs": ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
    "secretsmanager": ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
    "sts": ec2.InterfaceVpcEndpointAwsService.STS,
}


class NetworkStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, cfg: EnvConfig, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cfg = cfg

        if cfg.existing_vpc_id:
            self.vpc: ec2.IVpc = ec2.Vpc.from_vpc_attributes(
                self,
                "Vpc",
                vpc_id=cfg.existing_vpc_id,
                vpc_cidr_block=cfg.existing_vpc_cidr,
                availability_zones=cfg.existing_availability_zones,
                private_subnet_ids=cfg.existing_private_subnet_ids,
            )
            self.private_selection = ec2.SubnetSelection(subnets=self.vpc.private_subnets)
        else:
            self.vpc = ec2.Vpc(
                self,
                "Vpc",
                vpc_name=f"{cfg.prefix}-vpc",
                ip_addresses=ec2.IpAddresses.cidr(cfg.vpc_cidr),
                max_azs=cfg.max_azs,
                nat_gateways=0,
                subnet_configuration=[
                    ec2.SubnetConfiguration(
                        name="private", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, cidr_mask=20
                    ),
                    ec2.SubnetConfiguration(name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24),
                ],
            )
            self.vpc.add_gateway_endpoint("S3Endpoint", service=ec2.GatewayVpcEndpointAwsService.S3)
            self.private_selection = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)

        for name in cfg.create_vpc_endpoints:
            self.vpc.add_interface_endpoint(
                f"{name.replace('.', '-')}-endpoint",
                service=ENDPOINT_SERVICES[name],
                subnets=self.private_selection,
            )

        # One security group per hop; rules are added where both ends are known.
        self.sg_alb = ec2.SecurityGroup(
            self, "AlbSg", vpc=self.vpc, description="internal ALB", allow_all_outbound=True
        )
        self.sg_gateway = ec2.SecurityGroup(
            self, "GatewaySg", vpc=self.vpc, description="gateway tasks", allow_all_outbound=True
        )
        self.sg_ml = ec2.SecurityGroup(
            self, "MlSg", vpc=self.vpc, description="ml-service tasks", allow_all_outbound=True
        )
        self.sg_redis = ec2.SecurityGroup(
            self, "RedisSg", vpc=self.vpc, description="ElastiCache", allow_all_outbound=False
        )
        self.sg_db = ec2.SecurityGroup(
            self, "DbSg", vpc=self.vpc, description="RDS PostgreSQL", allow_all_outbound=False
        )

        # Who may call the gateway: CMP's Lambdas by security group, plus the admin CIDRs; the whole
        # VPC only when this app created it (a sandbox).
        ports = [443, 80]
        for i, sg_id in enumerate(cfg.caller_security_group_ids):
            caller = ec2.SecurityGroup.from_security_group_id(self, f"Caller{i}", sg_id, mutable=False)
            for port in ports:
                self.sg_alb.add_ingress_rule(caller, ec2.Port.tcp(port), f"CMP Lambda {sg_id}")
        for cidr in cfg.admin_cidrs if cfg.existing_vpc_id else [cfg.cidr]:
            for port in ports:
                self.sg_alb.add_ingress_rule(ec2.Peer.ipv4(cidr), ec2.Port.tcp(port), f"callers in {cidr}")
        self.sg_gateway.add_ingress_rule(self.sg_alb, ec2.Port.tcp(8080), "ALB to gateway")
        self.sg_ml.add_ingress_rule(self.sg_gateway, ec2.Port.tcp(8000), "gateway to ml-service")
        self.sg_redis.add_ingress_rule(self.sg_gateway, ec2.Port.tcp(6379), "gateway to Redis")
        self.sg_db.add_ingress_rule(self.sg_gateway, ec2.Port.tcp(5432), "gateway to PostgreSQL")

        # Private DNS for service discovery: ml.<namespace>.
        self.namespace: sd.IPrivateDnsNamespace
        if cfg.existing_namespace_id and cfg.existing_namespace_arn:
            self.namespace = sd.PrivateDnsNamespace.from_private_dns_namespace_attributes(
                self,
                "Namespace",
                namespace_id=cfg.existing_namespace_id,
                namespace_arn=cfg.existing_namespace_arn,
                namespace_name=cfg.dns_namespace,
            )
        else:
            self.namespace = sd.PrivateDnsNamespace(
                self,
                "Namespace",
                name=cfg.dns_namespace,
                vpc=self.vpc,
                description=f"{cfg.prefix} service discovery",
            )

        for key, value in cfg.tags.items():
            Tags.of(self).add(key, value)
