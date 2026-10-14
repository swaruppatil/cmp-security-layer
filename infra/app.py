"""CDK entry point.

    cd infra
    uv sync
    npx aws-cdk@2 synth  -c env=dev
    npx aws-cdk@2 deploy -c env=dev --all

``-c env=<name>`` picks the environment from ``cmp_security/config.py`` (default ``dev``: the test
deployment in CMP's ARC VPC, not connected to CMP; ``sandbox``: own VPC; ``prod``: template). Three
stacks per environment, deployed in order: network, data, compute.
"""

from __future__ import annotations

import os

import aws_cdk as cdk
from aws_cdk import aws_iam as iam

from cmp_security.compute_stack import ComputeStack
from cmp_security.config import DEFAULT_ENV, ENVIRONMENTS
from cmp_security.data_stack import DataStack
from cmp_security.network_stack import NetworkStack

app = cdk.App()
env_name = app.node.try_get_context("env") or DEFAULT_ENV
if env_name not in ENVIRONMENTS:
    raise SystemExit(f"unknown environment {env_name!r}; known: {', '.join(ENVIRONMENTS)}")
cfg = ENVIRONMENTS[env_name]

# Permissions boundary on every role, including the ones CDK's custom-resource providers create
# (those read the context key; the aspect below covers the Role constructs).
if cfg.iam_permissions_boundary:
    app.node.set_context("@aws-cdk/core:permissionsBoundary", {"name": cfg.iam_permissions_boundary})

aws_env = cdk.Environment(
    account=cfg.account or os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=cfg.region or os.environ.get("CDK_DEFAULT_REGION"),
)
# Accounts bootstrapped with CMP's custom toolkit (qualifier such as "bat-cac1") name the bucket,
# the repository and the roles without the region suffix the default synthesizer expects.
synth_kwargs: dict[str, object] = {}
if cfg.cdk_qualifier:
    q, acct = cfg.cdk_qualifier, cfg.account

    def role(kind: str) -> str:
        return f"arn:${{AWS::Partition}}:iam::{acct}:role/cdk-{q}-{kind}-role-{acct}"

    synth_kwargs["synthesizer"] = cdk.DefaultStackSynthesizer(
        qualifier=q,
        file_assets_bucket_name=f"cdk-{q}-assets-{acct}",
        image_assets_repository_name=f"cdk-{q}-container-assets-{acct}",
        deploy_role_arn=role("deploy"),
        file_asset_publishing_role_arn=role("file-publishing"),
        image_asset_publishing_role_arn=role("image-publishing"),
        cloud_formation_execution_role=role("cfn-exec"),
        lookup_role_arn=role("lookup"),
        bootstrap_stack_version_ssm_parameter=f"/cdk-bootstrap/{q}/version",
    )

network = NetworkStack(
    app,
    cfg.rn("network"),
    cfg,
    env=aws_env,
    **synth_kwargs,
    description=f"{cfg.prefix}: VPC, endpoints, security groups",
)
data = DataStack(
    app,
    cfg.rn("data"),
    cfg,
    network,
    env=aws_env,
    **synth_kwargs,
    description=f"{cfg.prefix}: Redis, PostgreSQL, secrets, S3",
)
compute = ComputeStack(
    app,
    cfg.rn("compute"),
    cfg,
    network,
    data,
    env=aws_env,
    **synth_kwargs,
    description=f"{cfg.prefix}: ECS services and ALB",
)
# Stack order (network → data → compute) follows from the cross-stack references.

if cfg.iam_permissions_boundary:
    for stack in (network, data, compute):
        iam.PermissionsBoundary.of(stack).apply(
            iam.ManagedPolicy.from_managed_policy_name(
                stack, "PermissionsBoundary", cfg.iam_permissions_boundary
            )
        )

app.synth()
