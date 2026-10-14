# infra: AWS CDK app for the CMP security gateway

Deploys the stack described in [docs/deployment-aws.md](../docs/deployment-aws.md) with the AWS CDK
(Python). One set of three stacks per environment:

* **`dev`** (default): the security layer in CMP's ARC VPC (`vpc-0761edb89dad92a02`, AC-CCT-INT
  account) as a standalone test deployment: mock AI and test runner included, **not connected to
  CMP** (no Kafka publishing, no Lambda access). The ARC values for the later integration (MSK
  brokers, `ac-cct-cmp-inbound-messages-arc`, Lambda security groups) are recorded in
  `cmp_security/config.py`, sourced from `ac-cct-channel-manager-proxy/configs/config-arc.ini` and the
  account on 2026-10-14. Stacks and resources are prefixed `security-layer-dev`.
* **`bat`**: the layer in CMP's BAT VPC (`vpc-004a501b6a94f294a`, AC-CCT-BAT `209479273605`), named
  under the new scheme `cmp-security-layer-<component>-<env>`: stacks `cmp-security-layer-network-bat`
  / `-data-bat` / `-compute-bat`, cluster `cmp-security-layer-bat`, services
  `cmp-security-layer-gateway-bat` / `-ml-service-bat` / `-mock-ai-bat` / `-test-runner-bat`, ALB
  `cmp-security-layer-gateway-bat`, RDS `cmp-security-layer-postgres-bat`, Redis
  `cmp-security-layer-redis-bat`, secrets `cmp-security-layer/<name>-bat`, log groups
  `/cmp-security-layer-<service>-bat`, roles `ac-cct-cmp-security-layer-<service>-task|exec-bat`,
  namespace `bat.cmp-security-layer.local`. Values from `configs/config-bat.ini` of the CMP repo.
  `dev` keeps its earlier `security-layer-dev-…` names until it is redeployed under the new scheme
  (`resource_prefix` in `config.py`).
* **`sandbox`**: the same layer in its own VPC.
* **`prod`**: template to fill from `environment-infrastructure.md`.

| Stack | Contents |
|---|---|
| `<env>-network` | VPC (private subnets, no NAT), VPC endpoints (ECR, S3, Secrets Manager, Logs, STS), one security group per hop, private DNS namespace |
| `<env>-data` | ElastiCache Redis (single node in dev, Multi-AZ + TLS in prod), RDS PostgreSQL 16, Secrets Manager secrets (admin key, identity hash key, dashboard password, DB credentials), S3 bucket for model artifacts |
| `<env>-compute` | ECS Fargate cluster; `ml-service` (Cloud Map `ml.<ns>`), `gateway` behind an internal ALB (`/admin/*` restricted to the admin CIDRs); IAM and security-group access to CMP's MSK topic when configured; autoscaling; log groups; alarms |

Environment differences live in `cmp_security/config.py` (`DEV`, `PROD`): sizes, Multi-AZ, TLS
certificate, admin CIDRs, CMP never-ban ranges, log retention, whether `cdk destroy` deletes data.

## Prerequisites

* Node 18+ (for the CDK CLI), Docker with buildx (images are built for ARM64), `uv`.
* An AWS profile with rights to create the resources, and CDK bootstrapped in the account/region:
  `npx aws-cdk@2 bootstrap aws://<account>/<region> --profile <profile>`.

## Deploy `dev` (dev integration with CMP)

```bash
cd infra
uv sync
set -a; source ../../aws_env.sh; set +a          # AC-CCT-INT credentials (never committed)
npx aws-cdk@latest bootstrap aws://982081066747/ca-central-1   # once per account
npx aws-cdk@latest synth  -c env=dev
# 1. network + data first (security groups, namespace, ElastiCache, RDS, secrets: ~10 minutes)
npx aws-cdk@latest deploy -c env=dev security-layer-dev-network security-layer-dev-data --require-approval never
# 2. meanwhile, warm the image cache (optional; `cdk deploy` builds the same images)
(cd .. && docker build -f ml-service/Dockerfile.prebuilt --platform linux/arm64 -t cmp-security-ml-service:prebuilt .)
# 3. compute (builds/pushes the four images, creates the services and the ALB)
npx aws-cdk@latest deploy -c env=dev security-layer-dev-compute --require-approval never
```

Deploying into a shared corporate VPC: the app creates no subnets, endpoints or routes there, only
security groups, the ECS services, an internal ALB, a Cloud Map namespace, ElastiCache and RDS in the
three private subnets. Check with the account owners that the subnet IP budget allows it (the three
private /24s) before the first deploy.

**The ml-service image is prebuilt** (`ml-service/Dockerfile.prebuilt`): it ships the bundles named by
`ml-service/models/current.json` and `ml-service/models/tool/current.json`, the model caches in
`ml-service/.cache` (embedding model, int8 transformer view) and the locked runtime dependencies as
wheels (`ml-service/.wheels`), and loads both models once during the build as a check. Nothing is
trained or downloaded during the deploy (package downloads from inside Docker Desktop go through its
proxy on this network and stall), so the compute stack takes about 10 minutes, mostly pushing ~1 GB
of layers. Train and evaluate on a workstation first, then prepare the image inputs:

```bash
cd ml-service
uv run python -m training.train --data ../datasets --out models --cache-dir .cache --strict
uv run python -m training.train --data ../datasets --data ../datasets/tool --out models/tool --cache-dir .cache \
  --name tool --budget-set toolcontent --budget-set handwritten
uv run python -m evaluation.evaluate
uv run python prepare_prebuilt.py      # checks the bundles, fetches the int8 view, downloads the wheels
```

The int8 transformer files live in `ml-service/.cache/transformers/horizon-small-int8/` (`model.onnx`
is `onnx/model_quantized.onnx` of `Horizon-Labs/prompt-injection-guard-small`, revision
`e0e88c4e…`, plus `tokenizer.json` and `config.json`); `app/transformer.py` downloads them on first use
(`get_transformer("horizon-small-int8", ".cache")`). The service picks the view with
`ML_TRANSFORMER_NAME`, set in the image and the task definition.

Outputs after deploy: `GatewayUrl` (internal ALB; reachable only inside the VPC), the Secrets Manager
name of the admin key, the models bucket.

Cloud Map namespace: the dev config reuses the namespace `dev.security-layer.local`
(`ns-tu3bl2ig5kbngcfq`) that the first, rolled-back network stack left behind; CloudFormation could
not recreate it (one private hosted zone per name per VPC) and the deploying role cannot delete
namespaces in the shared account. `existing_namespace_id`/`existing_namespace_arn` in `config.py`
import it; clear them to create a fresh one in another VPC or account.

First steps after the deploy, from a host inside the VPC (bastion, CloudShell in the VPC, or a Lambda):

```bash
ADMIN=$(aws secretsmanager get-secret-value --secret-id security-layer-dev/admin-api-key --query SecretString --output text --profile <profile>)
curl -s $GATEWAY_URL/ready
curl -s -X POST $GATEWAY_URL/admin/api-keys -H "x-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"name":"cmp-enricher-dev","scopes":["inspect"]}'
```

Then follow `docs/integration-with-cmp.md` §2 (keys, protected prompt, canary) and run the scenario
suite with `--url $GATEWAY_URL`.

## Deploy `bat`

Same procedure with `-c env=bat` and the AC-CCT-BAT credentials. Before the first deploy, fill in
`config.py`: `BAT_VPC_CIDR` (`aws ec2 describe-vpcs --vpc-ids vpc-004a501b6a94f294a`), and check the
account: CDK bootstrap (`cdk-hnb659fds-*` roles, or set `cdk_qualifier` to the account's own
toolkit qualifier, e.g. `bat-cac1`), the `cfct-permission-boundary-policy` policy, and whether the
MSK security group `sg-00b5184a46495279b` admits the VPC on 9092 (otherwise set
`kafka_security_group_id`). The first deploy is standalone (no Lambda access, no Kafka); after the
ECS Exec tests, set `BAT_LAMBDA_SGS` from the account, `caller_security_group_ids`,
`kafka_enabled=True`, redeploy, and add the `security_gateway_*` keys to `configs/config-bat.ini`
in the CMP repo (secret `cmp-security-layer/cmp-enricher-api-key-bat`, the BAT ALB URL).

```bash
cd infra && set -a; source <bat credentials file>; set +a
npx aws-cdk@latest deploy -c env=bat cmp-security-layer-network-bat cmp-security-layer-data-bat --require-approval never
npx aws-cdk@latest deploy -c env=bat cmp-security-layer-compute-bat --require-approval never
```

## Test phase on `dev` (before wiring CMP in)

`dev` starts with `kafka_enabled=False`, `deploy_mock_ai=True` and `enable_exec=True`: the gateway
publishes nothing, the mock AI app answers proxy-mode calls, and a **test-runner** task (gateway
scripts + datasets) sits in the VPC. Run the same checks as locally through ECS Exec:

```bash
CLUSTER=security-layer-dev-security
TASK=$(aws ecs list-tasks --cluster $CLUSTER --service-name security-layer-dev-test-runner --query 'taskArns[0]' --output text)
aws ecs execute-command --cluster $CLUSTER --task $TASK --container test-runner --interactive \
  --command "python -m scripts.run_scenarios --url $GATEWAY_URL --ml-url $ML_PUBLIC_URL"      # 94 chats
aws ecs execute-command --cluster $CLUSTER --task $TASK --container test-runner --interactive \
  --command "python scripts/coverage_traffic.py"                                             # every reason code
aws ecs execute-command --cluster $CLUSTER --task $TASK --container test-runner --interactive \
  --command "python scripts/try_message.py --session t1 'Is my flight on time?'"
```

(`GATEWAY_URL`, `ML_PUBLIC_URL` and `ADMIN_API_KEY` are set in the runner's environment.) ECS Exec
needs the Session Manager plugin on your machine (`session-manager-plugin`).

## Integration with ARC CMP (switched on in `config.py` on 2026-10-15)

After the standalone tests passed (scenario suite 92/94 on the server, coverage 73/73), `DEV` now has
`caller_security_group_ids = list(ARC_LAMBDA_SGS.values())` (the ARC Lambdas may reach the internal
ALB), `kafka_enabled=True` with `kafka_topic = ac-cct-cmp-inbound-messages-arc` and
`kafka_topics_allowed = [ac-cct-cmp-inbound-messages-bravo-arc]` (the enricher names the topic per
contact), and the data stack generates the enricher's caller key
(`security-layer-dev/cmp-enricher-api-key`, created in the gateway at start-up). Mock AI and the test
runner stay for now. The CMP side is `configs/config-arc.ini` + `cmp_message_metadata_enrich` in the
CMP repo (`security_gateway_mode = monitor` first: decisions are logged, delivery unchanged); see
`docs/integration-with-cmp.md` §1b. Deploy order: this app (`--all`), then the CMP ARC stacks
(`deploy/scripts/manual_deploy_cmp_arc_from_int.sh`).

## Other environments

```bash
npx aws-cdk@2 deploy -c env=prod --all --profile <prod profile>
```

Before a prod deploy set in `config.py`: `alb_certificate_arn` (ACM certificate for the internal
hostname), `admin_cidrs` (the security team's network), `never_ban_cidrs` (CMP Lambda and Connect
egress ranges), the Kafka fields (`kafka_bootstrap_servers`, `kafka_cluster_arn`,
`kafka_security_group_id`, `kafka_topic`: CMP's existing MSK cluster and the enricher's topic; the
gateway then publishes passed messages itself), and keep `destroy_data_on_delete=False`. The same
Kafka fields apply to `dev` once CMP's dev MSK cluster is known.

## Grafana for dev (on your laptop)

The dev stack has no Grafana of its own and its gateway is only reachable inside the VPC. The local
Grafana and Prometheus can look at dev instead, through two SSM port-forwarding sessions that use
the ECS Exec agent (no VPN needed):

```bash
observability/dev.sh ../aws_env.sh
```

It opens `localhost:28080` → the dev gateway task (metrics, admin API) and `localhost:25432` → the
dev RDS instance (through the test-runner task), reads the admin key and the dashboard-reader
password from Secrets Manager into the environment, and starts `observability/docker-compose.dev.yml`
(Grafana `http://localhost:23000`, Prometheus `http://localhost:29090`, separate from the local
stack on 13000/19090). The same gateway dashboard shows dev's decisions, reasons, latency and the
message explorer; Ctrl-C closes everything. Note: the audit trail and Prometheus series are read from
dev, so "Active bans" and the message explorer include the scenario-suite runs.

## IAM in the shared accounts

The AC-CCT accounts' service control policy denies `iam:CreateRole` unless the role carries the
permissions boundary `cfct-permission-boundary-policy` (the roles of the other CMP stacks carry it
too). `iam_permissions_boundary` in `config.py` applies it to every role this app creates, through the
`@aws-cdk/core:permissionsBoundary` context and an aspect on each stack; `iam_role_prefix` names the
task and execution roles `ac-cct-security-layer-<env>-<service>-task|exec` so they follow the
account's naming. The S3 bucket is created without `auto_delete_objects` (its custom-resource
provider role cannot be named or bounded by this app): empty the models bucket by hand before a
`cdk destroy`. The boundary allows everything the tasks use (ECR pull, logs, Secrets Manager, SSM
messages for ECS Exec, S3, MSK).

## Sizing note (measured on dev, 2026-10-14)

Fargate Graviton is about three times slower per core than an Apple-silicon workstation for the ML
service: with 2 vCPU one text scored in ~83 ms and a four-text call in ~520 ms, so the gateway's
150 ms ML budget (fine locally) expired on multi-segment messages and the gateway fell back to
`restrict` with `ml_unavailable`. Dev now runs the ML task with 4 vCPU (`ML_EMBED_THREADS` follows the
vCPU count) and `ml_timeout_ms=400`. Size prod from the same measurement, or keep the ML task on the
larger size and the budget at 400 ms.

## Notes and known limits

* Secrets are generated by Secrets Manager at deploy; the gateway assembles `DATABASE_URL` from
  `DATABASE_HOST` and the RDS-generated password secret. Rotate the RDS secret with Secrets Manager
  rotation when needed; the gateway reads it at task start.
* The bootstrap caller key is not created by CDK (its `cmpsk_…` format cannot be generated by Secrets
  Manager); create caller keys through the admin API after the first deploy.
* Observability beyond CloudWatch (Managed Prometheus / Grafana, the dashboard JSON) is not created by
  this app; see `docs/deployment-aws.md` §4 step 8.
* The challenger-model layer (SQS, Lambdas, shadow-score table) from `docs/deployment-aws.md` §6 is
  not in this app yet.
