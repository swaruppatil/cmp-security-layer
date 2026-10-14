#!/usr/bin/env bash
# Grafana for the dev deployment, on this laptop.
#
#   observability/dev.sh [path/to/aws_env.sh]      (default: ../aws_env.sh next to this repo)
#
# Opens two SSM port-forwarding sessions (no VPN needed: the gateway and test-runner tasks run
# with ECS Exec), reads the admin key and the dashboard DB password from Secrets Manager into the
# environment (never printed), and starts observability/docker-compose.dev.yml. Ctrl-C stops
# everything. Needs: aws CLI, session-manager-plugin, docker.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-$HERE/../../aws_env.sh}"
PREFIX="${PREFIX:-security-layer-dev}"
CLUSTER="${CLUSTER:-$PREFIX-security}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ca-central-1}"
export PATH="$HOME/.local/bin:$PATH"

if [ -f "$ENV_FILE" ]; then set -a; source "$ENV_FILE"; set +a; fi
aws sts get-caller-identity --query Account --output text >/dev/null || { echo "AWS credentials missing or expired: refresh $ENV_FILE"; exit 1; }

target() {  # ecs:<cluster>_<task id>_<runtime id> for a service's first task
  local task; task=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "$PREFIX-$1" --query 'taskArns[0]' --output text)
  local rid; rid=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$task" --query 'tasks[0].containers[0].runtimeId' --output text)
  echo "ecs:${CLUSTER}_${task##*/}_${rid}"
}
DB_HOST=$(aws rds describe-db-instances --db-instance-identifier "$PREFIX-postgres" --query 'DBInstances[0].Endpoint.Address' --output text)

echo "opening tunnels: localhost:28080 -> gateway, localhost:25432 -> $DB_HOST"
aws ssm start-session --target "$(target gateway)" --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8080"],"localPortNumber":["28080"]}' >/tmp/cmp-sec-dev-pf-gateway.log 2>&1 &
PF1=$!
aws ssm start-session --target "$(target test-runner)" --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters "{\"host\":[\"$DB_HOST\"],\"portNumber\":[\"5432\"],\"localPortNumber\":[\"25432\"]}" >/tmp/cmp-sec-dev-pf-db.log 2>&1 &
PF2=$!
cleanup() { echo; echo "stopping"; docker compose -f "$HERE/docker-compose.dev.yml" down >/dev/null 2>&1 || true; kill $PF1 $PF2 2>/dev/null || true; }
trap cleanup EXIT INT TERM

for i in $(seq 1 20); do curl -sf -m 2 localhost:28080/ready >/dev/null 2>&1 && break; sleep 1; done
curl -sf -m 2 localhost:28080/ready >/dev/null || { echo "gateway tunnel did not come up; see /tmp/cmp-sec-dev-pf-gateway.log"; exit 1; }

ADMIN_API_KEY=$(aws secretsmanager get-secret-value --secret-id "$PREFIX/admin-api-key" --query SecretString --output text)
DASHBOARD_DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id "$PREFIX/dashboard-db-password" --query SecretString --output text)
export ADMIN_API_KEY DASHBOARD_DB_PASSWORD

docker compose -f "$HERE/docker-compose.dev.yml" up -d --build
echo
echo "Grafana (dev):     http://localhost:${HOST_GRAFANA_PORT:-23000}   (anonymous viewer; admin / GRAFANA_ADMIN_PASSWORD to edit)"
echo "Prometheus (dev):  http://localhost:${HOST_PROMETHEUS_PORT:-29090}"
echo "Gateway (dev):     http://localhost:28080   (e.g. /ready, /metrics with the admin key)"
echo "Ctrl-C closes the tunnels and stops the containers."
wait $PF1
