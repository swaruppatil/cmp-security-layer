# CMP Security Layer — AI Security Gateway (prototype)

A security gateway that sits in front of an AI application and decides, per request, whether to
**allow, block, throttle, restrict, or inspect deeper** — protecting against prompt injection,
multi-turn manipulation, sensitive-data exfiltration, bots and abuse.

> Defense in depth, not immunity. No detector makes an AI system immune to prompt injection.
> New here? Read [GUIDE.md](GUIDE.md) first — it explains the whole project.
> See [PLAN.md](PLAN.md) for the full architecture and the staged build plan.

All services are **Python 3.11 + FastAPI**, managed with [`uv`](https://docs.astral.sh/uv/).

## Status

| Stage | State |
|---|---|
| 1. Structure, config, Docker, tests | ✅ done |
| 2. Gateway, API-key auth, proxy, inspect API | ✅ done |
| 3. Rate limiting, reputation, strikes, bans, blacklists | ✅ done |
| 4. Detection rules + ML baseline classifier | ✅ done |
| 5. Embeddings + ensemble classifier + held-out evaluation | ✅ done |
| 6. Multi-turn conversation analysis | ✅ done |
| 7. Sensitive data, outbound checks, canary tokens | ✅ done |
| 8. Bot detection + adaptive throttling | ✅ done |
| 9. Audit trail, policies, metrics, dashboards | ✅ done |
| 10 | see [PLAN.md §17](PLAN.md#17-progress) |

## Layout

```
gateway/      FastAPI — the request pipeline, auth, proxy, inspect API, admin API
ml-service/   FastAPI — injection ensemble: n-grams + multilingual embeddings + similarity + a pretrained
              transformer view; a chat model and a tool-content model (both trained at image build)
mock-ai/      FastAPI — stand-in for the protected AI app
datasets/     Training data (seed*, train*) and held-out evaluation data (heldout*) + the scripts that build them
docs/         API docs and results
```

## Prerequisites

- Python 3.11 and `uv`
- Docker Desktop with Compose v2

**How it all works:** [docs/explained/](docs/explained/01-overview-and-architecture.md) — 1 overview and
architecture · 2 code walkthrough · 3 algorithms and design decisions · 4 testing and evaluation ·
5 dashboard, metrics and operations · 6 the security checks explained (how each check recognises
attacks, bots and leaks — no code). Sessions and `cmp_action`: see
[Sessions and decisions](#sessions-and-decisions) below.

**All services, why each exists and how they connect:** [docs/services-overview.md](docs/services-overview.md).
**Infrastructure as code:** [infra/](infra/README.md) — AWS CDK app (Python), one set of stacks per
environment (`cmp-dev`, `cmp-prod`): VPC, ElastiCache, RDS, Secrets Manager, ECS Fargate services, internal ALB.

**Integrating with CMP:** [docs/integration-with-cmp.md](docs/integration-with-cmp.md) — the six hook
points (chat start, identity verification, customer message, tool results, AI reply, chat end), what CMP
does with each `cmp_action`, timeouts and fail-open/fail-closed per hook, and a monitor-first rollout.
**Deploying on AWS:** [docs/deployment-aws.md](docs/deployment-aws.md) — ECS Fargate for the two
services, ElastiCache and RDS for the state, step-by-step with task definitions, sizing, CI/CD and cost.

**Hands-on testing guide:** [TESTING.md](TESTING.md) — start the stack, send demo traffic, try your own
messages, read the audit trail and the Grafana dashboard. `gateway/scripts/coverage_traffic.py` triggers
every check and reason code (73/73 outcomes), so every dashboard panel has data;
`gateway/scripts/run_scenarios.py` plays 90 test chats from `datasets/sessions/scenarios.yaml` as
sessions and checks every step's outcome (90/90).

## Quick start (full stack in Docker)

```bash
cp .env.example .env          # first time only; change ADMIN_API_KEY
docker compose up -d --build --wait
docker compose ps             # all five services "healthy"
```

The gateway applies pending database migrations on startup.

| Service | URL on your machine | Inside Docker |
|---|---|---|
| Gateway | http://localhost:18080 | gateway:8080 |
| Gateway API docs (OpenAPI) | http://localhost:18080/docs | — |
| ML service | http://localhost:18000 | ml-service:8000 |
| Mock AI app | http://localhost:19000 | mock-ai:9000 |
| PostgreSQL | localhost:15432 (user `sec`, password `sec`, db `security`) | postgres:5432 |
| Redis | localhost:16379 | redis:6379 |
| Grafana dashboard (observability profile) | http://localhost:13000 | grafana:3000 |
| Prometheus (observability profile) | http://localhost:19090 | prometheus:9090 |

Host ports avoid clashes with other local services; change them with `HOST_*_PORT` in `.env`.

Dashboards (optional): `docker compose --profile observability up -d --build --wait` adds Prometheus
(scrapes `/metrics` with the admin key) and Grafana with the "CMP Security Gateway" dashboard: live
metrics plus every decision from the audit trail — the (redacted) message, action, reasons, which
check decided, ML score and its parts, rules fired, bot tier, conversation state, a per-event drill-down
of every check, a "CMP sessions" row (what CMP was told to do, by channel and session state, a
per-session timeline), tuning views and filters by channel / session state / mode / action /
CMP action / reason / session id / customer or IP / text. Grafana reads PostgreSQL through a read-only
role (`DASHBOARD_DB_PASSWORD`) that cannot see API keys.

```bash
docker compose logs -f gateway    # follow logs
docker compose up -d --build      # rebuild after code changes
docker compose down               # stop, keep data
docker compose down -v            # stop and delete Redis/Postgres/model volumes
```

## Try it

```bash
ADMIN="x-admin-key: change-me-admin-key"     # the ADMIN_API_KEY from .env

# 1. Create a caller API key (shown once — copy it). Scopes: inspect (inspect + session calls),
#    outbound (AI replies), proxy (/v1/ai/*). Or set BOOTSTRAP_API_KEY in .env to have one created at startup.
KEY=$(curl -s -X POST localhost:18080/admin/api-keys -H "$ADMIN" -H 'content-type: application/json' \
  -d '{"name":"cmp-qa","scopes":["inspect","outbound","proxy"]}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["api_key"])')
AUTH="authorization: Bearer $KEY"

# 2. Start a CMP session (optional: inspect works with only a session id); later calls inherit these attributes
curl -s -X POST localhost:18080/v1/sessions/c-1/start -H "$AUTH" -H 'content-type: application/json' \
  -d '{"channel":"web","customer_id":"AP123","ip":"203.0.113.9"}'

# 3. Inspect mode: ask for a decision on a customer message
curl -s -X POST localhost:18080/v1/inspect -H "$AUTH" -H 'content-type: application/json' \
  -d '{"session_id":"c-1","message_id":"m-1","message":"Can I change my seat?"}'    # -> "cmp_action":"deliver"
# Sending the same message_id again returns the cached decision with "replayed":true (no second check or strike)

# 4. CMP's identity verification succeeded: AI replies may now contain this customer's own booking
curl -s -X POST localhost:18080/v1/sessions/c-1/identity -H "$AUTH" -H 'content-type: application/json' \
  -d '{"verified":true,"customer_id":"AP123","identifiers":{"booking_ref":["ABC123"]}}'
curl -s -X POST localhost:18080/v1/inspect/outbound -H "$AUTH" -H 'content-type: application/json' \
  -d '{"session_id":"c-1","reply":"Booking ABC123 is confirmed."}'                 # -> "cmp_action":"deliver"

# 5. Proxy mode: the gateway forwards to the mock AI app if allowed
curl -s -X POST localhost:18080/v1/ai/chat -H "$AUTH" -H 'x-session-id: c-2' -H 'content-type: application/json' \
  -d '{"message":"hello"}'

# 6. Ban a customer for 10 minutes (raw customer id or its cu_… hash), then check their reputation
curl -s -X POST localhost:18080/admin/bans -H "$ADMIN" -H 'content-type: application/json' \
  -d '{"entity_type":"user","value":"u-1","reason":"abuse","duration_seconds":600}'
curl -s -X POST localhost:18080/v1/inspect -H "$AUTH" -H 'content-type: application/json' \
  -d '{"session_id":"c-3","message":"hi","customer_id":"u-1"}'
  # -> "action":"block","reasons":["banned"],"cmp_action":"retry_later" (a ban of 15 min or less; longer → "end_contact")
curl -s "localhost:18080/admin/reputation?entity_type=user&value=u-1" -H "$ADMIN"

# 7. Look at a session (attributes, verification, conversation memory, ban, strikes), then end it
curl -s localhost:18080/admin/sessions/c-1 -H "$ADMIN"
curl -s -X POST localhost:18080/v1/sessions/c-1/end -H "$AUTH"

# 8. Revoke the key (takes effect on every gateway instance immediately)
curl -s localhost:18080/admin/api-keys -H "$ADMIN"
curl -s -X DELETE localhost:18080/admin/api-keys/<key-id> -H "$ADMIN"
```

Or use `gateway/scripts/try_message.py` (see [TESTING.md](TESTING.md)): it creates its own key, keeps it
in `gateway/.try_key`, and prints the `cmp_action` and session state of each decision —
`--session`, `--start`, `--verify TYPE=VALUE`, `--end`, `--customer`, `--channel`, `--ip`, `--device`,
`--message-id`, `--reply` (check an AI reply), `--scope`, `--endpoint`, `--json`.

## Sessions and decisions

The prototype is designed around CMP, so there are no tenants: API keys identify **callers**, and the
**session id** (in CMP that would be the Amazon Connect contact id) ties together everything the gateway
knows about a chat — attributes, verification state, conversation memory, rate limits, strikes and bans.
Explained in [GUIDE.md §14](GUIDE.md#14-how-it-connects-to-cmp).

- `POST /v1/inspect` and `POST /v1/inspect/outbound` require a `session_id`. Attributes given once to
  `POST /v1/sessions/{id}/start` (channel, customer, IP, device, user agent) are inherited by later calls;
  `POST /v1/sessions/{id}/identity` marks the session verified and stores the customer's own identifiers
  (as keyed hashes); `POST /v1/sessions/{id}/end` forgets it. All three are optional.
- Customer ids are stored only as a keyed hash (`cu_…`).
- Every decision carries a `cmp_action` — the action the caller should take:

| `cmp_action` | When |
|---|---|
| `deliver` | customer message allowed (use `redacted_message` if present) / AI reply may be sent (send `deliver`) |
| `forward_without_tools` | restrict |
| `retry_later` | throttle, or a ban that ends within `CMP_SHORT_BAN_SECONDS` (900 s) |
| `refuse` | block |
| `end_contact` | banned for longer than 900 s, or permanently |
| `send_fallback` | AI reply blocked (`deliver` is `null`), or it promises money / approvals the AI cannot make |

- With a `message_id`, a repeat within `IDEMPOTENCY_TTL_SECONDS` (10 min) returns the first decision
  (`replayed: true`) without re-running the checks or striking again.

## Endpoints

### Gateway
| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness (never touches dependencies) |
| GET | `/ready` | none | Readiness: probes Redis, Postgres, ML service; 503 names the failing one |
| POST | `/v1/inspect` | API key, scope `inspect` | Decision for one customer message of a session (`session_id` required); includes `cmp_action`; the caller enforces it (and forwards `redacted_message` when present) |
| POST | `/v1/inspect/outbound` | API key, scope `outbound` | Checks an AI reply before delivery against the session's scope (or `allowed_identifiers`); deliver `deliver` (never the raw reply), or a fallback when it is `null` |
| POST | `/v1/inspect/tool-result` | API key, scope `tool` | Checks a tool's output before the AI reads it; `deliver` is the result with poisoned pieces removed (`deliver_without_tools`) or `null` (`withhold`) |
| POST | `/v1/sessions/{id}/start` | API key, scope `inspect` | Session attributes (channel, customer, IP, device, user agent), inherited by later calls; idempotent |
| POST | `/v1/sessions/{id}/identity` | API key, scope `inspect` | CMP's IDV result: `verified: true` → session state `verified` and the customer's own identifiers (stored as keyed hashes); `false` → back to anonymous |
| POST | `/v1/sessions/{id}/end` | API key, scope `inspect` | Forget the session and its conversation memory (strikes and bans stay until they expire) |
| any | `/v1/ai/{path}` | API key, scope `proxy` | Inspects the request; forwards to the AI app if allowed. Identity from `X-Session-Id`, `X-End-User-Id`, `X-Device-Id`, `X-Channel` |
| POST | `/admin/api-keys` | admin key | Create a caller key `{name, scopes, expires_at}` — plaintext returned once; default scopes `inspect`, `outbound` |
| GET | `/admin/api-keys` | admin key | List keys (never the plaintext or hash) |
| DELETE | `/admin/api-keys/{id}` | admin key | Revoke a key |
| POST | `/admin/bans` | admin key | Ban an IP / CIDR / customer (`user`) / device / session / API key — temporary (`duration_seconds`) or `permanent` |
| GET | `/admin/bans?active_only=&entity_type=&value=&limit=` | admin key | List bans |
| DELETE | `/admin/bans/{id}?clear_history=` | admin key | Unban (optionally forget reputation and strikes) |
| POST | `/admin/blacklists` | admin key | Bulk-import permanent bans (up to 10,000 values; invalid ones reported) |
| GET | `/admin/reputation?entity_type=&value=` | admin key | Score, events, strikes, active ban for a customer / device / session / IP (customer: raw id or `cu_…` hash) |
| DELETE | `/admin/reputation?entity_type=&value=` | admin key | Forget an identity's reputation and strike counters (bans are not lifted) |
| GET | `/admin/sessions/{id}` | admin key | Session record (counts, never hashes), ban, strikes, conversation memory: per-turn scores/actions/rule ids, AI-reply turns, blocks, lock (never message text) |
| DELETE | `/admin/sessions/{id}` | admin key | Reset a session: forget its conversation memory (unlocks it) and its reputation and strikes (bans are not lifted) |
| POST / GET | `/admin/canaries` | admin key | Create a canary token for the AI's system prompt (shown once) / list canaries (never the token) |
| DELETE | `/admin/canaries/{id}` | admin key | Revoke a canary |
| POST / GET | `/admin/protected-prompts` | admin key | Register the AI's system prompt for leak detection by content (only 8-word shingle hashes are stored) / list |
| DELETE | `/admin/protected-prompts/{id}` | admin key | Revoke a protected prompt |
| GET | `/admin/events?session_id=&api_key_id=&action=&cmp_action=&channel=&reason=&mode=&user_id=&ip=&label=&since=&until=&before=&limit=` | admin key | Search the audit trail (newest first; `next_before` pages; `user_id` takes a raw customer id or its `cu_…` hash) |
| GET | `/admin/events/{id}` | admin key | One event with every check |
| POST | `/admin/events/{id}/label` | admin key | Mark `false_positive` / `true_positive` (or `null` to clear) |
| GET | `/admin/metrics/summary?hours=&channel=&api_key_id=` | admin key | Counts, top reasons, latency percentiles, labels, labelled precision, hourly series |
| POST / GET | `/admin/policies` (`GET ?channel=`) | admin key | Create (version 1) / list policies — chosen by channel × session state × endpoint |
| GET / PUT / DELETE | `/admin/policies/{id}` | admin key | One policy with its versions / replace (version + 1) / retire |
| GET | `/metrics` | admin key (bearer) | Prometheus metrics |

API keys: `Authorization: Bearer <key>` or `X-API-Key: <key>`. Admin key: `X-Admin-Key: <key>`.

### ML service / mock AI
| Service | Method | Path | Purpose |
|---|---|---|---|
| ML | GET | `/health` | Liveness + which model is loaded |
| ML | GET | `/v1/model` | Version, embedder, calibrated thresholds, training data, out-of-fold + held-out metrics |
| ML | POST | `/v1/score` | `{"texts": [...]}` → per text: score + components (n-gram, embedding, similarity, nearest attack family); plus the model's thresholds |
| Mock AI | GET | `/health` | Liveness |
| Mock AI | POST | `/v1/ai/chat` | Canned reply; echoes the security headers it received |
| Mock AI | POST | `/v1/ai/leak-test` | Returns the requested reply (outbound tests, Stage 7) |
| Mock AI | GET | `/v1/ai/models` | A request with no user text |

## Development

Each service has its own environment:

```bash
cd gateway          # or ml-service / mock-ai
uv sync --python 3.11
uv run pytest                          # unit tests
uv run ruff check . && uv run ruff format --check .
uv run mypy app                        # gateway: strict type checking
```

Gateway integration tests need the Docker stack running:

```bash
docker compose up -d --wait
cd gateway && uv run pytest -m integration
```

Live smoke test against the running stack (71 steps, real HTTP, the way CMP uses the gateway — session
lifecycle, retries and replays, the SMS length limit, key scopes, … — prints PASS/FAIL per step):

```bash
cd gateway && uv run python scripts/smoke_test.py            # --url / --admin-key to point elsewhere
```

It creates its own caller keys, random session and customer ids, and IPs from 198.18.0.0/15. The
brute-force step bans this machine's IP as the gateway sees it, then lifts the ban.

Run the gateway outside Docker against the Docker stores:

```bash
cd gateway
set -a; source ../.env; set +a
uv run uvicorn app.main:create_app --factory --port 8081 --reload
```

Datasets and the model:

```bash
python3 datasets/build_seed.py                     # seed attack/benign data (deterministic)
python3 datasets/build_benign_general.py           # general off-topic benign training data
python3 datasets/build_benign_heldout.py           # handwritten benign held-out set (never trained on)
cd ml-service
uv run --with pyarrow python ../datasets/fetch_public.py   # public labelled data: train split + held-out test split
uv run python -m training.train                    # train ensemble → models/ + evaluation/reports/<version>.json
uv run python -m evaluation.evaluate --all         # held-out + leave-one-family-out + ablation → <version>-evaluation.md
cd .. && docker compose up -d --build ml-service   # the image retrains from datasets/ at build time

# Multi-turn (Stage 6)
python3 datasets/build_multiturn.py                # conversations composed from existing rows: tune / calib / heldout
cd gateway
uv run python -m scripts.eval_multiturn --sweep    # choose thresholds on calib.jsonl, report on heldout.jsonl
uv run python -m scripts.eval_multiturn            # report only → gateway/reports/multiturn-heldout.md
```

Database migrations (also applied automatically on gateway startup):

```bash
cd gateway
set -a; source ../.env; set +a
uv run python -m app.db.migrate --status
uv run python -m app.db.migrate
```

## Current results

| Check | Result |
|---|---|
| Gateway unit tests | 364 passed |
| Gateway integration tests (real Redis/Postgres/ML model/mock AI + container; isolated by caller key and unique session ids) | 31 passed |
| Live smoke test | 71/71 steps |
| Coverage traffic (`scripts/coverage_traffic.py`) | 73/73 expected outcomes |
| Session scenarios (`scripts/run_scenarios.py`) | 90/90 chats, 196/196 steps |
| ML service tests (offline hash embedder + one real-embedder test) / mock AI | 19 / 3 passed |
| Gateway lint / format / mypy strict; ML lint | clean |

**Detection quality (Stage 5 ensemble; full report in `ml-service/evaluation/reports/<version>-evaluation.md`).**
"Flagged" = restricted or blocked. Thresholds are calibrated by the model: block ≥ 0.969, restrict ≥ 0.660.

| Data (never trained on unless noted) | Attacks caught | Benign flagged | AUC |
|---|---|---|---|
| Public test split (deepset, EN/DE, 60 attacks / 56 benign) — through the gateway | 50/60 (83%; 38 blocked) | 2/56 (3.6%) | 0.968 |
| Handwritten support messages (92 benign, EN/FR) — through the gateway | — | 5/92 (5.4%; 2 blocked) | — |
| Out-of-fold on training data (2,534 rows) | 97% | 1.0% | 0.998 |
| Seed data through gateway (*trained on*) | 481/481 | 5/1282 | — |

| Comparison | Result |
|---|---|
| AUC on public test split by component | ensemble 0.968 · n-grams 0.939 · embedding 0.946 · similarity 0.880 |
| Training data ablation (public test split AUC) | seed only 0.843 → seed + public train + general benign 0.968 |
| Leave-one-family-out (attack family never seen in training) | 6 of 9 families ≥ 85% recall; weakest: data harvesting 47%, public injections 22% |

Known weak spots (kept visible on purpose, not tuned away against the held-out data):
customers retracting their own earlier message ("Please ignore my earlier message…") score as
attacks and can be *blocked*; "bypass the line", "override the seat assignment" restrict. Stage 6
did **not** fix this (it is a single-message false positive; the conversation layer neither causes
nor removes it). Off-topic political questions occasionally restrict.

**Multi-turn (Stage 6; `gateway/reports/multiturn-heldout.md`, `multiturn-calib-sweep.md`).**
Conversations are composed from existing dataset rows (no new attack text): attacks split across
turns, repeated probing, mechanical retries after a block, long normal chats, mixed-topic chats.
Thresholds were chosen on `calib.jsonl` (one half of the held-out rows); results below are on
`heldout.jsonl` (the other half): *tracked* (one session per conversation) and *baseline* (a new session
for every turn, so no conversation memory).

| Held-out conversations | Single-message checks | With Stage 6 |
|---|---|---|
| Split payload (30) — caught / blocked | 27 / 24 | 27 / 24 |
| Probing (15) — caught / blocked | 15 / 15 | 15 / 15 |
| Retry after block (30) — caught / blocked | 30 / 27 | 30 / 27 |
| Normal chats (60, 674 turns) — conversations flagged | 18 | 18 (0 added by the conversation check) |

Honest reading: on this data Stage 6 adds **no** catches — every composed attack conversation
contains turns that are attacks on their own, and the single-message checks already catch them on
the first attack turn. It also adds no false alarms. What it adds is shown by the unit and smoke
tests rather than by this data: the lock after repeated blocks, retry detection, the accumulator,
and split phrases matched by the rules across turns. Re-scoring the joined window *with the ML
model* is **off by default**: on the calibration set it caught nothing extra and flagged up to 29%
of normal chats (joined unrelated questions look like an injection to the model). Attacks whose
individual turns all look innocent (gradual "crescendo" attacks) are not in this data and remain
untested — building them would mean writing new attack text.

**Sensitive data and outbound checks (Stage 7).**

| Check | Result |
|---|---|
| Detector over every single-turn dataset row (2,742) | no secret / payment / personal-data hits on benign rows; only booking references (100) and one ticket number — the expected identifiers |
| Inbound | card numbers, SIN/SSN, passport, IBAN and credentials redacted before the AI (and before conversation memory); request still allowed |
| Outbound | canary leak (also spaced out, upper-cased, base64, invisible characters, truncated) → block + deterministic strike → ban; secret → block; someone else's booking ref / email → block; card etc. always redacted; images and unknown links stripped; 5+ out-of-scope identifiers → block |
| Proxy mode | forwarded body redacted; the app's JSON reply checked; blocked → 502 generic body |
| Cost | detector ~27 µs per message; outbound check 1.2 ms round trip (pipeline 0.16 ms) |

Known limits: detection is pattern-based (no named-entity model), so names and street addresses are
not detected; booking references, passports, Aeroplan numbers and dates of birth need a context
word nearby. In proxy mode the authorized-data check needs the app to send
`X-Security-Allowed-Identifiers`; without it, identifiers in replies are redacted
(`OUTBOUND_UNSCOPED_ACTION`).

**Bots (Stage 8; `uv run python -m scripts.simulate_bots`).** Message content is ordinary customer
text from the seed dataset, so only behaviour differs. "Slowed" = reached the likely-bot tier, where
the user's own buckets drain 10× faster (with default limits that throttles within a few requests).

| Simulated profile | Sessions | Throttled | Slowed | First throttle |
|---|---|---|---|---|
| Human (irregular, 3–7 chars/s, varied messages; 400 messages) | 20 | 0 | 0 | — |
| Template every 2 s | 5 | 5 | 5 | message 4 |
| Different messages every 3 s ± 3 % | 5 | 5 | 5 | message 6 |
| Different long messages every 0.5–1.5 s | 5 | 1 | 5 | — |
| 40 messages in under a minute | 5 | 1 | 5 | — |
| Same question every 2 minutes (slow poller) | 3 | 0 | 0 | — (harmless; left alone) |
| Same long message from 8 users | 8 users | 0 | 0 | flagged "campaign" from the 5th user |

A real-time bot through the container (same message every 0.3 s, python-requests user agent) is
throttled at request 6 while a person sent through the same caller key is allowed. Cost: one extra Redis call per
request with an end-user identity — 1.4 ms p50 measured under load (could later be folded into the
rate-limit call). Limits: a slow, irregular, human-paced bot with varied content is not detected by
behaviour (the content checks still apply); `BOT_HOSTING_CIDRS` ships empty.

**Audit trail and dashboards (Stage 9).** Every decision — inspect, proxy, outbound and proxied
replies — becomes one row in `security_events` (container check: 309 decisions → 309 events queued, 0
written directly, 0 dropped; integration test: 6 calls → exactly 6 rows, including the proxied
reply). Stored events hold no card numbers, emails or other sensitive values (tested). The audit
write happens after the response: full-pipeline latency stayed at p50 10.0 ms / p99 12.3 ms. All 12
dashboard panel queries checked against Prometheus.

**Latency.**

| Measurement | Result |
|---|---|
| ML service, one short message (service time) | p50 6.5 ms · p99 8.8 ms (embedding ~5 ms of it) |
| ML service, three texts in one call | p50 14 ms · p99 19 ms |
| Benign request through the full gateway pipeline (incl. ML hop) | p50 10.3 ms · p99 13.7 ms |
| Same, in a tracked conversation (Redis GET + vectors) | p50 14.4 ms · p99 17–18 ms |
| First ML score after 30 s idle (service time) | 16–18 ms with keep-warm (52–72 ms without) |
| Attack wave, 1,000 attacks each creating an auto-ban — round trip (Stage 3/4) | p50 1.57 ms · p99 5.28 ms |
| Pipeline time for a banned request (local index, no network) | p50 0.010 ms · p99 0.017 ms |
| Ban propagation between two gateway instances (Redis pub/sub) | < 1 s (integration test) |

Measured on a laptop in Docker Desktop (arm64). Numbers double when other work saturates the CPU
(the last full run, with another project's parallel tests at load average ~41: pipeline p50 22 ms).

## Notes

- **Docker Desktop cannot bind-mount folders under `~/Desktop`** on this machine, so the Compose file
  uses image builds and named volumes only. Rebuild after code changes.
- Configuration is validated at startup (`gateway/app/config.py`); a bad value stops the gateway with a clear message.
- Logs never include request bodies or API keys; 422 errors never echo submitted values.
- The ML image is ~3 GB (ONNX Runtime + the 230 MB multilingual embedding model baked in, so the
  container needs no network at runtime). `ml-service/.cache/` holds the same model for local runs.
- The ML service keeps itself warm (`ML_KEEP_WARM_SECONDS=1`) and the gateway warms its ML connection
  at startup: without that, the first message after a restart or a quiet spell overran the 50 ms ML
  budget and was restricted as `ml_unavailable`.
- **Shared IPs** (Wi-Fi, mobile-carrier NAT): an attack is charged to the session / customer / device,
  never to an IP other people share. The IP is struck only for anonymous attacks (IP only), or when 3+
  different identities — sessions count — attacked from it and it is not shared (3+ different customers
  or devices with allowed traffic in 24 h; opening sessions is free, so sessions never make an IP look
  shared). So an attacker opening chat after chat gets the IP banned. Shared IPs get a 10× rate limit;
  automatic IP bans stop at 24 h. Reproduced (one attacker banned everyone on the IP) and fixed; tested
  with 120 users on one address.
- **Sessions** are an identity of their own: a rate bucket (`RL_SESSION_*`: 20, then one every 5 s),
  reputation, strikes and bans. A session is banned only for deterministic strikes (high-severity rule,
  canary leak, rate-limit abuse) and never permanently; model-based strikes are recorded and escalate
  the conversation lock instead. A blocked AI reply with model-based evidence is charged to the session
  only, not the customer.
- **Known limit:** a banned customer can still open new sessions anonymously (no customer id) until
  identity verification; the session / IP rules and bot checks apply to those.
- Gateway shutdown never waits more than 5 s for background tasks; the audit worker polls the stream
  instead of a blocking read (a blocking read could not always be cancelled and hung shutdown).
- Unexpected errors return a generic `500 {"error": "internal_error", "request_id": …}` (logged with
  the trace) — found when a database bug made the gateway drop the connection instead of answering.
- Conversation updates are atomic (Redis WATCH/MULTI on the latest state), so turns fired back to
  back are all counted — an earlier version lost blocks this way and never locked a fast attacker.
- Pin numpy/BLAS to one thread next to ONNX Runtime (`OPENBLAS_NUM_THREADS=1`, set in the image):
  otherwise they fight for cores and scoring time doubles.
