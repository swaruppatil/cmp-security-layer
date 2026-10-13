# CMP Security Layer — AI Security Gateway (Prototype Plan)

A production-oriented prototype of a security gateway that protects AI applications and APIs against
prompt injection, multi-turn manipulation, sensitive-data exfiltration, malicious bots and abuse.

> **This layer reduces risk; it does not make anything immune to prompt injection.** Every detector is
> probabilistic and attackers adapt. The design is defense in depth: fast deterministic checks, ML
> scoring, conversation-level analysis, output checks, and — most importantly — the protected application
> never letting an ML score alone authorize a sensitive action.

- **Status:** Stages 1–9 and the CMP refactor done (2026-10-13); Stage 10 open
- **Stack:** all services are **Python 3.11 + FastAPI** (changed from Node.js/Fastify on 2026-10-12)
- **Location:** `air-canada-official/cmp-security-layer/` (sibling of `ac-cct-channel-manager-proxy`)
- **Created:** 2026-10-12

> **Design change (2026-10-13, "CMP refactor"):** the original plan had **tenants** (one per channel /
> environment). The gateway now protects **one product, CMP**: there are no tenants, API keys are
> **caller identities** (CMP's enricher, its processor, test tools), and the **CMP session** (= the
> Amazon Connect contact id) is the backbone for memory, limits, strikes, bans and the audit trail.
> Policies are chosen by **channel × session state × endpoint**. Stages 1–9 below keep their history;
> where they mention tenants, a note says what replaced them. See
> [CMP refactor](#cmp-refactor-no-tenants-session-backbone) for what changed.

---

## 1. Goals and non-goals

### Goals (prototype)
1. A working gateway that sits in front of an AI application and decides, per request: **allow, block, throttle, restrict, or inspect deeper**.
2. Detection for: prompt injection, multi-turn manipulation, sensitive-data exfiltration, bots, abuse.
3. Fast hot path: **p95 ≤ 10 ms added latency** for requests that don't need ML, **p95 ≤ 40 ms** with the ML tier.
4. Horizontal scaling: stateless gateway instances, shared state in Redis, durable state in PostgreSQL.
5. Ban management, reputation, rate limiting, configurable policies, admin API, metrics.
6. Measurable accuracy: labeled attack/benign datasets and evaluation scripts with precision, recall and false-positive rate.

### Non-goals (for the prototype)
- Claiming complete protection against prompt injection.
- Production AWS deployment (planned in Stage 10, not built in the MVP).
- Replacing the protected application's own authorization (the app must still check permissions for sensitive actions).
- Training large models; the prototype uses small embedding models and lightweight classifiers.

---

## 2. Two ways to use the gateway

CMP's chat messages reach the AI through **Amazon Connect → SNS → SQS → enricher → Kafka**, not through an HTTP API.
So the gateway supports both modes from the same detection pipeline:

| Mode | Endpoint | Used by |
|---|---|---|
| **Proxy mode** | `POST /v1/ai/*` → forwards to the protected AI app if allowed (scope `proxy`; end user from `X-Session-Id`, `X-End-User-Id`, `X-Device-Id`, `X-Channel`) | Any HTTP AI API (the generic case in the brief) |
| **Inspect mode** | `POST /v1/inspect` → returns a decision; the caller enforces it (scope `inspect`; `session_id` required) | CMP's enricher |
| **Outbound inspect** | `POST /v1/inspect/outbound` → checks an AI reply before delivery (scope `outbound`) | CMP's message processor (exfiltration checks on replies) |
| **Session calls** (optional) | `POST /v1/sessions/{id}/start`, `/identity` (CMP's IDV result), `/end` (scope `inspect`) | CMP, at contact start, after identity verification, at contact end |

Both modes run the same pipeline; only the last step (forward vs return decision) differs. Every
inspect decision also carries a **`cmp_action`** (`deliver`, `forward_without_tools`, `retry_later`,
`refuse`, `handoff_to_agent`, `end_contact`; outbound: `deliver` / `send_fallback`), so CMP needs no
knowledge of check names or reasons. *(Added in the CMP refactor.)*

---

## 3. Architecture

```
                 ┌──────────────────────────────────── Gateway (Python + FastAPI) ───────────────────────────────────┐
Request ───────► │ 1 Auth ─► 2 Ban check ─► 3 Rate limit ─► 4 Fast rules ─► 5 ML checks ─► 6 Policy decision ─► 7 Act │──► Protected AI app
                 │  (API key)   (local cache   (Redis token    (normalize,     (Python ML      (score fusion +   (forward /
                 │               + Redis)       bucket, Lua)    patterns, PII,  service, timed, policy table)     block / throttle
                 │                                              bot signals)    optional)                         / restrict)
                 │                                                                                                   │
                 │   Session + conversation (Redis) ◄──── multi-turn analysis ─────────────────┘                     │
                 │   Reputation (Redis hot, PostgreSQL history)                                                      │
                 │   Audit events ──► Redis Stream ──► async worker ──► PostgreSQL                                   │
                 └───────────────────────────────────────────────────────────────────────────────────────────────────┘
                                │ HTTP (keep-alive, strict timeout)
                                ▼
                 ┌──────── ML service (Python + FastAPI) ────────┐
                 │ /v1/score   injection classifier (n-gram LR)   │
                 │             + embedding classifier             │
                 │             + attack-similarity index          │
                 │ /v1/embed   embeddings for multi-turn drift    │
                 │ /v1/pii     NER-light PII (optional)           │
                 └────────────────────────────────────────────────┘
Admin API (separate auth) ──► keys, bans, policies, sessions, events   Prometheus /metrics ──► Grafana (optional)
```

### 3.1 Request pipeline, step by step

| # | Stage | What happens | Store | Target latency |
|---|---|---|---|---|
| 1 | **Authentication** | Validate API key → resolve the **caller** (key id, name, `scopes`). Unknown key → 401. The end user (session, customer, device, IP, channel) comes from the request; missing attributes are inherited from the session record. *(Was "resolve `tenant`" before the CMP refactor.)* | Local LRU cache, Postgres fallback; session record in Redis | < 0.1 ms (cached) |
| 2 | **Ban check** | Check IP (exact + CIDR), customer, device, session, API key against bans and blacklists | In-process ban index (exact + CIDR), Redis for TTL bans | < 0.1 ms local, < 1 ms Redis |
| 3 | **Rate limiting** | Token bucket per session, customer, IP, API key, endpoint and one **global** bucket (all in one Lua call). *(The tenant bucket became the global bucket in the CMP refactor.)* | Redis | < 1 ms |
| 4 | **Fast security rules** | Normalize text; length/encoding/invisible chars; phrase and role-token matching; PII/secret patterns; bot signals | In-process | < 1 ms |
| 5 | **ML / NLP checks** | Only when the policy asks (uncertain score, sensitive endpoint, flagged reputation): classifier + embeddings + multi-turn | Python ML service | 5–30 ms, hard timeout 50 ms |
| 6 | **Policy decision** | Fuse scores into a risk score; look up the policy for (channel, session state, endpoint, risk band); pick an action. *(Was (tenant, endpoint) before the CMP refactor.)* | In-process (policies cached from Postgres) | < 0.1 ms |
| 7 | **Act** | allow → forward / return; block → refusal; throttle → 429 + Retry-After; restrict → forward with a `restricted` flag; inspect → deeper async review. Inspect mode also returns the `cmp_action` for CMP | — | — |

Before the response (one Redis write each, so the AI reply check a moment later sees them): the session
record learns this message's attributes and typed identifiers, and — when a `message_id` is sent — the
decision is cached for idempotent retries. After the decision (never blocking the response): update
reputation, conversation state, strike counters, and emit an audit event.

### 3.2 Components

| Component | Tech | Responsibility |
|---|---|---|
| Gateway | Python 3.11, FastAPI, uvicorn (uvloop), asyncpg, redis-py, httpx | Pipeline, policy engine, proxy, admin API, metrics |
| ML service | Python 3.11, FastAPI, scikit-learn, ONNX embedding model | Scoring, embeddings, similarity index, evaluation tools |
| Redis | Redis 7 | Session records, idempotency cache, rate buckets, ban cache, reputation, conversation windows, bot features, audit stream |
| PostgreSQL | PostgreSQL 16 | Caller API keys, policies (+ versions), bans, strikes, canaries, security events (no tenants since the CMP refactor) |
| Audit worker | Python (gateway package, separate process) | Reads Redis Stream, batch-inserts events into Postgres |
| Mock AI app | FastAPI (tiny) | Stand-in for the protected application in tests and demos |

---

## 4. Detection design

### 4.1 Fast rules (gateway, in-process)
| Check | Technique |
|---|---|
| Normalization | Unicode NFKC, strip zero-width / bidi / tag characters, collapse whitespace, lowercase copy for matching |
| Size and flooding | Max length (`MAX_PROMPT_CHARS` ceiling, stricter per channel via `CHANNEL_MAX_CHARS`, e.g. SMS 1600), repetition ratio, total-chars-per-session |
| Encodings | Detect base64 / hex / URL-encoding; decode (max 2 levels) and re-run rules on the decoded text |
| Instruction override / jailbreak phrases | Multi-pattern matcher (Aho-Corasick) over a versioned EN/FR phrase list |
| Role / template tokens | `<\|im_start\|>`, `[INST]`, `</s>`, `System:` etc. |
| Indirect-injection signals | Instructions inside fields that should be data (documents, tool results, profile fields) — rules run on every text field, not just the prompt |
| Markup / links | Script tags, markdown images, non-allow-listed URLs |
| Sensitive data | Card numbers (Luhn), API keys / tokens (known formats + entropy), emails, phone numbers, passport-like IDs |

### 4.2 ML service
| Model | How | Purpose | Latency |
|---|---|---|---|
| **Baseline classifier** | Character n-gram TF-IDF + logistic regression | First injection score; robust to spacing/typos | < 1 ms |
| **Embedding model** | Small sentence-embedding model run with ONNX on CPU (e.g. a MiniLM / BGE-small class model; a multilingual one if FR matters) | Vectors for classifier, similarity and drift | 2–10 ms |
| **Embedding classifier** | Logistic regression on embeddings | Catches paraphrases the n-gram model misses | < 1 ms after embedding |
| **Attack-similarity index** | Cosine similarity against embedded known attacks (numpy for the prototype; FAISS/HNSW if large) | "Looks like a known attack" signal | < 1 ms |
| **Normal-intent centroids** | Average embedding per normal intent | Off-topic / out-of-distribution signal | < 1 ms |

The ML service returns: `{ injection_score, embedding_score, max_attack_similarity, attack_family, ood_score, model_version, latency_ms }`.

*As built (Stage 5):* `/v1/score` returns per text `score` (stacked ensemble) and `components`
`{ngram, embedding, attack_similarity, benign_similarity, nearest_attack_family}`, plus the model's calibrated
`thresholds`. The normal-intent centroids became "similarity to the nearest normal messages" (top-3 mean cosine),
which needs no intent labels; a separate OOD score is left for later. Embedding model:
`paraphrase-multilingual-MiniLM-L12-v2` (ONNX via fastembed, 384 dims).

### 4.3 Multi-turn analysis
Per conversation (Redis, TTL), keep the last N turns: text hash, embedding (or reference), per-turn scores.
*Since the CMP refactor the conversation is the CMP session (`conv:{session_id}`); AI replies are kept
as separate assistant turns (count, hash, action, length, reasons — no text) that never enter the window
re-score or the accumulated risk, but a blocked reply counts toward the lock.*

| Signal | Computation |
|---|---|
| Rolling risk | `risk_t = max(score_t, decay · risk_{t-1} + (1 − decay) · score_t)` |
| Window re-score | Join the last 3–5 user turns and score the combined text (catches split payloads) |
| Topic drift | Cosine distance of each turn from the conversation's first intent and from the normal-intent centroids; rising trend = signal |
| Retry after block | Cosine similarity of the new turn to previously blocked turns |
| Setup markers | "from now on", "let's play a game", variable/rule definitions followed by a trigger later |

### 4.4 Exfiltration (outbound)
| Check | How |
|---|---|
| Canary tokens | A unique token placed in the protected app's system prompt; seeing it in a reply → block + alert |
| Secrets / PII in replies | Same detectors as inbound, applied to the AI's output |
| Authorized-data check | Identifiers in the reply (e.g. booking refs, emails) must belong to the scope; otherwise block. *As built (CMP refactor):* the caller's `allowed_identifiers` if sent; otherwise the session's scope — identifiers the customer typed are always allowed; a **verified** session also allows its IDV identifiers and is strict (anything else → block `unauthorized_data`); an **anonymous** session treats other identifiers as unscoped (`OUTBOUND_UNSCOPED_ACTION`, default redact) |
| Exfil channels | Strip markdown images / unknown links from replies |
| Volume | Unusually large replies or record lists → restrict / inspect |

### 4.5 Bot detection
Features per IP / user / API key / device: requests per window, burst ratio, inter-arrival regularity
(coefficient of variation), chars-per-second vs human typing, near-duplicate content across sessions (SimHash),
header / user-agent anomalies, hosting-provider IP ranges. Combined into a `bot_score` (weighted rules first;
trainable later) that drives adaptive throttling. *Since the CMP refactor every session is profiled too, and
user-agent signals count only on channels in `BOT_UA_CHANNELS` (default `web`) — on SMS / WhatsApp the user
agent belongs to the provider.*

### 4.6 Reputation
Per entity (IP, user, API key, device): a decaying risk score updated after every decision, plus counters for
blocked attacks, failed authentication and abuse events. Reputation shifts thresholds (worse reputation →
stricter policy) and feeds ban escalation. History is persisted to Postgres for audit.
*As built:* reputation is kept for session, customer, device and IP (`rep:{type}:{value}`, no tenant scope);
strikes are persisted in Postgres, the decision history is the audit trail. `DELETE /admin/reputation`
forgets one identity's reputation and strike counters.

---

## 5. Policy engine

### 5.1 Risk fusion
`risk = max(rule_score, w1·ml_score + w2·similarity + w3·multi_turn_risk) + reputation_adjustment`

All weights and thresholds come from configuration / the `policies` table, not code.

### 5.2 Actions
| Action | Meaning |
|---|---|
| `allow` | Forward / return allow |
| `block` | Refuse with a generic message (never reveal the reason or score) |
| `throttle` | 429 with `Retry-After`; tighter bucket for this entity |
| `restrict` | Allow, but mark the request `restricted` so the app disables sensitive tools / actions |
| `inspect` | Escalate to the ML tier (if not run yet) or queue for async deep review; hold or allow per policy |

### 5.3 Safety rules (hard requirements)
1. **An ML score alone never authorizes a sensitive action.** For endpoints/actions tagged `sensitive`, the gateway requires all
   *required* checks to complete; if the ML service times out, the default is `restrict` (sensitive tools off), not `allow`.
2. **No permanent ban from an uncertain model prediction.** Permanent bans require deterministic evidence
   (e.g. repeated rule hits, canary leak, confirmed abuse) or a manual admin action. ML-only signals can only cause
   temporary bans with short expiry.
3. Every decision records the checks run, scores, policy version and model version.

### 5.4 Ban escalation (default)
Strike 1 → 1 min · strike 2 → 15 min · strike 3 → 24 h · strike 4+ → permanent **only if** the strikes include
deterministic evidence; otherwise capped at 24 h. Strikes decay after 30 days. Manual unban always available.

*Session rules (CMP refactor):* identified requests (session / customer / device) are charged to those
identities, never to the IP; the IP is charged too only when `IP_ATTACKERS_FOR_STRIKE` (3) different
identities — sessions count — were struck from it within the window and it is not a shared address (so an
attacker opening chat after chat gets the IP banned). A session is banned only for **deterministic**
strikes (high-severity rule, canary leak, rate-limit abuse); probabilistic strikes on a session are
recorded and the conversation lock escalates instead. Session and IP bans are never permanent. A blocked
AI reply with probabilistic evidence (`secret_in_reply`, `unauthorized_data`, `bulk_data`) is charged to
the session only; a canary leak still strikes the customer.

---

## 6. Data model

*Updated for the CMP refactor: no tenants anywhere; the CMP session is an entity of its own. The
original plan's Redis ban keys (`ban:{type}:{value}`, `banset:version`), `reputation_history` and
`model_versions` were not built: bans live in PostgreSQL with an in-process index refreshed over pub/sub,
the decision history is the audit trail, and the model version is recorded on every event.*

### 6.1 Redis keys (all with TTL unless noted)
| Key | Purpose |
|---|---|
| `sess:{session_id}` | Session record (JSON): channel, IP, device, user agent, hashed customer (`cu_…`), state (`anonymous` / `verified`), started / verified times, hashes of the IDV identifiers and of the identifiers the customer typed. TTL `SESSION_TTL_SECONDS` (24 h), refreshed on use |
| `idem:{session_id}:{inbound\|outbound}:{message_id}` | The decision for one `message_id`, so a retry gets it back (`replayed: true`). TTL `IDEMPOTENCY_TTL_SECONDS` (600 s) |
| `rl:session:{id}`, `rl:user:{u}`, `rl:ip:{ip}`, `rl:key:{key}`, `rl:ep:{endpoint}`, `rl:global` | Token bucket state (tokens, last refill), all checked in one Lua call |
| `rep:{type}:{value}` | Reputation hash: score, event counters, updated_at (session, user, device, IP) |
| `strikes:{type}:{value}` | Strike sorted set (30-day window, deterministic / probabilistic) |
| `conv:{session_id}` | Conversation memory: the last N customer turns (hash, scores, embedding) and, separately, the AI replies as assistant turns (no text) |
| `bot:{type}:{value}` | Sliding-window bot features per identity (session, user, device, IP) |
| `botc:{band}` | Campaign detection: identities sending the same message (SimHash band) |
| `ipgood:{ip}` / `ipbad:{ip}` | Shared-IP tracking: distinct customers / devices with allowed traffic (HyperLogLog); identities struck from the IP |
| `bans:changed`, `policies:changed` | Pub/sub channels (no TTL): every gateway reloads its ban index / policy cache |
| `audit:events` | Redis Stream of audit events (no TTL; capped, read by the audit worker) |

### 6.2 PostgreSQL tables
| Table | Key columns |
|---|---|
| `api_keys` | id, name, prefix, key_hash, scopes (`inspect`, `outbound`, `proxy`; default `inspect` + `outbound`), status, expires_at, last_used_at — **caller identities**, no tenant |
| `policies` | id, name, channel (null = any), session_state (`anonymous` / `verified`, null = both), endpoint_pattern, sensitive, mode, thresholds (jsonb), actions (jsonb), version, active — unique among active: (channel, session_state, endpoint_pattern) |
| `policy_versions` | policy_id, version, body (jsonb), created_by |
| `bans` | id, entity_type (ip / cidr / user / device / session / api_key), value, reason, source (manual / auto / blacklist), evidence (jsonb), permanent, expires_at, created_by, revoked_at — blacklist imports are bans with source `blacklist` |
| `strikes` | id, entity_type (ip / user / device / session), value, reason, evidence_kind, request_id, ban_id |
| `canaries` | id, label, token_hash (only the hash), revoked_at |
| `security_events` | id, ts, request_id, api_key_id, mode, endpoint, action, enforced_action, **cmp_action**, risk, reasons, checks (jsonb), **session_id**, **message_id**, **session_state**, channel, user_id (`cu_…` hash), ip, device_id, policy_id + version, model_version, ruleset_version, latency_ms, text_hash, redacted_excerpt, label |
| views | `security_events_view` (one row per decision, check details flattened; for Grafana) and `security_sessions_view` (one row per session); readable by `dashboard_reader` |

Migration `006_cmp_sessions.sql` dropped the `tenants` table and every `tenant_id` column, retired the
tenant-specific policies (kept inactive with their history) and renamed `security_events.conversation_id`
to `session_id`.

Raw prompts are **not** stored: only a hash and a redacted excerpt (configurable). Customer ids and
identifiers are stored only as keyed hashes (`IDENTITY_HASH_KEY`).

---

## 7. Repository layout

```
cmp-security-layer/
├── PLAN.md                     # this file
├── README.md                   # setup, commands, architecture summary
├── docker-compose.yml          # redis, postgres, ml-service, gateway, mock-ai, (grafana)
├── .env.example
├── gateway/                    # Python + FastAPI
│   ├── app/
│   │   ├── main.py             # app factory + lifespan (clients, migrations, auth, pipeline, bootstrap caller key)
│   │   ├── config.py           # pydantic-settings, validated env config
│   │   ├── deps.py             # Redis, asyncpg pool, httpx clients, readiness probes
│   │   ├── security.py         # FastAPI dependencies: API-key auth, scopes, admin auth, client IP
│   │   ├── entities.py         # (type, value) entities: ip, cidr, user, device, session, api_key
│   │   ├── cmp.py              # (CMP refactor) cmp_action for every decision
│   │   ├── auth/               # key format/hashing, cached auth service, cache invalidation
│   │   ├── db/                 # SQL migrations (001–006), migration runner, repository
│   │   ├── pipeline/           # context, checks, engine, decision, after-decision bookkeeping
│   │   ├── routes/             # health, inspect (+ outbound), sessions, proxy, admin_* (keys, bans, canaries, events, policies, sessions)
│   │   ├── session/            # (CMP refactor) session store, idempotency cache, customer-id / identifier hashing
│   │   ├── detectors/          # (Stage 4, 7) normalize, encodings, rules, structure, sensitive
│   │   ├── ml/                 # (Stage 4) ML client: timeout, concurrency cap, failure mode
│   │   ├── state/              # (Stage 3) Redis Lua admission, shared-IP tracking, pub/sub events
│   │   ├── conversation/       # (Stage 6) multi-turn state + analysis, keyed by session id
│   │   ├── outbound/           # (Stage 7) reply checks, canaries
│   │   ├── bots/               # (Stage 8) bot features + scoring
│   │   ├── reputation/ bans/ policy/   # (Stage 3–5, 9)
│   │   ├── audit/              # (Stage 9) stream producer + worker
│   │   └── metrics.py          # (Stage 9) prometheus-client
│   ├── scripts/                # try_message, demo_traffic, coverage_traffic, run_scenarios, smoke_test, simulate_bots, eval_multiturn, export_openapi
│   ├── tests/                  # unit/, integration/ (adversarial from Stage 4)
│   └── bench/                  # load / latency scripts (Stage 10)
├── ml-service/                 # Python + FastAPI
│   ├── app/                    # api, models, features, similarity, multiturn
│   ├── training/               # train + export scripts
│   ├── evaluation/             # eval scripts, reports
│   └── tests/
├── datasets/
│   ├── attacks/                # labeled attacks by family (jsonl)
│   ├── benign/                 # normal traffic + hard negatives, EN/FR
│   └── multiturn/              # labeled multi-turn conversations
├── mock-ai/                    # tiny protected-app stand-in
├── observability/              # Prometheus + Grafana images, dashboard generator (build_dashboard.py)
└── docs/                       # API docs (OpenAPI), explained/ chapters, architecture diagrams
```

---

## 8. Configuration (`.env.example`)

```
# Gateway
GATEWAY_PORT=8080
UPSTREAM_AI_URL=http://mock-ai:9000
ADMIN_API_KEY=change-me
LOG_LEVEL=info
# Stores
REDIS_URL=redis://redis:6379
DATABASE_URL=postgresql://sec:sec@postgres:5432/security
# ML service
ML_URL=http://ml-service:8000
ML_TIMEOUT_MS=50
ML_MAX_CONCURRENCY=64
ML_FAILURE_MODE=restrict          # allow | restrict | block
# Limits
MAX_PROMPT_CHARS=4000
CHANNEL_MAX_CHARS=sms:1600,facebook:2000   # stricter per channel; MAX_PROMPT_CHARS stays the ceiling
CONVERSATION_WINDOW=10
CONVERSATION_TTL_SECONDS=3600
# Privacy
STORE_REDACTED_EXCERPT=true
# CMP sessions (CMP refactor)
# BOOTSTRAP_API_KEY=cmpsk_<10 hex>_<secret>   # optional caller key created at startup (only its hash stored)
BOOTSTRAP_API_KEY_NAME=cmp
BOOTSTRAP_API_KEY_SCOPES=inspect,outbound
SESSION_TTL_SECONDS=86400
IDEMPOTENCY_TTL_SECONDS=600
IDENTITY_HASH_KEY=change-me-identity-hash-key
CMP_HANDOFF_AFTER_BLOCKS=2
CMP_SHORT_BAN_SECONDS=900
# Rate limits: per session / user / IP / API key / endpoint, plus one global bucket
RL_SESSION_CAPACITY=20
RL_SESSION_REFILL_PER_SEC=0.2
RL_GLOBAL_CAPACITY=10000                    # was RL_TENANT_* before the CMP refactor
RL_GLOBAL_REFILL_PER_SEC=1000
# Bots
BOT_UA_CHANNELS=web                         # channels where the user agent is the customer's browser
# Bans
NEVER_BAN_CIDRS=127.0.0.0/8,::1/128,192.168.65.0/24   # 192.168.65.x = Docker Desktop's host (local tests)
```

This is an excerpt; `.env.example` lists every setting with a comment.

---

## 9. Datasets and evaluation

| Dataset | Content | Source |
|---|---|---|
| `attacks/*.jsonl` | Labeled by family: instruction_override, jailbreak_roleplay, prompt_exfiltration, encoded_payload, tool_manipulation, data_harvesting, indirect_injection | Hand-written seed set + scripted augmentations; optional import of public datasets (check licenses before use) |
| `benign/*.jsonl` | Normal airline-support messages EN/FR + **hard negatives** ("ignore my previous booking", "override the fee", angry complaints, PNRs, ticket numbers, pasted errors) | Hand-written + generated; later a redacted sample of real CMP traffic |
| `multiturn/*.jsonl` | Conversations labeled per turn (crescendo, split payload, retry-after-block, benign long chats) | Hand-written + LLM-generated in a test environment |

**Evaluation scripts** report: precision, recall, F1, **false-positive rate on benign**, per family and per language;
**leave-one-family-out** recall (to measure generalization to unseen attacks); threshold sweep and calibration;
multi-turn detection delay (turns until caught). Results are saved under `ml-service/evaluation/reports/`.

---

## 10. Implementation stages

Each stage ends with tests passing and commands documented in the README. Stages build on each other;
nothing is a placeholder.

### Stage 1 — Project structure, configuration, Docker, tests
- Gateway, ML service and mock AI app — all FastAPI, pytest, ruff, uv (gateway also mypy strict).
- `docker-compose.yml` with Redis and Postgres (named volumes, **no bind mounts** — see §14).
- `.env.example`, pydantic-settings config validation, health endpoints.
- **Done when:** `docker compose up` starts all services; `/health` green on each; one test per package passes.

### Stage 2 — Gateway, authentication, protected API proxy
- API-key auth (hashed keys in Postgres, cached locally), tenant/user resolution.
- Proxy `POST /v1/ai/*` to the mock AI app; `POST /v1/inspect` decision endpoint.
- First migrations (`tenants`, `api_keys`, `policies`).
- **Done when:** valid key → proxied response; invalid key → 401; integration tests green.
- **Built (2026-10-12):** `cmpsk_` keys (SHA-256 stored, plaintext shown once), local TTL cache + negative cache,
  revocation broadcast over Redis pub/sub, scopes (`inspect`, `proxy`), admin API for tenants/keys, migration runner,
  pipeline engine with the size check, proxy that strips gateway credentials and adds `X-Security-*` headers,
  trusted-proxy-aware client IP. 55 unit + 6 integration tests.
  *(Tenants, the tenant admin API and tenant resolution were replaced in the CMP refactor: keys are
  caller identities, the end user comes from the request and the session record.)*

### Stage 3 — Redis rate limiting, reputation, ban management
- Token bucket in a single Lua script across IP / user / API key / tenant / endpoint.
- Bans: temporary (Redis TTL) and permanent (Postgres), CIDR support, local Bloom/trie cache with pub/sub reload.
- Reputation scores with decay; strike escalation rules (§5.4).
- **Done when:** burst tests produce 429s at the configured rate; banned entities are rejected within one request; ban expiry works.
- **Built (2026-10-12):** one Lua `ADMISSION` script per request (all-or-nothing token buckets for api_key / tenant /
  endpoint / ip / user + decayed reputation read, Redis `TIME` clock); reputation 0–100 with 6 h half-life; strikes in a
  30-day sorted set tagged deterministic/probabilistic; ladder 60 s → 15 min → 24 h, permanent only at 4 strikes *with*
  deterministic evidence; `never_ban_cidrs`; in-memory ban index (exact + CIDR by prefix length, expiry at lookup)
  reloaded via `bans:changed` pub/sub and every 30 s; pre-auth global IP ban check and failed-auth brute-force strikes;
  admin API for bans, blacklists (bulk) and reputation; post-decision bookkeeping as background tasks.
  Migration `002_bans_strikes`. 109 unit + 13 integration tests; pipeline p50 0.18 ms incl. Redis.
  *(Replaced in the CMP refactor: the tenant bucket became the global bucket, a session bucket was
  added, and bans / reputation have no tenant scope — a ban matches (type, value) everywhere.)*

### Stage 4 — Baseline prompt-injection rules + Python ML service
- Normalization, encodings, phrase/role-token matcher, length/repetition, markup/link checks.
- ML service `/v1/score` with the n-gram TF-IDF + logistic regression baseline.
- Gateway → ML client with timeout, concurrency limit and failure mode.
- **Done when:** adversarial test suite blocks the seed attacks; benign suite passes; ML timeout falls back per policy.
- **Built (2026-10-12):** `app/detectors/` — normalization (NFKC, invisible/bidi strip, look-alike + leet folding,
  spaced-letter joining, recovery of text hidden in Unicode tag characters), decoding (base64, hex, URL, escapes,
  ROT13, 2 levels, false-positive guards for PNRs/ticket numbers), ~40 EN/FR rules in 8 families, structure checks
  (flooding, script/markdown-image markup, links/raw IPs); rules check (high → block + deterministic strike,
  medium → restrict). ML service: char n-gram TF-IDF + logistic regression trained at image build from
  `datasets/` (hold-out P 0.97 / R 1.0 / FPR 1.2% on seed data), `/v1/score`, `/v1/model`. Gateway ML client: hard
  timeout, concurrency cap with load shedding, failure mode (default restrict), thresholds block 0.9 / restrict 0.7,
  ML skipped for texts < 15 chars. Ban propagation made incremental (an attack wave no longer forces a full ban
  reload per ban: p99 48 ms → 5 ms). 194 unit + 16 integration tests; smoke test 43/43.

### Stage 5 — Embeddings + trainable classifier + labeled evaluation dataset
- ONNX embedding model, embedding classifier, attack-similarity index, normal-intent centroids.
- Training and evaluation scripts; first evaluation report (per family, per language, leave-one-family-out).
- **Done when:** report generated; thresholds chosen from the false-positive budget; model version recorded.
- **Built (2026-10-12):** `ml-service/app/embedder.py` (fastembed ONNX `paraphrase-multilingual-MiniLM-L12-v2`,
  light normalisation that keeps case/accents; `HashEmbedder` for offline tests), `app/ensemble.py` (n-gram LR +
  embedding LR + top-3 similarity to known attacks and to normal messages → logistic stacker trained on 5-fold
  out-of-fold predictions), `training/train.py` (trains on `seed*`/`train*` files only; thresholds calibrated from
  benign OOF scores with FPR budgets 0.2% block / 1% restrict, floors 0.8/0.5; held-out metrics stored in the
  bundle), `evaluation/evaluate.py` (held-out, leave-one-family-out with an n-gram-only baseline, training-data
  ablation → JSON + markdown). Data: public `deepset/prompt-injections` (Apache-2.0; its train split trains, its
  test split is held out), general off-topic benign training data, a handwritten benign held-out set. Gateway uses
  the model's thresholds by default (`ML_USE_MODEL_THRESHOLDS`) and shows the components in each decision.
  Results: public test split 83% caught / 3.6% benign flagged / AUC 0.968 (n-grams alone 0.939); handwritten
  benign 5.4% flagged (2 blocked: customers retracting their own earlier message); ML service p50 6.5 ms per
  message; 199 unit + 19 integration tests; smoke test 47/47.

### Stage 6 — Multi-turn conversation analysis
- Conversation window in Redis; rolling risk, window re-score, drift, retry-after-block.
- **Done when:** labeled multi-turn tests caught within the target number of turns; benign long chats not flagged.
- **Built (2026-10-13):** `gateway/app/conversation/` — per-conversation memory in Redis (JSON, TTL, last 10
  turns; blocked turns keep only a hash + embedding), loaded by a `conversation_memory` check before the rules
  and updated after the response with an atomic WATCH/MULTI read-modify-write; `conversation` check after ML
  with accumulated risk (`acc = 0.75·acc + max(0, score − 0.3)`, restrict ≥ 1.0, block ≥ 2.0), setup markers
  (`override.from_now_on` etc. double the excess for 5 turns), crescendo bonus, window re-score (rules on the
  last 4 turns the AI saw — cross-turn matches only; ML on the window optional, **off by default**), retry after
  block (cosine ≥ 0.85 or same folded hash), lock after 3 blocks, drift (reported). ML service returns
  float16 embeddings on request and keeps itself warm; gateway warms its ML connection at startup. Admin
  `GET/DELETE /admin/conversations/{tenant}/{conversation}`. Data: `datasets/build_multiturn.py` composes
  conversations from existing rows only — `tune` (training rows), `calib` and `heldout` (two disjoint halves
  of the held-out rows); `scripts/eval_multiturn.py` replays them with and without a conversation id and
  sweeps thresholds on `calib` under a 2.5% false-alarm budget. Result on `heldout`: Stage 6 adds no catches
  and no false alarms on this data (single-message checks already catch every composed attack on its first
  attack turn); window ML re-score flagged up to 29% of normal chats on `calib`, hence off. Gradual attacks
  with innocent-looking turns are untested. 219 unit + 22 integration tests; smoke test 52/52.
  *(Replaced in the CMP refactor: memory is keyed by the session id (`conv:{session_id}`), AI replies
  are kept as assistant turns, and the admin view is `GET/DELETE /admin/sessions/{id}`.)*

### Stage 7 — Sensitive-data detection + authorization before outbound transfers
- Inbound/outbound PII and secret detection with redaction; `POST /v1/inspect/outbound`; canary tokens; authorized-data check.
- **Done when:** secrets/PII redacted; canary leak blocked; replies with out-of-scope identifiers blocked.
- **Built (2026-10-13):** `app/detectors/sensitive.py` — pattern detectors with validation (Luhn for cards/SIN,
  mod-97 for IBAN, SSN ranges) and context words for weak patterns (passport, SIN without separators, booking
  reference, Aeroplan, date of birth); secrets (AWS, GitHub, Slack, Stripe, Google, JWT, private keys, gateway
  keys, credential URLs, password assignments); airline identifiers (booking ref, 014 ticket, Aeroplan).
  Findings carry type + fingerprint, never the value. Inbound `sensitive` check redacts payment/secret/SIN/
  SSN/passport before the AI (proxy rewrites the forwarded JSON; inspect returns `redacted_message`;
  conversation memory stores the redacted text). `POST /v1/inspect/outbound` with its own pipeline:
  `reply_size` (restrict), `canary` (block; deterministic strike for the tenant's own active token),
  `reply_data` (secret → block, always-redact types, authorized-data check against `allowed_identifiers`,
  unscoped → redact, bulk ≥ 5 → block), `reply_links` (images and unknown links stripped); `deliver` is the
  only text to send. Proxy mode checks the app's JSON reply (scope via `X-Security-Allowed-Identifiers`,
  stripped before the client). Canaries: migration `003_canaries.sql` (hash only), admin API, 30 s cache.
  Blocked replies count toward the conversation lock. 271 unit + 25 integration tests; smoke test 59/59.
  *(Replaced in the CMP refactor: canaries are global (`/admin/canaries`), and without
  `allowed_identifiers` the reply scope comes from the session — typed and IDV identifiers.)*

### Stage 8 — Bot detection + adaptive throttling
- Bot features, `bot_score`, policy-driven throttle tiers.
- **Done when:** a scripted bot (fixed timing, duplicate content) is throttled while a human-like simulation is not.
- **Built (2026-10-13):** `app/bots/` — per identity (user / device / IP, never trusted shared IPs) one Redis Lua
  call records `(time, length, SimHash)` and returns recent events; Python computes rate, gap CV, typing speed,
  near-duplicates; campaign detection via four 16-bit SimHash bands per tenant (same 8+-word message from 5+
  identities in 10 min). Weighted signals (timer 0.45, campaign 0.40, fast typing 0.35, repetition 0.30, rate
  0.30, automation UA 0.25, missing UA 0.15, hosting IP 0.15) → `bot_score` → tiers: suspect (end-user bucket
  cost ×3), likely (×10), bot (throttle 30 s, `bot_detected`). No single signal reaches "likely". `bot` check runs
  before admission; tenant/key buckets never charged extra. `scripts/simulate_bots.py` (fake clock, benign
  content): 0/20 human sessions slowed; timer bots throttled by message 4–6; fast/burst bots all slowed; slow
  poller left alone. 288 unit + 27 integration tests; smoke 59/59.
  *(Replaced in the CMP refactor: campaign bands are global, the session is profiled too, the global
  and key buckets are never charged extra, and user-agent signals count only on `BOT_UA_CHANNELS`.)*

### Stage 9 — Admin API, metrics, audit logs, dashboards
- Admin API: bans (list/create/revoke), events (search), policies (CRUD + versioning), metrics summary.
- Audit worker (Redis Stream → Postgres), Prometheus `/metrics`, optional Grafana dashboard.
- OpenAPI docs.
- **Done when:** every decision appears in `security_events`; dashboards show volume, blocks, latency, false-positive reports.
- **Built (2026-10-13):** migration `004_events_policies.sql` (`security_events`, `policy_versions`, policy
  `mode`). `app/audit/` — every decision (inspect, proxy, outbound, proxy-outbound) → event (hash + fully
  redacted excerpt, never raw text) → Redis stream (`XADD`, approx. capped; direct PostgreSQL write if Redis
  is down) → audit worker in each gateway (consumer group, batch insert `ON CONFLICT DO NOTHING`, ack after
  write, `XAUTOCLAIM` of stale entries). `app/policy/` — resolution by specificity, action overrides,
  monitor mode (`would_have`), policy ML thresholds; never overrides bans / throttles / bot / canary; monitor
  never strikes; cache + pub/sub invalidation; every change versioned. Admin: events search, event, labels,
  metrics summary (percentiles, labelled precision, hourly), policies CRUD + versions. `app/metrics.py` +
  `/metrics` (admin bearer). `observability/` — Prometheus + Grafana images (compose profile
  `observability`) with a 12-panel dashboard. OpenAPI tags + `scripts/export_openapi.py` → `docs/openapi.json`.
  Found and fixed: untyped SQL parameter in labelling (500 dropped the connection) → generic 500 handler.
  302 unit + 30 integration tests; smoke 60/60.
  *(Replaced in the CMP refactor: policies are resolved by channel × session state × endpoint instead
  of tenant × endpoint; the dashboard's Tenant filter became Channel / Session state / Session id.)*

### CMP refactor (no tenants, session backbone)
- The gateway protects **one product, CMP**: tenants removed; the **CMP session** (= the Amazon Connect
  contact id) becomes the backbone for memory, limits, strikes, bans, policies and the audit trail.
- **Done when:** no tenant left in schema, API, config, scripts or dashboard; every decision carries a
  `cmp_action`; all suites green against the new API.
- **Built (2026-10-13):**
  - **Schema** — migration `006_cmp_sessions.sql` drops `tenants` and every `tenant_id` (api_keys,
    policies, bans, strikes, canaries, security_events), retires tenant-specific policies, renames
    `security_events.conversation_id` → `session_id`, adds `message_id`, `session_state`, `cmp_action`,
    rebuilds `security_events_view` and adds `security_sessions_view` (one row per session).
  - **Callers, not tenants** — API keys identify callers (`POST/GET /admin/api-keys`,
    `DELETE /admin/api-keys/{id}`); scopes `inspect`, `outbound` (new: `POST /v1/inspect/outbound`),
    `proxy`; default `inspect` + `outbound`. Optional `BOOTSTRAP_API_KEY` creates a caller key at
    startup (only its hash is stored). Removed: `/admin/tenants*`, tenant status, `tenant_disabled`.
  - **Sessions** — `POST /v1/inspect` requires `session_id`; channel, customer, IP, device and user agent
    may come with any message or from `POST /v1/sessions/{id}/start` (idempotent) and are inherited from
    the session record (`sess:{id}`, 24 h); a value in the request wins for that request.
    `POST /v1/sessions/{id}/identity` records an IDV result (`verified` → session state `verified`,
    identifiers stored as keyed hashes; `false` → back to `anonymous`). `POST /v1/sessions/{id}/end`
    forgets the session and its memory (strikes and bans stay until they expire). All three are
    optional: inspect works with only a session id. Customer ids are stored as `cu_<32 hex>`
    (HMAC with `IDENTITY_HASH_KEY`); admin APIs accept the raw id or the hash.
  - **Session as an entity** — its own rate bucket (`RL_SESSION_*`: burst 20, then 1 every 5 s; bot-cost
    scaled), reputation, strikes, bans (never permanent) and bot profile. The tenant bucket became the
    **global** bucket (`RL_GLOBAL_*`). Entities and Redis keys have no scope (`rep:{type}:{value}`).
  - **Strikes** — identity-first (session / customer / device are charged, the IP only when
    `IP_ATTACKERS_FOR_STRIKE` identities — sessions count — were struck from a non-shared IP); a session is
    banned only for deterministic strikes; a blocked AI reply with probabilistic evidence is charged to
    the session only; only customer and device ids make an IP look shared (see §5.4).
  - **`cmp_action`** on every decision (`app/cmp.py`): inbound `deliver` (allow), `forward_without_tools`
    (restrict), `retry_later` (throttle, or a ban ending within `CMP_SHORT_BAN_SECONDS` = 900 s, with
    `retry_after_seconds`), `refuse` (block), `handoff_to_agent` (session locked, or its
    `CMP_HANDOFF_AFTER_BLOCKS` = 2nd block), `end_contact` (banned longer or permanently); outbound
    `deliver` / `send_fallback`. Decisions also carry `session_state` and `replayed`.
  - **Idempotency** — a `message_id` caches the decision (`idem:…`, 600 s), written before the response;
    a repeat returns it with `replayed: true`, without re-running checks or striking again.
  - **Checks** — per-channel size limits (`CHANNEL_MAX_CHARS`, SMS 1600); bot user-agent signals only on
    `BOT_UA_CHANNELS` (web); identifiers the customer types are remembered for the session; AI replies are
    assistant turns in conversation memory; the reply scope comes from the caller's `allowed_identifiers`
    or else the session (typed identifiers always; a verified session also its IDV identifiers, strictly;
    an anonymous one redacts the rest); policies resolved by channel × session state × endpoint.
  - **Proxy mode** — `X-Session-Id`, `X-End-User-Id` (hashed), `X-Device-Id`, `X-Channel` (default web).
  - **Admin** — `GET/DELETE /admin/sessions/{id}` (record, ban, strikes, memory; reset does not lift a
    ban), `DELETE /admin/reputation`, global canaries (`/admin/canaries`), events filters `session_id`,
    `api_key_id`, `cmp_action`, `channel`; summary by `channel` / `api_key_id`.
  - **Dashboard** — Tenant filter replaced by Channel, Session state, CMP action, Session id and
    Customer (cu_…) / IP; new row "CMP sessions — what CMP was told to do" (CMP actions, by channel and
    session state, Sessions, Session timeline); "Sessions at risk" replaces "Conversations at risk"
    (57 panels: 36 SQL, 11 Prometheus, 10 rows).
  - **Scripts** — `try_message.py` (`--session`, `--start`, `--verify`, `--end`, `--customer`, `--channel`,
    `--message-id`, …), `demo_traffic.py` (10 scenarios, every customer a session),
    `coverage_traffic.py` (3 caller keys, **73/73** outcomes), `smoke_test.py` (**71** steps),
    `eval_multiturn.py` (tracked = one session per conversation, baseline = a new session per turn).
    Local `.env`: `NEVER_BAN_CIDRS` includes Docker Desktop's host range `192.168.65.0/24`, from which
    all local test traffic reaches the container.
  - **Tests** — 349 unit (new `tests/unit/test_sessions.py`, 18 tests; `test_scenarios_file.py`, 4; `test_dashboard.py`, 2) + 31 integration (isolated by
    caller key and unique session ids; `test_tenants_are_gone_from_the_schema`).
- **Known limitations:** two copies of one `message_id` arriving at the same instant can both run;
  gradual multi-turn attacks whose turns all look innocent are caught only if the accumulated total
  rises; the model still flags some benign phrasing; a banned customer can open new sessions as
  anonymous (no customer id) until IDV — the session / IP rules and bot checks apply then.

### Stage 10 — Load testing, security testing, CI/CD, AWS deployment plan
- Load tests (Python load generator, e.g. locust or an httpx-based script): p50 / p95 / p99 latency with and without ML; throughput per instance.
- Security tests: adversarial suite, fuzzing of the gateway inputs, admin API auth tests.
- CI pipeline (lint, test, build images); AWS deployment design (ECS Fargate + ElastiCache + RDS + WAF in front).
- **Done when:** benchmark report meets the latency targets (§11) or documents the gap.

---

## 11. Performance targets and benchmarks

| Path | p50 | p95 | p99 |
|---|---|---|---|
| Rules only (no ML) | ≤ 3 ms | ≤ 10 ms | ≤ 20 ms |
| With ML tier | ≤ 15 ms | ≤ 40 ms | ≤ 60 ms |
| Ban / rate-limit reject | ≤ 1 ms | ≤ 3 ms | ≤ 5 ms |

Measured as **gateway-added latency** (total minus upstream time) with `gateway/bench/`. Techniques:
local caches for keys, bans and policies; one Redis round trip per request where possible (pipelined Lua);
keep-alive HTTP to the ML service; ML only when the policy requires it; async audit writes.

---

## 12. Testing strategy

| Type | What | Tool |
|---|---|---|
| Unit | Detectors, token bucket math, policy fusion, ban escalation | pytest |
| Integration | Gateway + Redis + Postgres + ML service + mock AI via Docker Compose | pytest `-m integration` |
| Adversarial | Attack datasets → must be blocked/restricted; benign + hard negatives → must pass | dataset-driven test runner |
| Multi-turn | Labeled conversations replayed turn by turn | dataset-driven test runner |
| Load | Throughput, p50/p95/p99, degradation under ML/Redis failure | locust / httpx script |
| Failure | ML timeout, Redis down, Postgres down | integration tests with stopped containers |

---

## 13. Observability

- **Metrics (Prometheus):** requests by action, blocked attacks by family, stage latencies (histograms), ML timeouts,
  Redis errors, rate-limit rejections, active bans, false-positive reports (admin-marked events).
- **Logs:** structured logging, no raw prompts, request ID on every line.
- **Health:** `/health` (liveness) and `/ready` (Redis, Postgres, ML reachable).
- **Accuracy tracking:** admin can mark events as false positive / true positive; metrics derive precision over time.

### Graceful degradation
| Failure | Behaviour |
|---|---|
| ML service slow / down | Timeout → policy `ML_FAILURE_MODE` (default `restrict`; sensitive actions never allowed on ML failure) |
| Redis down | Local ban cache keeps working; rate limiting fails open with alert; conversation analysis skipped |
| Postgres down | Audit events buffer in the Redis Stream; admin API returns 503 |
| Overload | Concurrency limits per stage; shed ML tier first, never the ban/rate-limit tiers |

---

## 14. Local environment notes

- **Python** 3.11 via `uv` for every service (3.14 is the system default, but ML wheels are safer on 3.11).
- **Docker** 28 + Compose v2 available; Redis and Postgres run as containers (not installed locally).
- **Host ports** default to 16379 (Redis), 15432 (Postgres), 18000 (ML), 19000 (mock AI), 18080 (gateway), because
  5432/6379/8000/8080/9000 are already used by other local services. Override with `HOST_*_PORT` in `.env`.
- **Docker Desktop cannot currently mount folders under `~/Desktop`** (seen earlier: `mkdir /host_mnt/Users/.../Desktop: operation not permitted`).
  Compose files therefore use **named volumes and image builds, not bind mounts**. To use bind mounts for live reload,
  grant Docker Desktop access to `~/Desktop` (Settings → Resources → File sharing) or move the project out of `~/Desktop`.
- First run downloads the embedding model (~100 MB); it's cached in a named volume.

---

## 15. How it would plug into CMP later

A design note, not an integration guide: the prototype was designed with CMP in mind but is not
integrated. *(Rewritten in the CMP refactor; the original table mapped CMP channels / environments to
tenants and the contact to a `conversation_id`.)*

| CMP concept | Gateway concept |
|---|---|
| Connect contact / initial contact ID | `session_id` — the backbone for memory, limits, strikes, bans and the audit trail |
| Aeroplan ID / authenticated customer | `customer_id`, stored only as a keyed hash (`cu_…`); entity `user` |
| Channel (web, SMS, WhatsApp, Apple, …) | `channel` on the session; selects policies, size limits and whether user-agent bot signals count |
| Identity verification (IDV) result | session state `verified` + the verified identifiers (keyed hashes) — the reply scope of that session |
| IP + device (only visible at `/start-chat`, not on chat messages) | Session attributes, given once and inherited by every later message of the session |
| Enricher, message processor, test tools | Caller API keys (scopes `inspect`, `outbound`, `proxy`) — no tenants |
| What to do with a decision | `cmp_action` — the action a caller like CMP would take (`deliver`, `refuse`, `handoff_to_agent`, `end_contact`, …) |

---

## 16. Open decisions

1. Fail mode for the ML tier per endpoint (`restrict` vs `block` vs `allow`).
2. Which entities may be banned permanently, and who approves (admin role).
3. False-positive budget per action (e.g. block < 0.1%, restrict < 1%).
4. Multilingual embedding model vs English-only (French support).
5. Retention of security events and redacted excerpts.
6. Whether to import public attack datasets (license review) or rely on curated + generated data.

Still open after the CMP refactor:

- **Stage 10** — load and security testing, CI/CD and the AWS deployment design.
- **Gradual multi-turn attacks** — conversations whose turns each look innocent are caught only if the
  accumulated total rises; further layers for them are not built or tested (no labelled data).
- **Optional deeper review** — an LLM-based review behind the `inspect` action ("queue for async deep
  review", §5.2) is not built.

---

## 17. Progress

| Stage | Status |
|---|---|
| 1. Structure, config, Docker, tests | ✅ 2026-10-12 |
| 2. Gateway, auth, proxy | ✅ 2026-10-12 |
| 3. Rate limiting, reputation, bans | ✅ 2026-10-12 |
| 4. Rules + ML service baseline | ✅ 2026-10-12 |
| 5. Embeddings, classifier, evaluation | ✅ 2026-10-12 |
| 6. Multi-turn analysis | ✅ 2026-10-13 |
| 7. Sensitive data + outbound authorization | ✅ 2026-10-13 |
| 8. Bot detection + adaptive throttling | ✅ 2026-10-13 |
| 9. Admin API, metrics, audit, dashboards | ✅ 2026-10-13 |
| CMP refactor (no tenants, session backbone) | ✅ 2026-10-13 |
| 10. Load/security testing, CI/CD, AWS plan | ☐ |
