"""Gateway configuration.

Read once from the environment and validated by pydantic. A bad value stops startup with a clear
message instead of misbehaving later.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    # --- server ---
    gateway_host: str = "0.0.0.0"  # noqa: S104 - container listens on all interfaces
    gateway_port: int = Field(8080, gt=0)
    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"

    # --- protected application ---
    upstream_ai_url: str = "http://localhost:9000"
    upstream_timeout_seconds: float = Field(30.0, gt=0)

    # --- admin ---
    admin_api_key: SecretStr = Field(..., min_length=8)
    # Optional caller key created at startup if it does not exist yet (format cmpsk_<10 hex>_<secret>),
    # so CMP can be given its key through a secret store instead of an admin call. Only its hash is stored.
    bootstrap_api_key: SecretStr | None = None
    bootstrap_api_key_name: str = Field("cmp", min_length=1, max_length=100)
    bootstrap_api_key_scopes: str = "inspect,outbound"

    # --- CMP sessions ---
    # A session is one CMP / Amazon Connect contact. Its attributes (channel, IP, device, customer,
    # verification) are remembered this long after the last call, so later requests can omit them.
    session_ttl_seconds: int = Field(24 * 3600, gt=0)
    # Same message_id within this window → the cached decision is returned (CMP retries are safe).
    idempotency_ttl_seconds: int = Field(600, gt=0)
    # Customer ids are stored as a keyed hash (HMAC-SHA256): the audit trail, Redis and the dashboard
    # never hold the raw id. Change this for any shared environment; changing it resets per-customer
    # reputation and strikes.
    identity_hash_key: SecretStr = SecretStr("dev-only-identity-hash-key-change-me")
    # After this many blocked messages in one session, a block becomes "handoff_to_agent" for CMP.
    cmp_handoff_after_blocks: int = Field(2, gt=0)
    # A ban ending within this many seconds is "retry_later" for CMP; a longer one is "end_contact".
    cmp_short_ban_seconds: int = Field(900, ge=0)

    # --- stores ---
    redis_url: str = "redis://localhost:6379"
    database_url: str = "postgresql://sec:sec@localhost:5432/security"
    db_pool_min: int = Field(1, ge=0)
    db_pool_max: int = Field(10, gt=0)

    # --- ML service ---
    ml_url: str = "http://localhost:8000"
    # Embedding (~5 ms) + pretrained transformer view (~8 ms per text, batched) + a few segments of a
    # long message; 150 ms keeps a chat-sized request inside the budget without shedding it.
    ml_timeout_ms: int = Field(150, gt=0)
    ml_max_concurrency: int = Field(64, gt=0)
    ml_failure_mode: Literal["allow", "restrict", "block"] = "restrict"
    ml_enabled: bool = True
    # While idle, ping the ML service this often so the first real call isn't cold (0 = off).
    ml_keep_warm_seconds: float = Field(10.0, ge=0)
    # Injection-probability thresholds (0..1). By default the model's own calibrated thresholds are
    # used (it sends them with every score); these apply when it doesn't, or when
    # ML_USE_MODEL_THRESHOLDS=false pins the operating point here.
    ml_use_model_thresholds: bool = True
    ml_block_at: float = Field(0.9, gt=0, le=1)
    ml_restrict_at: float = Field(0.7, gt=0, le=1)
    # Texts shorter than this skip the ML tier (rules still run): a character model has too little to
    # go on in "yes" or "thanks", and no attack phrase is that short.
    ml_min_chars: int = Field(15, ge=0)

    # --- fast rules (Stage 4) ---
    rules_enabled: bool = True
    # A high-severity *phrase* rule (probabilistic evidence) blocks the message, but strikes the customer
    # only when the ML tier agrees (score ≥ its restrict threshold). When the ML tier finds the text
    # clearly benign (score < RULES_ML_CLEAR_BELOW) the block is softened to a restrict. Deterministic
    # rules (template tokens, hidden text, encoded payloads) block and strike on their own.
    rules_corroborate_with_ml: bool = True
    rules_ml_clear_below: float = Field(0.3, ge=0, le=1)
    # Fusion: two or more weak findings from different rule families plus an ML score within this much
    # of the restrict threshold → restrict (no single check would have acted).
    fusion_enabled: bool = True
    fusion_ml_margin: float = Field(0.15, ge=0, le=1)
    # Off-topic use of the assistant (homework, code, essays): what to do when the ML tier's topic
    # similarity falls below the model's off_topic threshold. "flag" records it without acting.
    off_topic_action: Literal["off", "flag", "restrict"] = "flag"
    # Indirect injection found in content the AI fetched (tool results, documents) in proxy mode.
    untrusted_content_action: Literal["off", "flag", "restrict", "block"] = "restrict"
    # Links to these domains (and their subdomains) are not flagged. Comma-separated.
    allowed_link_domains: str = "aircanada.com,aircanada.ca,aeroplan.com,flyaircanada.com"
    max_links: int = Field(5, ge=0)

    # --- authentication cache ---
    auth_cache_ttl_seconds: float = Field(30.0, gt=0)
    auth_negative_cache_ttl_seconds: float = Field(5.0, gt=0)
    auth_cache_max_entries: int = Field(10_000, gt=0)

    # --- request limits ---
    max_prompt_chars: int = Field(4000, gt=0)
    # Stricter limits for some channels (channel:chars,…). MAX_PROMPT_CHARS stays the ceiling for all.
    channel_max_chars: str = "sms:1600,facebook:2000"
    max_body_bytes: int = Field(256 * 1024, gt=0)
    # Number of reverse proxies in front of the gateway whose X-Forwarded-For entries are trusted.
    trusted_proxy_count: int = Field(0, ge=0)

    # --- rate limiting (token buckets: capacity = burst size, refill = sustained rate per second) ---
    rate_limit_failure_mode: Literal["open", "closed"] = "open"
    # Failure policy for sensitive endpoints (bookings, refunds, payments, account changes): when a
    # check that needs Redis, or the session store, could not run, they are restricted (or blocked)
    # instead of carrying on as if nothing were wrong. Ordinary chat is not affected.
    sensitive_endpoints: str = "booking*,refund*,payment*,account*"  # globs; a policy can also say sensitive
    degraded_sensitive_action: Literal["allow", "restrict", "block"] = "restrict"
    # Identifier enumeration: one chat (or one IP across chats) trying many different booking references
    # / tickets / Aeroplan numbers within the window. The customer's own verified identifiers never count;
    # shared and never-ban IPs are not counted per IP.
    enum_enabled: bool = True
    enum_types: str = "booking_ref,ticket,aeroplan"
    enum_window_seconds: int = Field(600, gt=0)
    enum_session_restrict_at: int = Field(4, ge=2)
    enum_session_block_at: int = Field(8, ge=2)
    enum_ip_restrict_at: int = Field(12, ge=2)
    rl_ip_capacity: float = Field(60, gt=0)
    rl_ip_refill_per_sec: float = Field(1.0, gt=0)
    rl_user_capacity: float = Field(30, gt=0)
    rl_user_refill_per_sec: float = Field(0.5, gt=0)
    rl_api_key_capacity: float = Field(2000, gt=0)
    rl_api_key_refill_per_sec: float = Field(200, gt=0)
    rl_session_capacity: float = Field(20, gt=0)  # one chat: burst of 20 messages…
    rl_session_refill_per_sec: float = Field(0.2, gt=0)  # …then one every 5 s
    rl_global_capacity: float = Field(10000, gt=0)  # the whole gateway (all callers)
    rl_global_refill_per_sec: float = Field(1000, gt=0)
    rl_endpoint_capacity: float = Field(5000, gt=0)
    rl_endpoint_refill_per_sec: float = Field(500, gt=0)

    # --- reputation (score 0–100, decays by half every half-life) ---
    reputation_half_life_seconds: float = Field(6 * 3600, gt=0)
    reputation_restrict_at: float = Field(60, ge=0, le=100)
    reputation_ttl_seconds: int = Field(7 * 24 * 3600, gt=0)

    # --- strikes and bans ---
    strike_window_seconds: int = Field(30 * 24 * 3600, gt=0)
    # A block whose only striking check is one of these (probabilistic, single-signal) does not strike
    # the customer, device or IP: the message is still refused and the session's block count still
    # grows (conversation lock, handoff), but one model verdict never starts the ban ladder. Two
    # striking checks, or a deterministic one, always strike.
    single_signal_no_strike: str = "ml,rules"
    # Auto-ban durations by strike count (1st, 2nd, 3rd, …). Beyond the list the last value repeats,
    # unless permanent_after_strikes is reached *with* deterministic evidence.
    ban_ladder_seconds: list[int] = Field(default_factory=lambda: [60, 900, 86400])
    permanent_after_strikes: int = Field(4, gt=0)
    throttle_strike_count: int = Field(30, gt=0)
    throttle_strike_window_seconds: int = Field(60, gt=0)
    auth_fail_strike_count: int = Field(20, gt=0)
    auth_fail_window_seconds: int = Field(300, gt=0)
    ban_cache_refresh_seconds: float = Field(30.0, gt=0)
    # IPs/CIDRs that are never banned automatically (e.g. CMP's own servers, shared NATs). Comma-separated.
    never_ban_cidrs: str = "127.0.0.0/8,::1/128"

    # --- shared IP addresses (airport / hotel Wi-Fi, mobile-carrier NAT, offices) ---
    # A request that carries a user or device id is penalised through that identity, not its IP:
    # one person's attack must not ban everyone behind the same address.
    # An IP is "shared" once this many distinct users sent *allowed* traffic from it within the window
    # (attack traffic never counts, so inventing user ids cannot make an IP look shared).
    shared_ip_min_users: int = Field(3, ge=2)
    shared_ip_window_seconds: int = Field(24 * 3600, gt=0)
    # A shared IP's rate-limit bucket is this many times larger (many people, one address).
    shared_ip_rate_multiplier: float = Field(10.0, ge=1)
    # The IP itself gets a strike when this many *different* identities attacked from it within the
    # window — unless it is shared (catches attackers who rotate user ids).
    ip_attackers_for_strike: int = Field(3, ge=2)
    ip_attackers_window_seconds: int = Field(3600, gt=0)
    # Automatic IP bans stop at the last ladder step (24 h): addresses are reassigned.
    ip_ban_never_permanent: bool = True

    # --- conversation analysis (Stage 6) — only for requests that carry a conversation id ---
    # Crescendo: attack-likeness rising over the last turns. With "strict" all three must rise; with
    # "loose" two of the last three steps rise and the latest leans to attack.
    conv_crescendo_mode: Literal["strict", "loose"] = "loose"
    conversation_enabled: bool = True
    conversation_window: int = Field(10, gt=0)  # turns remembered per conversation
    conversation_ttl_seconds: int = Field(3600, gt=0)  # memory expires this long after the last turn
    conv_turn_chars: int = Field(500, gt=0)  # characters of each turn kept (for the window re-score)
    # Window re-score: the last N turns the AI actually saw (this one included), joined and scored again.
    conv_window_turns: int = Field(4, ge=2)
    # The joined window must score this much above its best single turn to count as a split payload.
    conv_window_lift: float = Field(0.55, ge=0, le=1)
    # What a high ML score on the joined window may do. Off by default: on the calibration set it
    # caught no attack the other checks missed and flagged normal chats, because joined unrelated
    # questions look like an injection to the model. Rules on the window (an exact phrase matched
    # across turns) always run and block.
    conv_window_ml_action: Literal["off", "restrict", "block"] = "off"
    # Accumulated risk: acc = decay * acc + max(0, turn_score - floor). Several medium turns add up.
    conv_decay: float = Field(0.75, ge=0, lt=1)
    conv_floor: float = Field(0.3, ge=0, lt=1)
    conv_restrict_at: float = Field(1.0, gt=0)
    conv_block_at: float = Field(2.0, gt=0)
    # A "setup" turn ("from now on …") arms the conversation: later excess counts this much more.
    conv_setup_turns: int = Field(5, ge=0)
    conv_setup_boost: float = Field(2.0, ge=1)
    # Steadily rising attack-likeness over the last 3 turns adds this to the accumulator.
    conv_crescendo_bonus: float = Field(0.15, ge=0)
    # A turn this similar (cosine) to an earlier blocked turn is a retry.
    conv_retry_similarity: float = Field(0.85, gt=0, le=1)
    # After this many blocked turns the rest of the conversation is locked to conv_lock_action.
    conv_max_blocks: int = Field(3, gt=0)
    conv_lock_action: Literal["restrict", "block"] = "restrict"

    # --- bot detection and adaptive throttling (Stage 8) ---
    bot_enabled: bool = True
    bot_window_events: int = Field(20, ge=5)  # recent requests remembered per identity
    bot_ttl_seconds: int = Field(900, gt=0)
    bot_min_gaps: int = Field(5, ge=3)  # gaps needed before timing regularity counts
    bot_regular_cv: float = Field(0.15, gt=0)  # gap variation below this = on a timer
    bot_regular_max_gap_seconds: float = Field(60, gt=0)  # only fast timers count (slow polling is harmless)
    bot_fast_cps: float = Field(20, gt=0)  # characters per second no person types
    bot_fast_min_chars: int = Field(30, gt=0)  # shorter messages are too short to judge typing speed
    bot_dup_distance: int = Field(12, ge=0, le=32)  # SimHash bits apart that still count as the same message
    bot_dup_count: int = Field(3, gt=0)  # near-duplicates in the window that count as repetition
    bot_rate_per_minute: int = Field(20, gt=0)
    bot_campaign_identities: int = Field(5, gt=1)  # identities sending the same message = a campaign
    bot_campaign_window_seconds: int = Field(600, gt=0)
    # Only messages at least this long count for campaigns: many customers legitimately send the
    # same short question ("is my flight on time?").
    bot_campaign_min_words: int = Field(8, gt=2)
    bot_automation_user_agents: str = (
        "curl,wget,python-requests,python-httpx,python-urllib,aiohttp,go-http-client,okhttp,java/,"
        "libwww-perl,httpclient,headless,phantomjs,selenium,puppeteer,playwright,scrapy"
    )
    bot_hosting_cidrs: str = ""  # e.g. cloud/VPS ranges; requests from them add to the bot score
    # A request whose only identity besides the IP is a session id is profiled by the IP too: sessions
    # are free to open, so a bot that starts a new chat per message would otherwise never be seen.
    bot_profile_ip_for_session_only: bool = True
    # Channels where a user agent means something (a browser). SMS, WhatsApp, Apple Messages … reach CMP
    # through a provider, so their user agent is not the customer's and is ignored.
    bot_ua_channels: str = "web"
    # Tiers: the end user's rate-limit buckets drain this much faster…
    bot_suspect_at: float = Field(0.4, gt=0, le=1)
    bot_suspect_cost: float = Field(3.0, ge=1)
    bot_likely_at: float = Field(0.6, gt=0, le=1)
    bot_likely_cost: float = Field(10.0, ge=1)
    # …and at this score the request is throttled outright.
    bot_block_at: float = Field(0.8, gt=0, le=1)
    bot_cooldown_seconds: int = Field(30, gt=0)

    # --- sensitive data and outbound checks (Stage 7) ---
    sensitive_enabled: bool = True
    # Types (or categories: pii, payment, secret, identifier) redacted from user text before it reaches
    # the AI. A customer's own email, phone or booking reference stays: the AI needs them to help.
    inbound_redact_types: str = "payment,secret,sin,ssn,passport"
    outbound_enabled: bool = True
    # Always redacted from replies, whoever they belong to (the AI never needs to repeat them in full).
    outbound_always_redact: str = "payment,sin,ssn,passport,dob"
    # A secret in a reply: block the reply (default) or deliver it redacted.
    outbound_secret_action: Literal["block", "redact"] = "block"  # noqa: S105 - an action, not a secret
    # Identifiers checked against the caller's scope (``allowed_identifiers``): the authorized-data check.
    outbound_scope_types: str = "email,phone,booking_ref,ticket,aeroplan"
    # Identifier not in the caller's scope → block (default) or redact.
    outbound_unauthorized_action: Literal["block", "redact"] = "block"
    # The caller sent no scope at all → identifiers are allowed, redacted (default) or blocked.
    outbound_unscoped_action: Literal["allow", "redact", "block"] = "redact"
    # This many distinct identifiers in one reply looks like a record dump → block.
    outbound_bulk_identifiers: int = Field(5, gt=1)
    outbound_max_chars: int = Field(8000, gt=0)  # longer replies are restricted (flagged for review)
    # Replies that promise money, approvals or policy exceptions ("you will be refunded $500", "I have
    # approved") → restrict in anonymous sessions (CMP routes them for review), flag in verified ones.
    outbound_commitment_action: Literal["off", "flag", "restrict"] = "restrict"
    # A reply that asks the customer to type a card number, password, SIN … → block (phishing through
    # a trusted channel) or flag.
    outbound_credential_request_action: Literal["off", "flag", "block"] = "block"
    # A reply that itself contains an injection (template tokens, "ignore previous instructions"): an
    # attack got through and is being relayed → block or flag.
    outbound_injection_echo_action: Literal["off", "flag", "block"] = "block"
    # Replies that look like general-purpose output (code fences, very long) are flagged.
    outbound_code_fence_flag: bool = True
    # A reply sharing this many hashed 8-word shingles with a registered system prompt leaked it → block.
    prompt_leak_min_shingles: int = Field(3, gt=0)
    # Out-of-scope identifiers in replies are also counted per session (slow harvesting: one foreign
    # booking per reply): ≥ ENUM_SESSION_BLOCK_AT distinct in ENUM_WINDOW_SECONDS → block.
    outbound_enum_enabled: bool = True
    outbound_strip_images: bool = True  # markdown images can carry data out in their URL
    outbound_strip_unknown_links: bool = True  # links outside ALLOWED_LINK_DOMAINS
    canary_cache_ttl_seconds: float = Field(30.0, gt=0)

    # --- audit trail, policies, metrics (Stage 9) ---
    audit_enabled: bool = True
    audit_stream: str = "audit:events"
    audit_stream_maxlen: int = Field(100_000, gt=0)  # approximate cap on unwritten + recent entries
    audit_worker_enabled: bool = True  # run the stream → PostgreSQL writer inside this gateway
    audit_batch_size: int = Field(200, gt=0)
    audit_claim_idle_seconds: int = Field(30, gt=0)  # retry entries a crashed worker left unwritten
    audit_excerpt_chars: int = Field(200, ge=0)
    policy_cache_ttl_seconds: float = Field(30.0, gt=0)
    # Password for the read-only "dashboard_reader" database role Grafana uses to show per-message
    # details (the audit trail, bans, policies — never API keys). Unset = the role cannot log in.
    dashboard_db_password: SecretStr | None = None

    # --- privacy ---
    store_redacted_excerpt: bool = True

    # --- readiness ---
    ready_probe_timeout_ms: int = Field(500, gt=0)


def parse_channel_limits(raw: str) -> dict[str, int]:
    """``"sms:1600,web:4000"`` → ``{"sms": 1600, "web": 4000}`` (bad entries are ignored)."""
    out: dict[str, int] = {}
    for part in raw.split(","):
        name, _, value = part.partition(":")
        if name.strip() and value.strip().isdigit() and int(value) > 0:
            out[name.strip().lower()] = int(value)
    return out


def load_settings(**overrides: object) -> Settings:
    """Load settings from the environment; keyword overrides win (used by tests)."""
    return Settings(**overrides)  # type: ignore[arg-type]
