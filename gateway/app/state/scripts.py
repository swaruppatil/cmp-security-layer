"""Redis Lua scripts. Each runs atomically on the Redis server, using Redis's own clock (TIME), so
gateway instances never disagree about time and no read-modify-write race is possible.

Floats are returned as strings: Redis converts Lua numbers to integers in replies.
"""

# ADMISSION — one round trip per request.
#   1. Shared IP: if given, count the distinct good users seen on the request's IP (HyperLogLog); at
#      `shared_min` or more, buckets marked scalable (the IP bucket) get capacity and refill × `mult`.
#      Each bucket stores the capacity it was last used with; when it grows, the extra tokens are
#      granted immediately.
#   2. Token buckets: refill each bucket for the elapsed time, then take `cost` from *all* of them, or
#      from none if any bucket is short (so a refused request never spends tokens).
#   3. Reputation: read each score, decayed by half every half-life.
#
# KEYS = bucket keys (n), reputation keys (m), then the shared-IP counter key if has_shared = 1
# ARGV = n, then for each bucket: capacity, refill_per_sec, cost, scalable (0/1);
#        then half_life_seconds, has_shared, shared_min, mult
# Returns: { denied_index (0 = allowed), retry_after_seconds, remaining_1..n, rep_1..m, ip_users }
ADMISSION = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local n = tonumber(ARGV[1])
local base = 2 + n * 4
local half_life = tonumber(ARGV[base])
local has_shared = tonumber(ARGV[base + 1]) == 1
local nkeys = #KEYS
local ip_users = 0
local mult = 1
if has_shared then
  ip_users = redis.call('PFCOUNT', KEYS[nkeys])
  if ip_users >= tonumber(ARGV[base + 2]) then mult = tonumber(ARGV[base + 3]) end
  nkeys = nkeys - 1
end
local tokens = {}
local caps = {}
local rates = {}
local denied = 0
local retry = 0
for i = 1, n do
  local cap = tonumber(ARGV[2 + (i - 1) * 4])
  local rate = tonumber(ARGV[3 + (i - 1) * 4])
  local cost = tonumber(ARGV[4 + (i - 1) * 4])
  if tonumber(ARGV[5 + (i - 1) * 4]) == 1 then cap = cap * mult; rate = rate * mult end
  caps[i] = cap
  rates[i] = rate
  local v = redis.call('HMGET', KEYS[i], 'tokens', 'ts', 'cap')
  local tk = tonumber(v[1])
  local ts = tonumber(v[2])
  local old_cap = tonumber(v[3])
  if tk == nil or ts == nil then tk = cap; ts = now end
  -- The capacity grew (an IP became shared): add the extra room at once, not over minutes of refill.
  if old_cap ~= nil and cap > old_cap then tk = tk + (cap - old_cap) end
  tk = math.min(cap, tk + math.max(0, now - ts) * rate)
  tokens[i] = tk
  if tk < cost and denied == 0 then
    denied = i
    retry = (cost - tk) / rate
  end
end
local out = { denied, tostring(retry) }
for i = 1, n do
  local cost = tonumber(ARGV[4 + (i - 1) * 4])
  local left = tokens[i]
  if denied == 0 then
    left = tokens[i] - cost
    redis.call('HSET', KEYS[i], 'tokens', tostring(left), 'ts', tostring(now), 'cap', tostring(caps[i]))
    redis.call('EXPIRE', KEYS[i], math.ceil(caps[i] / rates[i]) + 1)
  end
  out[#out + 1] = tostring(left)
end
for j = n + 1, nkeys do
  local v = redis.call('HMGET', KEYS[j], 'score', 'ts')
  local s = tonumber(v[1]) or 0
  local ts = tonumber(v[2]) or now
  s = s * math.pow(0.5, math.max(0, now - ts) / half_life)
  out[#out + 1] = tostring(s)
end
out[#out + 1] = tostring(ip_users)
return out
"""

# REPUTATION_ADD — decay the stored score to now, add `delta`, clamp to [0, 100], count the event.
# KEYS[1] = reputation hash; ARGV = delta, half_life_seconds, ttl_seconds, event_name
# Returns: new score (string)
REPUTATION_ADD = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local v = redis.call('HMGET', KEYS[1], 'score', 'ts')
local s = tonumber(v[1]) or 0
local ts = tonumber(v[2]) or now
s = s * math.pow(0.5, math.max(0, now - ts) / tonumber(ARGV[2])) + tonumber(ARGV[1])
if s > 100 then s = 100 end
if s < 0 then s = 0 end
redis.call('HSET', KEYS[1], 'score', tostring(s), 'ts', tostring(now))
redis.call('HINCRBY', KEYS[1], 'event:' .. ARGV[4], 1)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return tostring(s)
"""

# STRIKE_ADD — record a strike, forget strikes older than the window, return the counts.
# Members are "<ts>:<evidence>:<request_id>" so the evidence kind can be counted.
# KEYS[1] = strikes sorted set; ARGV = window_seconds, evidence (deterministic|probabilistic), request_id
# Returns: { total_in_window, deterministic_in_window }
STRIKE_ADD = """
local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000
local window = tonumber(ARGV[1])
redis.call('ZADD', KEYS[1], now, string.format('%.6f', now) .. ':' .. ARGV[2] .. ':' .. ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
redis.call('EXPIRE', KEYS[1], window)
local members = redis.call('ZRANGE', KEYS[1], 0, -1)
local det = 0
for _, m in ipairs(members) do
  if string.find(m, ':deterministic:', 1, true) then det = det + 1 end
end
return { #members, det }
"""

# WINDOW_COUNT — fixed-window event counter (throttles, failed logins).
# KEYS[1] = counter; ARGV[1] = window_seconds. Returns the count in the current window.
WINDOW_COUNT = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1])) end
return c
"""


# Bot features (Stage 8). Records this request for each identity and returns their previous events;
# optionally registers the message fingerprint's bands for campaign detection (same message from many
# identities). The arithmetic (gaps, typing speed, SimHash distances) is done in Python: Lua numbers are
# doubles and cannot hold 64-bit fingerprints.
#
# KEYS: n identity event lists, then 0 or 4 band sorted sets
# ARGV: n, now_ms, event, max_events, ttl_s, campaign_window_ms, campaign_member
BOT = """
local n = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local out = {}
for i = 1, n do
  local k = KEYS[i]
  out[i] = redis.call('LRANGE', k, 0, -1)
  redis.call('RPUSH', k, ARGV[3])
  redis.call('LTRIM', k, -tonumber(ARGV[4]), -1)
  redis.call('EXPIRE', k, tonumber(ARGV[5]))
end
local campaign = 0
for j = n + 1, #KEYS do
  local z = KEYS[j]
  redis.call('ZADD', z, now, ARGV[7])
  redis.call('ZREMRANGEBYSCORE', z, '-inf', now - tonumber(ARGV[6]))
  redis.call('PEXPIRE', z, tonumber(ARGV[6]))
  local c = redis.call('ZCARD', z)
  if c > campaign then campaign = c end
end
out[n + 1] = campaign
return out
"""
