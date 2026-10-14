-- Whether the gateway published the passed message to CMP's Kafka topic itself (integration with
-- the enricher, 2026-10-15), to which topic, and why not when it did not. NULL for requests that
-- carried no publish spec (the enricher publishes those itself).
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS published boolean,
    ADD COLUMN IF NOT EXISTS publish_topic text,
    ADD COLUMN IF NOT EXISTS publish_error text;
