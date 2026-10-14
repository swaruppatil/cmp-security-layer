-- Tool-result inspection (POST /v1/inspect/tool-result) is audited with mode 'tool'.
ALTER TABLE security_events DROP CONSTRAINT IF EXISTS security_events_mode_check;
ALTER TABLE security_events ADD CONSTRAINT security_events_mode_check
    CHECK (mode IN ('inspect', 'proxy', 'outbound', 'proxy-outbound', 'tool'));
