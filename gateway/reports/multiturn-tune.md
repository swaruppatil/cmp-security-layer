# Multi-turn evaluation — tune.jsonl

Settings: `conv_floor=0.3`, `conv_decay=0.75`, `conv_restrict_at=1.0`, `conv_block_at=2.0`, `conv_window_lift=0.25`, `conv_window_turns=4`, `conv_retry_similarity=0.85`, `conv_max_blocks=3`, `conv_setup_boost=2.0`

| kind | n | caught, single-turn | caught, Stage 6 | blocked, Stage 6 | median turns to catch (single → Stage 6) | caught only by Stage 6, via |
|---|---|---|---|---|---|---|
| split_payload | 60 | 60/60 | 60/60 | 56/60 | 0.0 → 0.0 | — |
| probing | 40 | 40/40 | 40/40 | 40/40 | 0.0 → 0.0 | — |
| retry_after_block | 40 | 40/40 | 40/40 | 40/40 | 0.0 → 0.0 | — |

| benign kind | conversations | turns | flagged, single-turn | flagged, Stage 6 | flagged by the conversation check | turns flagged, Stage 6 |
|---|---|---|---|---|---|---|
| benign_long | 80 | 964 | 3/80 | 3/80 | 0/80 | 3 |
