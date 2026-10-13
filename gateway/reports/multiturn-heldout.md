# Multi-turn evaluation — heldout.jsonl

Settings: `conv_floor=0.3`, `conv_decay=0.75`, `conv_restrict_at=1.0`, `conv_block_at=2.0`, `conv_window_lift=0.55`, `conv_window_ml_action=off`, `conv_window_turns=4`, `conv_retry_similarity=0.85`, `conv_max_blocks=3`, `conv_setup_boost=2.0`

| kind | n | caught, single-turn | caught, Stage 6 | blocked, single-turn | blocked, Stage 6 | median turns to catch (single → Stage 6) | caught only by Stage 6, via |
|---|---|---|---|---|---|---|---|
| split_payload | 30 | 27/30 | 27/30 | 24/30 | 24/30 | 0 → 0 | — |
| probing | 15 | 15/15 | 15/15 | 15/15 | 15/15 | 0 → 0 | — |
| retry_after_block | 30 | 30/30 | 30/30 | 27/30 | 27/30 | 0.0 → 0.0 | — |

| benign kind | conversations | turns | flagged, single-turn | flagged, Stage 6 | flagged by the conversation check | turns flagged, Stage 6 |
|---|---|---|---|---|---|---|
| benign_long | 40 | 479 | 12/40 | 12/40 | 0/40 | 12 |
| benign_mixed | 20 | 195 | 6/20 | 6/20 | 0/20 | 6 |
