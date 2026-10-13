# Multi-turn calibration sweep (calib.jsonl)

Built from one half of the held-out rows (the report set uses the other half). Budget: the conversation
check may flag at most 2.5% of normal conversations. Rule: most attack conversations caught, then fewest
false alarms. Chosen: `conv_window_ml_action=off`, `conv_restrict_at=1.0` (lift does not apply when off).

| ML on joined window | lift | accumulated restrict at | attack conversations caught | normal conversations flagged by the conversation check |
|---|---|---|---|---|
| block | 0.25 | 0.8 | 0.880 | 0.289 |
| block | 0.25 | 1.0 | 0.880 | 0.267 |
| block | 0.25 | 1.2 | 0.880 | 0.267 |
| block | 0.4 | 0.8 | 0.880 | 0.111 |
| block | 0.4 | 1.0 | 0.880 | 0.067 |
| block | 0.4 | 1.2 | 0.880 | 0.067 |
| block | 0.55 | 0.8 | 0.860 | 0.067 |
| block | 0.55 | 1.0 | 0.860 | 0.022 |
| block | 0.55 | 1.2 | 0.860 | 0.022 |
| restrict | 0.25 | 0.8 | 0.880 | 0.289 |
| restrict | 0.25 | 1.0 | 0.880 | 0.267 |
| restrict | 0.25 | 1.2 | 0.880 | 0.267 |
| restrict | 0.4 | 0.8 | 0.880 | 0.111 |
| restrict | 0.4 | 1.0 | 0.880 | 0.067 |
| restrict | 0.4 | 1.2 | 0.880 | 0.067 |
| restrict | 0.55 | 0.8 | 0.860 | 0.067 |
| restrict | 0.55 | 1.0 | 0.860 | 0.022 |
| restrict | 0.55 | 1.2 | 0.860 | 0.022 |
| off | 0.25 | 0.8 | 0.860 | 0.044 |
| off | 0.25 | 1.0 | 0.860 | 0.000 |
| off | 0.25 | 1.2 | 0.860 | 0.000 |
| off | 0.4 | 0.8 | 0.860 | 0.044 |
| off | 0.4 | 1.0 | 0.860 | 0.000 |
| off | 0.4 | 1.2 | 0.860 | 0.000 |
| off | 0.55 | 0.8 | 0.860 | 0.044 |
| off | 0.55 | 1.0 | 0.860 | 0.000 |
| off | 0.55 | 1.2 | 0.860 | 0.000 |
