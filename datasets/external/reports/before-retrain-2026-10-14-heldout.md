# External datasets — baseline against the current gateway (2026-10-14)

Rows: 1779 single-turn, 392 multi-turn conversations (sample of 6536). Seed 7. ML model `ensemble-20261014050420`, thresholds: restrict 0.7, block 0.9. Bot profiling off, rate limits lifted.
Inspect latency (in-process, single-turn): p50 92 ms, p95 164 ms.

Attacks: *caught* = restricted or blocked. Benign: *flagged* = a false positive.

## By category (all sources)

| label / category | n | caught or flagged | blocked | checks that fired (count) |
|---|---|---|---|---|
| attack/direct_injection | 538 | 497/538 (92.4%) | 438/538 (81.4%) | ml 386, rules 263, size 1 |
| attack/harmful_request | 101 | 77/101 (76.2%) | 38/101 (37.6%) | ml 77 |
| attack/indirect_injection | 314 | 219/314 (69.7%) | 112/314 (35.7%) | ml 219, rules 2 |
| attack/jailbreak | 221 | 218/221 (98.6%) | 199/221 (90.0%) | ml 212, rules 50, size 6 |
| attack/prompt_extraction | 430 | 425/430 (98.8%) | 414/430 (96.3%) | ml 422, rules 176 |
| benign/benign | 153 | 8/153 (5.2%) | 2/153 (1.3%) | ml 8 |
| benign/benign_hard | 22 | 10/22 (45.5%) | 4/22 (18.2%) | ml 10 |

## By source

| source | use | label / category | n | caught or flagged | blocked | decided by |
|---|---|---|---|---|---|---|
| advbench | train+eval | attack/harmful_request | 84 | 64/84 (76.2%) | 33/84 (39.3%) | ml 64 |
| bipia | train+eval | attack/indirect_injection | 299 | 213/299 (71.2%) | 110/299 (36.8%) | ml 213 |
| garak | train+eval | attack/jailbreak | 111 | 111/111 (100.0%) | 110/111 (99.1%) | ml 85, rules 20, size 6 |
| injecagent | train+eval | attack/indirect_injection | 15 | 6/15 (40.0%) | 2/15 (13.3%) | ml 6 |
| injecagent | train+eval | benign/benign | 5 | 1/5 (20.0%) | 0/5 (0.0%) | ml 1 |
| jailbreakbench-artifacts | train+eval | attack/jailbreak | 110 | 107/110 (97.3%) | 89/110 (80.9%) | ml 107 |
| jailbreakbench-behaviors | train+eval | attack/harmful_request | 17 | 13/17 (76.5%) | 5/17 (29.4%) | ml 13 |
| jailbreakbench-behaviors | train+eval | benign/benign_hard | 22 | 10/22 (45.5%) | 4/22 (18.2%) | ml 10 |
| local-attacks-heldout | reference | attack/direct_injection | 60 | 50/60 (83.3%) | 38/60 (63.3%) | ml 49, rules 1 |
| local-benign-heldout-deepset | reference | benign/benign | 56 | 2/56 (3.6%) | 0/56 (0.0%) | ml 2 |
| local-benign-heldout-handwritten | reference | benign/benign | 92 | 5/92 (5.4%) | 2/92 (2.2%) | ml 5 |
| tensor-trust | eval_only | attack/direct_injection | 478 | 447/478 (93.5%) | 400/478 (83.7%) | ml 275, rules 171, size 1 |
| tensor-trust | eval_only | attack/prompt_extraction | 430 | 425/430 (98.8%) | 414/430 (96.3%) | ml 308, rules 117 |

## Weakest attack families (≥ 5 rows, lowest catch rate)

| source | family | n | caught |
|---|---|---|---|
| bipia | Conversational Agent | 5 | 0/5 (0.0%) |
| bipia | Information Retrieval | 6 | 0/6 (0.0%) |
| bipia | Business Intelligence | 6 | 1/6 (16.7%) |
| bipia | Learning and Tutoring | 6 | 1/6 (16.7%) |
| bipia | Programming Help | 6 | 1/6 (16.7%) |
| bipia | Research Assistance | 6 | 1/6 (16.7%) |
| bipia | Emoji Substitution | 5 | 1/5 (20.0%) |
| bipia | Language Translation | 12 | 4/12 (33.3%) |
| bipia | Persuasion | 6 | 2/6 (33.3%) |
| bipia | Sentiment Analysis | 6 | 2/6 (33.3%) |
| bipia | Scams & Fraud | 5 | 2/5 (40.0%) |
| injecagent | others | 5 | 2/5 (40.0%) |
| bipia | Task Automation | 7 | 3/7 (42.9%) |
| bipia | Clickbait | 6 | 3/6 (50.0%) |
| bipia | Information Dissemination | 6 | 3/6 (50.0%) |
| bipia | Malware Distribution | 6 | 3/6 (50.0%) |
| bipia | Misinformation & Propaganda | 6 | 3/6 (50.0%) |
| bipia | Entertainment | 5 | 3/5 (60.0%) |
| bipia | Marketing & Advertising | 5 | 3/5 (60.0%) |
| bipia | Content Creation | 8 | 5/8 (62.5%) |

## Multi-turn (each conversation one session)

| label / category | conversations | caught or flagged | blocked | via conversation check | median first flagged turn | turns flagged | decided by |
|---|---|---|---|---|---|---|---|
| attack/jailbreak | 200 | 200/200 (100.0%) | 200/200 (100.0%) | 14 | 0.0 | 586/2256 (26.0%) | ml 200 |
| benign/benign | 96 | 96/96 (100.0%) | 96/96 (100.0%) | 13 | 0.0 | 287/911 (31.5%) | ml 96 |
| benign/benign_hard | 96 | 96/96 (100.0%) | 96/96 (100.0%) | 10 | 0.0 | 270/909 (29.7%) | ml 96 |

## Tool results (POST /v1/inspect/tool-result, one tool output per row)

| set | label / family | n | caught or flagged | withheld | parts removed | decided by |
|---|---|---|---|---|---|---|
| external-indirect-as-tool-data | attack/indirect_injection | 314 | 250/314 (79.6%) | 147 | 103 | ml 250 |
| toolcontent-attacks | attack/indirect_injection | 64 | 42/64 (65.6%) | 25 | 17 | ml 42 |
| toolcontent-benign | benign/airline_hard_negative | 69 | 44/69 (63.8%) | 13 | 31 | ml 44 |
| toolcontent-benign | benign/airline_tool_content | 101 | 14/101 (13.9%) | 0 | 14 | ml 14 |

Misses and false positives (text, family, ML score) are in the JSON report next to this file.
