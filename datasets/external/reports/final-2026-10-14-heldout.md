# External datasets — baseline against the current gateway (2026-10-14)

Rows: 1779 single-turn, 400 multi-turn conversations (sample of 6536). Seed 7. ML model `ensemble-20261014111145`, thresholds {'restrict': 0.7941, 'block': 0.9102}; tool model `tool-20261014112052`, thresholds {'restrict': 0.9215, 'block': 0.9715}. Bot profiling off, rate limits lifted.
Inspect latency (in-process, single-turn): p50 134 ms, p95 2038 ms.

Attacks: *caught* = restricted or blocked. Benign: *flagged* = a false positive.

## By category (all sources)

| label / category | n | caught or flagged | blocked | checks that fired (count) |
|---|---|---|---|---|
| attack/context_only_task | 56 | 2/56 (3.6%) | 2/56 (3.6%) | ml 2 |
| attack/direct_injection | 538 | 478/538 (88.8%) | 353/538 (65.6%) | ml 367, rules 263, size 1 |
| attack/harmful_request | 101 | 70/101 (69.3%) | 48/101 (47.5%) | ml 70 |
| attack/indirect_injection | 161 | 140/161 (87.0%) | 129/161 (80.1%) | ml 140, rules 2 |
| attack/jailbreak | 221 | 219/221 (99.1%) | 167/221 (75.6%) | ml 213, rules 50, size 6 |
| attack/output_manipulation | 97 | 10/97 (10.3%) | 6/97 (6.2%) | ml 10 |
| attack/prompt_extraction | 430 | 419/430 (97.4%) | 401/430 (93.3%) | ml 416, rules 176 |
| benign/benign | 153 | 0/153 (0.0%) | 0/153 (0.0%) | — |
| benign/benign_hard | 22 | 4/22 (18.2%) | 2/22 (9.1%) | ml 4 |

## By source

| source | use | label / category | n | caught or flagged | blocked | decided by |
|---|---|---|---|---|---|---|
| advbench | train+eval | attack/harmful_request | 84 | 60/84 (71.4%) | 40/84 (47.6%) | ml 60 |
| bipia | train+eval | attack/context_only_task | 56 | 2/56 (3.6%) | 2/56 (3.6%) | ml 2 |
| bipia | train+eval | attack/indirect_injection | 146 | 132/146 (90.4%) | 123/146 (84.2%) | ml 132 |
| bipia | train+eval | attack/output_manipulation | 97 | 10/97 (10.3%) | 6/97 (6.2%) | ml 10 |
| garak | train+eval | attack/jailbreak | 111 | 110/111 (99.1%) | 60/111 (54.1%) | ml 59, rules 45, size 6 |
| injecagent | train+eval | attack/indirect_injection | 15 | 8/15 (53.3%) | 6/15 (40.0%) | ml 8 |
| injecagent | train+eval | benign/benign | 5 | 0/5 (0.0%) | 0/5 (0.0%) | — |
| jailbreakbench-artifacts | train+eval | attack/jailbreak | 110 | 109/110 (99.1%) | 107/110 (97.3%) | ml 109 |
| jailbreakbench-behaviors | train+eval | attack/harmful_request | 17 | 10/17 (58.8%) | 8/17 (47.1%) | ml 10 |
| jailbreakbench-behaviors | train+eval | benign/benign_hard | 22 | 4/22 (18.2%) | 2/22 (9.1%) | ml 4 |
| local-attacks-heldout | reference | attack/direct_injection | 60 | 44/60 (73.3%) | 31/60 (51.7%) | ml 43, rules 1 |
| local-benign-heldout-deepset | reference | benign/benign | 56 | 0/56 (0.0%) | 0/56 (0.0%) | — |
| local-benign-heldout-handwritten | reference | benign/benign | 92 | 0/92 (0.0%) | 0/92 (0.0%) | — |
| tensor-trust | eval_only | attack/direct_injection | 478 | 434/478 (90.8%) | 322/478 (67.4%) | rules 220, ml 213, size 1 |
| tensor-trust | eval_only | attack/prompt_extraction | 430 | 419/430 (97.4%) | 401/430 (93.3%) | ml 296, rules 123 |

## Weakest attack families (≥ 5 rows, lowest catch rate)

| source | family | n | caught |
|---|---|---|---|
| bipia | Business Intelligence | 6 | 0/6 (0.0%) |
| bipia | Content Creation | 8 | 0/8 (0.0%) |
| bipia | Conversational Agent | 5 | 0/5 (0.0%) |
| bipia | Information Retrieval | 6 | 0/6 (0.0%) |
| bipia | Learning and Tutoring | 6 | 0/6 (0.0%) |
| bipia | Programming Help | 6 | 0/6 (0.0%) |
| bipia | Research Assistance | 6 | 0/6 (0.0%) |
| bipia | Sentiment Analysis | 6 | 0/6 (0.0%) |
| bipia | Misinformation & Propaganda | 6 | 0/6 (0.0%) |
| bipia | Alphanumeric Substitution | 5 | 0/5 (0.0%) |
| bipia | Base Encoding | 5 | 0/5 (0.0%) |
| bipia | Emoji Substitution | 5 | 0/5 (0.0%) |
| bipia | Entertainment | 5 | 0/5 (0.0%) |
| bipia | Information Dissemination | 6 | 0/6 (0.0%) |
| bipia | Language Translation | 12 | 0/12 (0.0%) |
| bipia | Reverse Text | 6 | 0/6 (0.0%) |
| bipia | Substitution Ciphers | 6 | 0/6 (0.0%) |
| bipia | Anagramming | 6 | 1/6 (16.7%) |
| bipia | Homophonic Substitution | 6 | 1/6 (16.7%) |
| bipia | Misspelling Intentionally | 6 | 1/6 (16.7%) |

## Multi-turn (each conversation one session)

`obfuscated_benign`: a harmless goal delivered through the same cipher / word-mapping set-up as the attacks. Blocking it is expected in a customer chat; it is not a false positive.

| label / category | conversations | caught or flagged | blocked | via conversation check | median first flagged turn | turns flagged | decided by |
|---|---|---|---|---|---|---|---|
| attack/jailbreak | 200 | 200/200 (100.0%) | 200/200 (100.0%) | 17 | 7.0 | 391/2186 (17.9%) | ml 200 |
| benign/obfuscated_benign | 200 | 200/200 (100.0%) | 200/200 (100.0%) | 10 | 7.0 | 339/1896 (17.9%) | ml 200 |

## Tool results (POST /v1/inspect/tool-result, one tool output per row)

Tool-content model: `tool-20261014112052` (None: the chat model answered).

| set | label / family | n | caught or flagged | withheld | parts removed | decided by |
|---|---|---|---|---|---|---|
| external-indirect-as-tool-data | attack/indirect_injection | 161 | 160/161 (99.4%) | 133 | 27 | ml 133, untrusted_content 27 |
| sealed-attacks | attack/indirect_injection | 53 | 46/53 (86.8%) | 30 | 16 | ml 32, untrusted_content 14 |
| sealed-benign | benign/airline_hard_negative | 81 | 1/81 (1.2%) | 0 | 1 | ml 1 |
| sealed-benign | benign/airline_tool_content | 109 | 0/109 (0.0%) | 0 | 0 | — |
| toolcontent-attacks | attack/indirect_injection | 106 | 101/106 (95.3%) | 77 | 24 | ml 79, untrusted_content 22 |
| toolcontent-benign | benign/airline_hard_negative | 79 | 4/79 (5.1%) | 2 | 2 | ml 4 |
| toolcontent-benign | benign/airline_tool_content | 95 | 1/95 (1.1%) | 1 | 0 | ml 1 |

Misses and false positives (text, family, ML score) are in the JSON report next to this file.
