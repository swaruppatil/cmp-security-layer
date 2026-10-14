# External datasets — baseline against the current gateway (2026-10-14)

Rows: 1779 single-turn, 400 multi-turn conversations (sample of 6536). Seed 7. ML model `ensemble-20261014080747`, thresholds {'restrict': 0.7718, 'block': 0.92}; tool model `tool-20261014081623`, thresholds {'restrict': 0.8913, 'block': 0.9413}. Bot profiling off, rate limits lifted.
Inspect latency (in-process, single-turn): p50 114 ms, p95 2025 ms.

Attacks: *caught* = restricted or blocked. Benign: *flagged* = a false positive.

## By category (all sources)

| label / category | n | caught or flagged | blocked | checks that fired (count) |
|---|---|---|---|---|
| attack/context_only_task | 56 | 2/56 (3.6%) | 1/56 (1.8%) | ml 2 |
| attack/direct_injection | 538 | 486/538 (90.3%) | 385/538 (71.6%) | ml 375, rules 263, size 1 |
| attack/harmful_request | 101 | 75/101 (74.3%) | 53/101 (52.5%) | ml 75 |
| attack/indirect_injection | 161 | 143/161 (88.8%) | 138/161 (85.7%) | ml 143, rules 2 |
| attack/jailbreak | 221 | 218/221 (98.6%) | 170/221 (76.9%) | ml 212, rules 50, size 6 |
| attack/output_manipulation | 97 | 11/97 (11.3%) | 6/97 (6.2%) | ml 11 |
| attack/prompt_extraction | 430 | 421/430 (97.9%) | 409/430 (95.1%) | ml 418, rules 176 |
| benign/benign | 153 | 0/153 (0.0%) | 0/153 (0.0%) | — |
| benign/benign_hard | 22 | 6/22 (27.3%) | 3/22 (13.6%) | ml 6 |

## By source

| source | use | label / category | n | caught or flagged | blocked | decided by |
|---|---|---|---|---|---|---|
| advbench | train+eval | attack/harmful_request | 84 | 63/84 (75.0%) | 46/84 (54.8%) | ml 63 |
| bipia | train+eval | attack/context_only_task | 56 | 2/56 (3.6%) | 1/56 (1.8%) | ml 2 |
| bipia | train+eval | attack/indirect_injection | 146 | 135/146 (92.5%) | 131/146 (89.7%) | ml 135 |
| bipia | train+eval | attack/output_manipulation | 97 | 11/97 (11.3%) | 6/97 (6.2%) | ml 11 |
| garak | train+eval | attack/jailbreak | 111 | 110/111 (99.1%) | 66/111 (59.5%) | ml 60, rules 44, size 6 |
| injecagent | train+eval | attack/indirect_injection | 15 | 8/15 (53.3%) | 7/15 (46.7%) | ml 8 |
| injecagent | train+eval | benign/benign | 5 | 0/5 (0.0%) | 0/5 (0.0%) | — |
| jailbreakbench-artifacts | train+eval | attack/jailbreak | 110 | 108/110 (98.2%) | 104/110 (94.5%) | ml 108 |
| jailbreakbench-behaviors | train+eval | attack/harmful_request | 17 | 12/17 (70.6%) | 7/17 (41.2%) | ml 12 |
| jailbreakbench-behaviors | train+eval | benign/benign_hard | 22 | 6/22 (27.3%) | 3/22 (13.6%) | ml 6 |
| local-attacks-heldout | reference | attack/direct_injection | 60 | 43/60 (71.7%) | 28/60 (46.7%) | ml 42, rules 1 |
| local-benign-heldout-deepset | reference | benign/benign | 56 | 0/56 (0.0%) | 0/56 (0.0%) | — |
| local-benign-heldout-handwritten | reference | benign/benign | 92 | 0/92 (0.0%) | 0/92 (0.0%) | — |
| tensor-trust | eval_only | attack/direct_injection | 478 | 443/478 (92.7%) | 357/478 (74.7%) | ml 237, rules 205, size 1 |
| tensor-trust | eval_only | attack/prompt_extraction | 430 | 421/430 (97.9%) | 409/430 (95.1%) | ml 302, rules 119 |

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
| bipia | Alphanumeric Substitution | 5 | 0/5 (0.0%) |
| bipia | Base Encoding | 5 | 0/5 (0.0%) |
| bipia | Emoji Substitution | 5 | 0/5 (0.0%) |
| bipia | Entertainment | 5 | 0/5 (0.0%) |
| bipia | Information Dissemination | 6 | 0/6 (0.0%) |
| bipia | Persuasion | 6 | 0/6 (0.0%) |
| bipia | Reverse Text | 6 | 0/6 (0.0%) |
| bipia | Substitution Ciphers | 6 | 0/6 (0.0%) |
| bipia | Language Translation | 12 | 1/12 (8.3%) |
| bipia | Misinformation & Propaganda | 6 | 1/6 (16.7%) |
| bipia | Anagramming | 6 | 1/6 (16.7%) |
| bipia | Homophonic Substitution | 6 | 1/6 (16.7%) |

## Multi-turn (each conversation one session)

`obfuscated_benign`: a harmless goal delivered through the same cipher / word-mapping set-up as the attacks. Blocking it is expected in a customer chat; it is not a false positive.

| label / category | conversations | caught or flagged | blocked | via conversation check | median first flagged turn | turns flagged | decided by |
|---|---|---|---|---|---|---|---|
| attack/jailbreak | 200 | 200/200 (100.0%) | 200/200 (100.0%) | 39 | 6.0 | 465/2186 (21.3%) | ml 200 |
| benign/obfuscated_benign | 200 | 200/200 (100.0%) | 200/200 (100.0%) | 15 | 5.0 | 406/1896 (21.4%) | ml 200 |

## Tool results (POST /v1/inspect/tool-result, one tool output per row)

Tool-content model: `tool-20261014081623` (None: the chat model answered).

| set | label / family | n | caught or flagged | withheld | parts removed | decided by |
|---|---|---|---|---|---|---|
| external-indirect-as-tool-data | attack/indirect_injection | 161 | 154/161 (95.7%) | 154 | 0 | ml 154 |
| toolcontent-attacks | attack/indirect_injection | 106 | 83/106 (78.3%) | 83 | 0 | ml 83 |
| toolcontent-benign | benign/airline_hard_negative | 79 | 11/79 (13.9%) | 9 | 2 | ml 11 |
| toolcontent-benign | benign/airline_tool_content | 95 | 1/95 (1.1%) | 0 | 1 | ml 1 |

Misses and false positives (text, family, ML score) are in the JSON report next to this file.
