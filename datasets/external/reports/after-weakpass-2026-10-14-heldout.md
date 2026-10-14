# External datasets — baseline against the current gateway (2026-10-14)

Rows: 1779 single-turn, 400 multi-turn conversations (sample of 6536). Seed 7. ML model `ensemble-20261014103132`, thresholds {'restrict': 0.8327, 'block': 0.9162}; tool model `tool-20261014104045`, thresholds {'restrict': 0.9257, 'block': 0.9757}. Bot profiling off, rate limits lifted.
Inspect latency (in-process, single-turn): p50 120 ms, p95 2025 ms.

Attacks: *caught* = restricted or blocked. Benign: *flagged* = a false positive.

## By category (all sources)

| label / category | n | caught or flagged | blocked | checks that fired (count) |
|---|---|---|---|---|
| attack/context_only_task | 56 | 2/56 (3.6%) | 2/56 (3.6%) | ml 2 |
| attack/direct_injection | 538 | 471/538 (87.5%) | 381/538 (70.8%) | ml 360, rules 263, size 1 |
| attack/harmful_request | 101 | 67/101 (66.3%) | 46/101 (45.5%) | ml 67 |
| attack/indirect_injection | 161 | 145/161 (90.1%) | 139/161 (86.3%) | ml 145, rules 2 |
| attack/jailbreak | 221 | 218/221 (98.6%) | 178/221 (80.5%) | ml 212, rules 50, size 6 |
| attack/output_manipulation | 97 | 11/97 (11.3%) | 7/97 (7.2%) | ml 11 |
| attack/prompt_extraction | 430 | 417/430 (97.0%) | 403/430 (93.7%) | ml 414, rules 176 |
| benign/benign | 153 | 0/153 (0.0%) | 0/153 (0.0%) | — |
| benign/benign_hard | 22 | 3/22 (13.6%) | 1/22 (4.5%) | ml 3 |

## By source

| source | use | label / category | n | caught or flagged | blocked | decided by |
|---|---|---|---|---|---|---|
| advbench | train+eval | attack/harmful_request | 84 | 58/84 (69.0%) | 39/84 (46.4%) | ml 58 |
| bipia | train+eval | attack/context_only_task | 56 | 2/56 (3.6%) | 2/56 (3.6%) | ml 2 |
| bipia | train+eval | attack/indirect_injection | 146 | 137/146 (93.8%) | 133/146 (91.1%) | ml 137 |
| bipia | train+eval | attack/output_manipulation | 97 | 11/97 (11.3%) | 7/97 (7.2%) | ml 11 |
| garak | train+eval | attack/jailbreak | 111 | 110/111 (99.1%) | 71/111 (64.0%) | ml 64, rules 40, size 6 |
| injecagent | train+eval | attack/indirect_injection | 15 | 8/15 (53.3%) | 6/15 (40.0%) | ml 8 |
| injecagent | train+eval | benign/benign | 5 | 0/5 (0.0%) | 0/5 (0.0%) | — |
| jailbreakbench-artifacts | train+eval | attack/jailbreak | 110 | 108/110 (98.2%) | 107/110 (97.3%) | ml 108 |
| jailbreakbench-behaviors | train+eval | attack/harmful_request | 17 | 9/17 (52.9%) | 7/17 (41.2%) | ml 9 |
| jailbreakbench-behaviors | train+eval | benign/benign_hard | 22 | 3/22 (13.6%) | 1/22 (4.5%) | ml 3 |
| local-attacks-heldout | reference | attack/direct_injection | 60 | 41/60 (68.3%) | 34/60 (56.7%) | ml 40, rules 1 |
| local-benign-heldout-deepset | reference | benign/benign | 56 | 0/56 (0.0%) | 0/56 (0.0%) | — |
| local-benign-heldout-handwritten | reference | benign/benign | 92 | 0/92 (0.0%) | 0/92 (0.0%) | — |
| tensor-trust | eval_only | attack/direct_injection | 478 | 430/478 (90.0%) | 347/478 (72.6%) | ml 221, rules 208, size 1 |
| tensor-trust | eval_only | attack/prompt_extraction | 430 | 417/430 (97.0%) | 403/430 (93.7%) | ml 298, rules 119 |

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
| bipia | Language Translation | 12 | 0/12 (0.0%) |
| bipia | Reverse Text | 6 | 0/6 (0.0%) |
| bipia | Substitution Ciphers | 6 | 0/6 (0.0%) |
| bipia | Misinformation & Propaganda | 6 | 1/6 (16.7%) |
| bipia | Anagramming | 6 | 1/6 (16.7%) |
| bipia | Homophonic Substitution | 6 | 1/6 (16.7%) |
| bipia | Misspelling Intentionally | 6 | 1/6 (16.7%) |

## Multi-turn (each conversation one session)

`obfuscated_benign`: a harmless goal delivered through the same cipher / word-mapping set-up as the attacks. Blocking it is expected in a customer chat; it is not a false positive.

| label / category | conversations | caught or flagged | blocked | via conversation check | median first flagged turn | turns flagged | decided by |
|---|---|---|---|---|---|---|---|
| attack/jailbreak | 200 | 200/200 (100.0%) | 200/200 (100.0%) | 26 | 7.0 | 391/2186 (17.9%) | ml 200 |
| benign/obfuscated_benign | 200 | 200/200 (100.0%) | 200/200 (100.0%) | 10 | 7.0 | 332/1896 (17.5%) | ml 200 |

## Tool results (POST /v1/inspect/tool-result, one tool output per row)

Tool-content model: `tool-20261014104045` (None: the chat model answered).

| set | label / family | n | caught or flagged | withheld | parts removed | decided by |
|---|---|---|---|---|---|---|
| external-indirect-as-tool-data | attack/indirect_injection | 161 | 160/161 (99.4%) | 151 | 9 | ml 151, untrusted_content 9 |
| sealed-attacks | attack/indirect_injection | 53 | 47/53 (88.7%) | 30 | 17 | ml 34, untrusted_content 13 |
| sealed-benign | benign/airline_hard_negative | 81 | 9/81 (11.1%) | 0 | 9 | untrusted_content 9 |
| sealed-benign | benign/airline_tool_content | 109 | 0/109 (0.0%) | 0 | 0 | — |
| toolcontent-attacks | attack/indirect_injection | 106 | 100/106 (94.3%) | 77 | 23 | ml 77, untrusted_content 23 |
| toolcontent-benign | benign/airline_hard_negative | 79 | 0/79 (0.0%) | 0 | 0 | — |
| toolcontent-benign | benign/airline_tool_content | 95 | 0/95 (0.0%) | 0 | 0 | — |

Misses and false positives (text, family, ML score) are in the JSON report next to this file.
