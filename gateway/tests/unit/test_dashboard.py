"""The Grafana dashboard (observability/grafana/dashboards/gateway.json): with every filter at "All",
the SQL Grafana sends must be valid. Grafana inserts a custom "all" value as is (the :sqlstring format
is not applied to it), so an unquoted value turns every condition into a syntax error and every SQL
panel shows "No data"."""

from __future__ import annotations

import json
import re
from pathlib import Path

DASHBOARD = Path(__file__).resolve().parents[3] / "observability" / "grafana" / "dashboards" / "gateway.json"


def load() -> dict:
    return json.loads(DASHBOARD.read_text())


def test_every_all_value_is_a_quoted_sql_string():
    for v in load()["templating"]["list"]:
        if v.get("includeAll"):
            assert re.fullmatch(r"'[a-z_]+'", v.get("allValue") or ""), v["name"]


def test_sql_with_every_filter_at_all_has_no_bare_words():
    dash = load()
    all_values = {v["name"]: v.get("allValue") for v in dash["templating"]["list"]}
    sql_panels = [t["rawSql"] for p in dash["panels"] for t in p.get("targets", []) if "rawSql" in t]
    assert len(sql_panels) >= 30
    for sql in sql_panels:
        filled = re.sub(
            r"\$\{(\w+):sqlstring\}",
            lambda m: all_values.get(m.group(1)) or "''",  # "All", or an empty text box
            sql,
        )
        assert "${" not in filled, filled[:120]
        # what Grafana produced before the fix: (all = 'all' OR channel = all)
        assert not re.search(r"\(all = |= all\)|OR all = ", filled), filled[:160]
