"""Unit tests never read the developer's environment: a shell that sourced ../.env (ADMIN_API_KEY,
IDENTITY_HASH_KEY, rate limits …) must not change what the tests see. Settings come only from each
test's explicit values (``tests.fakes.make_settings``) and the defaults in ``app/config.py``."""

from __future__ import annotations

import os

import pytest

from app.config import Settings


@pytest.fixture(autouse=True)
def _no_gateway_settings_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    fields = {name.upper() for name in Settings.model_fields}
    for var in list(os.environ):
        if var.upper() in fields:
            monkeypatch.delenv(var)
