"""Load the plugin the way hermes_cli.plugins does (as ``hermes_plugins.canary_trap``)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1] / "canary-trap"


def _load():
    if "hermes_plugins.canary_trap" in sys.modules:
        return sys.modules["hermes_plugins.canary_trap"]
    pkg = types.ModuleType("hermes_plugins")
    pkg.__path__ = []
    sys.modules.setdefault("hermes_plugins", pkg)
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.canary_trap", PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hermes_plugins.canary_trap"] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeState:
    def __init__(self):
        self.d = {}

    def get(self, k, default=None):
        return self.d.get(k, default)

    def set(self, k, v):
        self.d[k] = v


class FakeCtx:
    RESERVED = {"model", "plugins", "security", "settings"}

    def __init__(self, config=None):
        self.state = FakeState()
        self.config = config or {}
        self.hooks, self.commands = {}, {}

    def get_config(self, key, default=None):
        if key.split(".")[0] in self.RESERVED:
            raise ValueError(key)
        return self.config.get(key, default)

    def register_hook(self, name, fn, **kw):
        self.hooks[name] = fn

    def register_command(self, name, handler, **kw):
        self.commands[name] = handler


@pytest.fixture(scope="session")
def ct():
    return _load()


@pytest.fixture
def ctx():
    return FakeCtx()


@pytest.fixture
def plugin(ct, ctx):
    ct.register(ctx)
    return ctx
