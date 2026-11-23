# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""What a telemetry event contains — and, by construction, what it cannot contain."""
from __future__ import annotations

import hashlib
import hmac
import os
import platform
import traceback
from datetime import UTC, datetime
from typing import Any

from .. import __version__

SCHEMA = 1
LEVELS = ("off", "errors", "errors+usage")
MAX_FRAMES = 12


def level(env=os.environ) -> str:
    """``TELEMETRY`` (default ``errors+usage``); always ``off`` for the public demo and for an unknown value."""
    from ..web.common import public_demo_enabled
    if public_demo_enabled(env):
        return "off"
    v = env.get("TELEMETRY", "errors+usage").strip().lower()
    return v if v in LEVELS else "off"


def install_id(env=os.environ) -> str:
    """Random-looking, stable, not reversible: an HMAC of a fixed label with the installation's secret salt.
    ``TELEMETRY_ID`` overrides it (set a new value to reset the identity)."""
    if env.get("TELEMETRY_ID"):
        return hashlib.sha256(env["TELEMETRY_ID"].encode()).hexdigest()[:16]
    from ..privacy import _salt
    return hmac.new(_salt(), b"occultera-telemetry-v1", hashlib.sha256).hexdigest()[:16]


def install_kind(env=os.environ) -> str:
    k = env.get("OCC_INSTALL", "").strip().lower()
    if k in ("helm", "kustomize", "compose", "docker"):
        return k
    return "kubernetes" if env.get("KUBERNETES_SERVICE_HOST") else "other"


def _base(kind: str) -> dict:
    return {"schema": SCHEMA, "kind": kind, "app": __version__, "install": install_id(), "deploy": install_kind(),
            "python": platform.python_version(), "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}


def frames(exc: BaseException) -> list[str]:
    """``module:function`` for the frames inside the application, innermost last. No paths, no line text."""
    out = []
    for fs in traceback.extract_tb(exc.__traceback__):
        f = fs.filename.replace("\\", "/")
        i = f.rfind("/app/")
        if i < 0:
            continue
        mod = f[i + 1:].removesuffix(".py").replace("/", ".")
        out.append(f"{mod}:{fs.name}")
    return out[-MAX_FRAMES:]


def fingerprint(exc_type: str, fr: list[str]) -> str:
    return hashlib.sha256((exc_type + "|" + "|".join(fr[-5:])).encode()).hexdigest()[:16]


def error_event(exc: BaseException, where: str = "") -> dict:
    from ..errors import classify
    fr = frames(exc)
    t = type(exc).__name__
    return {**_base("error"), "exception": t, "category": classify(exc), "frames": fr,
            "where": where[:60] if where.replace(".", "").replace("_", "").isalnum() else "",
            "fingerprint": fingerprint(t, fr)}


def usage_event(features: dict[str, bool], environments: int, wazuh: list[str], llm: str) -> dict:
    return {**_base("usage"), "environments": int(environments),
            "wazuh": sorted({str(v)[:16] for v in wazuh if v})[:10],
            "llm": llm if llm in ("anthropic", "openai", "mock", "none") else "other",
            "features": {k: bool(v) for k, v in sorted(features.items())}}


ALLOWED = {
    "error": {"schema", "kind", "app", "install", "deploy", "python", "ts", "exception", "category", "frames",
              "where", "fingerprint"},
    "usage": {"schema", "kind", "app", "install", "deploy", "python", "ts", "environments", "wazuh", "llm",
              "features"},
}


def check(ev: dict) -> dict:
    """Last line of defence: an event with an unexpected key is not sent."""
    extra = set(ev) - ALLOWED.get(ev.get("kind", ""), set())
    if extra:
        raise ValueError(f"telemetry event has unexpected keys: {sorted(extra)}")
    return ev


def preview(rt: Any) -> dict[str, Any]:
    """What would be sent now (the About page shows this)."""
    try:
        raise RuntimeError("example")
    except RuntimeError as e:
        err = error_event(e, "example")
    return {"level": level(), "error_example": err, "usage": usage_event(*features_of(rt), wazuh=[], llm=_llm(rt))}


def _llm(rt: Any) -> str:
    try:
        return str(rt.settings.llm.provider)
    except Exception:  # noqa: BLE001
        return "other"


def features_of(rt: Any) -> tuple[dict[str, bool], int]:
    envs = list(getattr(rt, "envs", {}).values())

    def any_(f) -> bool:
        try:
            return any(f(e) for e in envs)
        except Exception:  # noqa: BLE001
            return False
    from ..mcp import token as mcp_token
    feats = {
        "mcp": bool(mcp_token()),
        "prometheus": any_(lambda e: "prometheus" in (e.sources or {})),
        "loki": any_(lambda e: "loki" in (e.sources or {})),
        "kubernetes": any_(lambda e: "kubernetes" in (e.sources or {})),
        "masking": any_(lambda e: getattr(e.env.privacy, "mode", "off") != "off"),
        "rule_deploy": any_(lambda e: bool(getattr(e.env.rule_deploy, "enabled", False))),
        "sso": bool(os.environ.get("AUTH_DISABLED", "").lower() in ("1", "true", "yes")
                    and os.environ.get("USER_HEADER")),
    }
    return feats, len(envs)
