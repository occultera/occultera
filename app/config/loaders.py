# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Where the settings come from: environments.yaml, or the variables of a single-environment setup."""
from __future__ import annotations

import os
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from ..backupcfg import backup_from_env
from .base import LANGUAGES, _bool, _expand
from .core import Settings


def llm_from_env() -> dict:
    """LLM settings from LLM_* variables (single-environment mode)."""
    E = os.environ.get
    llm: dict = {"provider": E("LLM_PROVIDER", "anthropic"), "model": E("LLM_MODEL", ""),
                 "api_key": E("LLM_API_KEY", ""), "base_url": E("LLM_BASE_URL") or None}
    if E("LLM_MAX_TOKENS"):
        llm["max_tokens"] = int(E("LLM_MAX_TOKENS"))
    temp = E("LLM_TEMPERATURE")
    if temp is not None and temp.strip() != "":
        llm["temperature"] = None if temp.strip().lower() in ("none", "default", "off") else float(temp)
    if E("LLM_TOKEN_PARAM"):
        llm["token_param"] = E("LLM_TOKEN_PARAM")
    extra: dict = {}
    if E("LLM_REASONING_EFFORT"):
        extra["reasoning_effort"] = E("LLM_REASONING_EFFORT")
    if E("LLM_EXTRA_BODY"):
        import json
        extra.update(json.loads(E("LLM_EXTRA_BODY")))
    if extra:
        llm["extra_body"] = extra
    if E("LLM_MAX_RETRIES"):
        llm["max_retries"] = int(E("LLM_MAX_RETRIES"))
    if E("LLM_MAX_TOOL_STEPS"):
        llm["max_tool_steps"] = int(E("LLM_MAX_TOOL_STEPS"))
    return llm


def _env(name: str, default: str | None = None) -> str | None:
    """Environment variable; an empty value counts as unset."""
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def notify_from_env() -> dict:
    """NOTIFY_* / SMTP_* / TELEGRAM_* / TEAMS_* variables (also used when the YAML has no notify block)."""
    E = _env
    return {
        "enabled": _bool(E("NOTIFY_ENABLED"), True),
        "on_run_error": _bool(E("NOTIFY_ON_RUN_ERROR"), False),
        "on_run_summary": _bool(E("NOTIFY_ON_RUN_SUMMARY"), False),
        "on_rule_deploy": _bool(E("NOTIFY_ON_RULE_DEPLOY"), True),
        "on_liveness": _bool(E("NOTIFY_ON_LIVENESS"), True),
        "on_pending": _bool(E("NOTIFY_ON_PENDING"), True),
        "pending_days": int(E("NOTIFY_PENDING_DAYS", "7")),
        "pending_time": E("NOTIFY_PENDING_TIME", "09:30"),
        "repeat_hours": int(E("NOTIFY_REPEAT_HOURS", "24")),
        "ui_url": E("NOTIFY_UI_URL", ""),
        "email": {"host": E("SMTP_HOST", ""), "port": int(E("SMTP_PORT", "587")), "security": E("SMTP_SECURITY", "starttls"),
                  "username": E("SMTP_USER", ""), "password": E("SMTP_PASSWORD", ""), "sender": E("SMTP_FROM", ""),
                  "to": [x.strip() for x in E("SMTP_TO", "").split(",") if x.strip()],
                  "verify_tls": _bool(E("SMTP_VERIFY_TLS"), True)},
        "telegram": {"bot_token": E("TELEGRAM_BOT_TOKEN", ""), "chat_id": E("TELEGRAM_CHAT_ID", "")},
        "teams": {"webhook_url": E("TEAMS_WEBHOOK_URL", "")},
        "slack": {"webhook_url": E("SLACK_WEBHOOK_URL", "")},
        "discord": {"webhook_url": E("DISCORD_WEBHOOK_URL", "")},
        "webhook": {"url": E("WEBHOOK_URL", ""), "token": E("WEBHOOK_TOKEN", "")},
        "ntfy": {"topic": E("NTFY_TOPIC", ""), "token": E("NTFY_TOKEN", "")},
    }


def settings_from_env() -> dict:
    """Single-environment configuration from plain environment variables (no YAML needed)."""
    E = os.environ.get
    if not E("WAZUH_INDEXER_URL"):
        want = E("WDT_CONFIG") or "config/environments.yaml"
        raise FileNotFoundError(
            f"no configuration: {want} does not exist and WAZUH_INDEXER_URL is not set. "
            f"For a real Wazuh, create the YAML file or set WAZUH_INDEXER_URL. For the demo set WDT_DEMO=true "
            f"(currently WDT_DEMO={E('WDT_DEMO', '')!r}; if .env sets a variable twice, the last line wins — "
            f"or simply: cp .env.demo .env)")
    verify = _bool(E("WAZUH_VERIFY_TLS"), True)
    env: dict = {
        "id": E("WAZUH_ENV_ID", "default"), "name": E("WAZUH_ENV_NAME", "Wazuh"),
        "indexer": {"url": E("WAZUH_INDEXER_URL"), "username": E("WAZUH_INDEXER_USER", ""),
                    "password": E("WAZUH_INDEXER_PASSWORD", ""), "verify_tls": verify, "ca_file": E("WAZUH_CA_FILE") or None},
        "schedule": {"enabled": _bool(E("SCHEDULE_ENABLED"), True), "time": E("SCHEDULE_TIME", "07:30").split(",")[0],
                     "times": [x.strip() for x in E("SCHEDULE_TIME", "").split(",") if x.strip()] if "," in E("SCHEDULE_TIME", "") else [],
                     "days": [d for d in E("SCHEDULE_DAYS", "mon,tue,wed,thu,fri").split(",") if d]},
        "high_level": int(E("HIGH_LEVEL", "7")),
        "window_min_hours": int(E("WINDOW_MIN_HOURS", "24")),
        "redact": _bool(E("REDACT"), False),
        "privacy": {"mode": E("PRIVACY_MODE") or "mask",
                    "ips": E("PRIVACY_IPS", "keep"), "detect": _bool(E("PRIVACY_DETECT"), True)},
    }
    if E("WAZUH_API_URL"):
        env["api"] = {"url": E("WAZUH_API_URL"), "username": E("WAZUH_API_USER", ""),
                      "password": E("WAZUH_API_PASSWORD", ""), "verify_tls": verify, "ca_file": E("WAZUH_CA_FILE") or None}
    if E("WAZUH_ALERTS_INDEX"):
        env["alerts_index"] = E("WAZUH_ALERTS_INDEX")
    if E("WAZUH_VERSION"):
        env["wazuh_version"] = E("WAZUH_VERSION")
    if E("LIVENESS_INTERVAL_MINUTES") or E("LIVENESS_ENABLED"):
        env["liveness"] = {"enabled": _bool(E("LIVENESS_ENABLED"), True),
                           "interval_minutes": int(E("LIVENESS_INTERVAL_MINUTES") or 10)}
    if E("MAIL_MAX_PER_HOUR"):
        env["mail"] = {"alert_level": int(E("MAIL_ALERT_LEVEL") or 7), "max_per_hour": int(E("MAIL_MAX_PER_HOUR"))}
    if E("HEALTH_ACCEPT"):
        env["health_accept"] = [x.strip() for x in E("HEALTH_ACCEPT", "").split(",") if x.strip()]
    if E("IGNORE_AGENTS"):
        env["ignore_agents"] = [x.strip() for x in E("IGNORE_AGENTS", "").split(",") if x.strip()]
    if E("INVENTORY"):
        env["inventory"] = [x.strip() for x in E("INVENTORY", "").split(",") if x.strip()]
    if _bool(E("RULE_DEPLOY_ENABLED"), False):
        env["rule_deploy"] = {"enabled": True, "username": E("WAZUH_DEPLOY_USER", ""),
                              "password": E("WAZUH_DEPLOY_PASSWORD", ""),
                              "file": E("RULE_DEPLOY_FILE") or "wdt_rules.xml",
                              "id_min": int(E("RULE_DEPLOY_ID_MIN") or 100000),
                              "id_max": int(E("RULE_DEPLOY_ID_MAX") or 119999),
                              "require_tests": _bool(E("RULE_DEPLOY_REQUIRE_TESTS"), False),
                              "allow_inconclusive": _bool(E("RULE_DEPLOY_ALLOW_INCONCLUSIVE"), False)}
    return {
        "app": {"timezone": E("TZ", "UTC"), "language": E("APP_LANGUAGE", "en")},
        "llm": llm_from_env(),
        "notify": notify_from_env(),
        "backup": backup_from_env(),
        "environments": [env],
    }


def config_path(demo: bool) -> str:
    """Configuration file to read: ``WDT_CONFIG`` when set, otherwise the demo or the normal YAML file.

    Demo mode must never require a configuration file. The container image sets ``WDT_CONFIG`` globally, so
    ``WDT_DEMO=true`` alone would otherwise look for ``/app/config/environments.yaml`` and refuse to start.
    """
    want = os.environ.get("WDT_CONFIG") or ("config/demo.yaml" if demo else "config/environments.yaml")
    if demo and not Path(want).is_file():
        want = "config/demo.yaml"
    return want


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    path = Path(path or os.environ.get("WDT_CONFIG", "config/environments.yaml"))
    if path.exists():
        raw = _expand(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        if "llm" not in raw:  # no llm block → LLM_* variables
            raw["llm"] = llm_from_env()
        if "notify" not in raw:  # no notify block → NOTIFY_*/SMTP_*/TELEGRAM_*/TEAMS_*
            raw["notify"] = notify_from_env()
        if "backup" not in raw:  # no backup block → BACKUP_* variables
            raw["backup"] = backup_from_env()
        app_cfg = dict(raw.get("app") or {})   # app.language / app.timezone fall back to APP_LANGUAGE / TZ
        if "language" not in app_cfg and os.environ.get("APP_LANGUAGE") in LANGUAGES:
            app_cfg["language"] = os.environ["APP_LANGUAGE"]
        if "timezone" not in app_cfg and os.environ.get("TZ"):
            try:
                ZoneInfo(os.environ["TZ"])
                app_cfg["timezone"] = os.environ["TZ"]
            except (ZoneInfoNotFoundError, ValueError):
                pass
        raw["app"] = app_cfg
        base = path.parent
    else:
        raw = settings_from_env()
        base = path.parent if path.parent.exists() else Path(".")
    s = Settings(**raw, base_dir=base)
    ids = [e.id for e in s.environments]
    if len(ids) != len(set(ids)):
        raise ValueError("environment ids must be unique")
    if not ids:
        raise ValueError("no environments configured")
    return s
