# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Error reports and anonymous usage data (docs/telemetry.md).

On by default, switched off with ``TELEMETRY=off`` (``errors`` sends crash reports only, ``errors+usage`` also a
weekly usage ping). Only *structured* data leaves the installation: exception class, ``module:function`` frames
inside ``app/``, an error category, versions and yes/no feature flags. Never an exception message, an alert, a log
line, an IP address, a host or user name, a model name or a key. The public demo never sends anything.
"""
from .schema import error_event, install_id, level, preview, usage_event  # noqa: F401
from .send import Telemetry, TelemetryHandler  # noqa: F401
