# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The watch: rule-based alerts between AI rounds.

Every few minutes the alerts of the last interval are checked against **local rules** — no model is
involved, so an urgent situation is announced within minutes and costs nothing:

1. ``level``            any alert at or above ``critical_level``
2. ``rules``/``groups`` the environment's watched rule ids; watched groups at or above ``group_min_level``
3. ``active_response``  Wazuh took an automatic action
4. ``brute_force``      a successful login from a source that failed ``brute_failures`` times before it
5. ``spike``            alerts at ``spike_min_level`` and above, outside the scan groups, reach ``spike_factor`` ×
                        their 7-day average — named by the rules behind them; a burst the same rules already
                        produced in the last 7 days is kept silent as *recurring*
6. ``agents``           agents that stopped reporting
7. ``egress``           a workload sends ``egress_factor`` × its 7-day average out of its pods (and at least
                        ``egress_min_mb``) — read from Prometheus (cAdvisor), off by default. It sees volume, not
                        content: a possible data leak, a backup or a sync job look the same, so a transfer the same
                        workload already made in the last 7 days is kept silent as *recurring*
8. ``prom_alerts``      the clusters' own Prometheus started firing an alert of a selected severity (default
                        critical); off by default. Alerts already firing for more than two hours stay silent

Events are then *sorted out* (muted keys, known noise from the knowledge base, the repeat window),
*announced* at once on the selected channels as "rule-based alert — not reviewed by AI" (held back
during quiet hours unless critical) and *kept* in ``<prefix>-events``. The next scheduled AI round gets
all of them in one call and returns a verdict per event plus tuning suggestions, which an administrator
can accept in the settings page — that is the only way the model influences the watch.
"""
from __future__ import annotations

from .scan import (
    Scanner as Scanner,
)
from .service import (
    WatchMixin as WatchMixin,
)
from .util import (
    AUTH_FAIL as AUTH_FAIL,
)
from .util import (
    AUTH_OK as AUTH_OK,
)
from .util import (
    MAX_HITS as MAX_HITS,
)
from .util import (
    MAX_WINDOW_MINUTES as MAX_WINDOW_MINUTES,
)
from .util import (
    NAME_OK as NAME_OK,
)
from .util import (
    PENDING as PENDING,
)
from .util import (
    POD_SUFFIX as POD_SUFFIX,
)
from .util import (
    PROM_FRESH as PROM_FRESH,
)
from .util import (
    VERDICTS as VERDICTS,
)
from .util import (
    WORKLOAD_RX as WORKLOAD_RX,
)
from .util import (
    _agg_ts as _agg_ts,
)
from .util import (
    _event as _event,
)
from .util import (
    _get as _get,
)
from .util import (
    _groups as _groups,
)
from .util import (
    _level as _level,
)
from .util import (
    _num as _num,
)
from .util import (
    _rx as _rx,
)
from .util import (
    channels_for as channels_for,
)
from .util import (
    classify as classify,
)
from .util import (
    compact_for_ai as compact_for_ai,
)
from .util import (
    event_line as event_line,
)
from .util import (
    fields as fields,
)
from .util import (
    fmt_bytes as fmt_bytes,
)
from .util import (
    known_noise as known_noise,
)
from .util import (
    muted as muted,
)
from .util import (
    normalize_verdicts as normalize_verdicts,
)
from .util import (
    quiet_now as quiet_now,
)
