# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Daily data collection: deterministic queries → compact summary dict.

The LLM receives this summary, not raw alerts. Each section catches its own
errors; a failed section shows up in the report as a blind spot instead of
aborting the run.
"""
from __future__ import annotations

from .core import (
    Collector as Collector,
)
from .extras import (
    ExtrasMixin as ExtrasMixin,
)
from .health import (
    HealthMixin as HealthMixin,
)
from .util import (
    _b as _b,
)
from .util import (
    _int as _int,
)
from .util import (
    _parse as _parse,
)
from .util import (
    accept_flags as accept_flags,
)
from .util import (
    health_status as health_status,
)
from .util import (
    iso as iso,
)
from .util import (
    rng as rng,
)
