# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Configuration: config/environments.yaml (multi-environment) or plain environment
variables (single environment).

``${VAR}`` and ``${VAR:-default}`` inside the YAML are expanded from the process
environment so secrets can live in ``.env`` rather than in the file.
"""
from __future__ import annotations

from .base import (
    _ENV_RE as _ENV_RE,
)
from .base import (
    DAYS as DAYS,
)
from .base import (
    LANGUAGES as LANGUAGES,
)
from .base import (
    _bool as _bool,
)
from .base import (
    _expand as _expand,
)
from .core import (
    AppConfig as AppConfig,
)
from .core import (
    Environment as Environment,
)
from .core import (
    Settings as Settings,
)
from .loaders import (
    _env as _env,
)
from .loaders import (
    config_path as config_path,
)
from .loaders import (
    llm_from_env as llm_from_env,
)
from .loaders import (
    load_settings as load_settings,
)
from .loaders import (
    notify_from_env as notify_from_env,
)
from .loaders import (
    settings_from_env as settings_from_env,
)
from .models import (
    _HM as _HM,
)
from .models import (
    Endpoint as Endpoint,
)
from .models import (
    IncidentCfg as IncidentCfg,
)
from .models import (
    JiraCfg as JiraCfg,
)
from .models import (
    KubernetesSource as KubernetesSource,
)
from .models import (
    LivenessCfg as LivenessCfg,
)
from .models import (
    LLMConfig as LLMConfig,
)
from .models import (
    MailCfg as MailCfg,
)
from .models import (
    PrivacyCfg as PrivacyCfg,
)
from .models import (
    PromoteCfg as PromoteCfg,
)
from .models import (
    QueryLimitsCfg as QueryLimitsCfg,
)
from .models import (
    RuleDeployCfg as RuleDeployCfg,
)
from .models import (
    Schedule as Schedule,
)
from .models import (
    SourceEndpoint as SourceEndpoint,
)
from .models import (
    SourcesCfg as SourcesCfg,
)
from .models import (
    VulnSlaCfg as VulnSlaCfg,
)
from .models import (
    ZammadCfg as ZammadCfg,
)
