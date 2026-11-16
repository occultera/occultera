# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Messages added in 0.14.0 (the clusters' own Prometheus alerts: pulse panel, AI explanation, watch)."""
from __future__ import annotations

EN: dict[str, str] = {
    "watch.trigger.prom_alerts": "Cluster alert (Prometheus)",
    "watch.ev.promalert": "[{cluster}] {alert} ({sev}) ×{n} — {ns}: {summary}",
    "watch.silent.still_firing": "already firing for more than two hours when first seen",
    "set.w.prom_sev": "severities",
    "set.w.prom_help": "Alerts the clusters' own Prometheus fires (Alertmanager rules). New ones are announced once; Watchdog is ignored.",
    "pl.k.alerts": "Firing alerts",
    "pl.alert_sub": "{c} critical · {w} warning",
    "pl.alerts": "Alerts this cluster's Prometheus is firing",
    "pl.alerts_none": "Nothing is firing (the Watchdog heartbeat is not counted).",
    "pl.alerts_note": "The cluster's own alerting rules (KubePodCrashLooping, TargetDown, disk filling up …), grouped by alert and severity. The explanation is written by the AI from these alerts and a few PromQL checks; it goes through the environment's masking.",
    "pl.explain": "Explain with AI",
    "pl.explain_busy": "The AI is reading the alerts…",
    "pl.explained_at": "Explanation from {at}",
    "pl.ai_off": "without AI (no model available)",
    "pl.c.alert": "Alert",
    "pl.c.sev": "Severity",
    "pl.c.ns": "Namespaces",
    "pl.c.since": "Since",
    "pl.c.summary": "Summary",
}

TR: dict[str, str] = {
    "watch.trigger.prom_alerts": "Küme alarmı (Prometheus)",
    "watch.ev.promalert": "[{cluster}] {alert} ({sev}) ×{n} — {ns}: {summary}",
    "watch.silent.still_firing": "ilk görüldüğünde iki saatten uzun süredir ateşleniyordu",
    "set.w.prom_sev": "önem dereceleri",
    "set.w.prom_help": "Kümelerin kendi Prometheus'unun ateşlediği alarmlar (Alertmanager kuralları). Yenileri bir kez bildirilir; Watchdog sayılmaz.",
    "pl.k.alerts": "Ateşlenen alarmlar",
    "pl.alert_sub": "{c} kritik · {w} uyarı",
    "pl.alerts": "Bu kümenin Prometheus'unun ateşlediği alarmlar",
    "pl.alerts_none": "Ateşlenen alarm yok (Watchdog nabzı sayılmaz).",
    "pl.alerts_note": "Kümenin kendi alarm kuralları (KubePodCrashLooping, TargetDown, disk doluyor …), alarm ve önem derecesine göre gruplu. Yorumu yapay zekâ bu alarmlardan ve birkaç PromQL kontrolünden yazar; ortamın maskelemesinden geçer.",
    "pl.explain": "AI ile yorumla",
    "pl.explain_busy": "Yapay zekâ alarmları okuyor…",
    "pl.explained_at": "{at} tarihli yorum",
    "pl.ai_off": "yapay zekâsız (model yok)",
    "pl.c.alert": "Alarm",
    "pl.c.sev": "Önem",
    "pl.c.ns": "Namespace'ler",
    "pl.c.since": "Başlangıç",
    "pl.c.summary": "Özet",
}

ES: dict[str, str] = {
    "watch.trigger.prom_alerts": "Alerta del clúster (Prometheus)",
    "watch.ev.promalert": "[{cluster}] {alert} ({sev}) ×{n} — {ns}: {summary}",
    "watch.silent.still_firing": "ya activa desde hace más de dos horas al verla por primera vez",
    "set.w.prom_sev": "severidades",
    "set.w.prom_help": "Alertas que dispara el propio Prometheus de los clústeres (reglas de Alertmanager). Las nuevas se avisan una vez; Watchdog se ignora.",
    "pl.k.alerts": "Alertas activas",
    "pl.alert_sub": "{c} críticas · {w} avisos",
    "pl.alerts": "Alertas que dispara el Prometheus de este clúster",
    "pl.alerts_none": "No hay alertas activas (el latido Watchdog no cuenta).",
    "pl.alerts_note": "Las reglas de alerta del propio clúster, agrupadas por alerta y severidad. La IA escribe la explicación a partir de estas alertas y algunas consultas PromQL; pasa por el enmascarado del entorno.",
    "pl.explain": "Explicar con IA",
    "pl.explain_busy": "La IA está leyendo las alertas…",
    "pl.explained_at": "Explicación del {at}",
    "pl.ai_off": "sin IA (no hay modelo)",
    "pl.c.alert": "Alerta",
    "pl.c.sev": "Severidad",
    "pl.c.ns": "Namespaces",
    "pl.c.since": "Desde",
    "pl.c.summary": "Resumen",
}

DE: dict[str, str] = {
    "watch.trigger.prom_alerts": "Cluster-Alarm (Prometheus)",
    "watch.ev.promalert": "[{cluster}] {alert} ({sev}) ×{n} — {ns}: {summary}",
    "watch.silent.still_firing": "beim ersten Sehen schon länger als zwei Stunden aktiv",
    "set.w.prom_sev": "Schweregrade",
    "set.w.prom_help": "Alarme, die das Prometheus der Cluster selbst auslöst (Alertmanager-Regeln). Neue werden einmal gemeldet; Watchdog wird ignoriert.",
    "pl.k.alerts": "Aktive Alarme",
    "pl.alert_sub": "{c} kritisch · {w} Warnung",
    "pl.alerts": "Alarme, die das Prometheus dieses Clusters auslöst",
    "pl.alerts_none": "Nichts aktiv (der Watchdog-Herzschlag zählt nicht).",
    "pl.alerts_note": "Die eigenen Alarmregeln des Clusters, gruppiert nach Alarm und Schweregrad. Die KI schreibt die Erklärung aus diesen Alarmen und einigen PromQL-Abfragen; sie läuft durch die Maskierung der Umgebung.",
    "pl.explain": "Mit KI erklären",
    "pl.explain_busy": "Die KI liest die Alarme…",
    "pl.explained_at": "Erklärung vom {at}",
    "pl.ai_off": "ohne KI (kein Modell)",
    "pl.c.alert": "Alarm",
    "pl.c.sev": "Schwere",
    "pl.c.ns": "Namespaces",
    "pl.c.since": "Seit",
    "pl.c.summary": "Zusammenfassung",
}

EXTRA = {"en": EN, "tr": TR, "es": ES, "de": DE}
