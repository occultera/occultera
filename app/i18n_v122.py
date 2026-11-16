# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Messages added or changed in 0.12.2 (watch: outbound transfer trigger; About page card)."""
from __future__ import annotations

EN: dict[str, str] = {
    "watch.trigger.egress": "Unusual outbound transfer (possible data leak)",
    "watch.ev.egress": "{wl} sent {size} out in {m} min — {x}× its 7-day average ({avg})",
    "watch.ev.egress_new": "{wl} sent {size} out in {m} min — nothing in the previous 7 days",
    "watch.silent.recurring_egress": "recurring transfer: this workload sent as much in the last 7 days (backup, sync)",
    "set.w.egress_factor": "× the workload's 7-day average",
    "set.w.egress_min_mb": "and at least (MB)",
    "set.w.egress_exclude": "Leave out these namespaces",
    "set.w.egress_help": "Reads outbound bytes per workload from Prometheus (cAdvisor). Volume only, never content; "
                         "traffic to other pods counts too. Empty = the default list; - = leave out nothing.",
    "set.w.egress_no_prom": "Needs a Prometheus source (sources.prometheus) for this environment.",
}

TR: dict[str, str] = {
    "watch.trigger.egress": "Olağan dışı dışarı aktarım (olası veri sızıntısı)",
    "watch.ev.egress": "{wl} {m} dk içinde {size} dışarı gönderdi — 7 günlük ortalamasının ({avg}) {x} katı",
    "watch.ev.egress_new": "{wl} {m} dk içinde {size} dışarı gönderdi — önceki 7 günde hiç göndermemişti",
    "watch.silent.recurring_egress": "tekrarlayan aktarım: bu iş yükü son 7 günde de bu kadar gönderdi (yedek, eşitleme)",
    "set.w.egress_factor": "× iş yükünün 7 günlük ortalaması",
    "set.w.egress_min_mb": "ve en az (MB)",
    "set.w.egress_exclude": "Bu namespace'leri sayma",
    "set.w.egress_help": "İş yükü başına dışarı giden baytı Prometheus'tan (cAdvisor) okur. Yalnız hacme bakar, "
                         "içeriğe asla; diğer pod'lara giden trafik de sayılır. Boş = varsayılan liste; - = hiçbirini çıkarma.",
    "set.w.egress_no_prom": "Bu ortam için bir Prometheus kaynağı (sources.prometheus) gerekir.",
}

ES: dict[str, str] = {
    "watch.trigger.egress": "Transferencia saliente inusual (posible fuga de datos)",
    "watch.ev.egress": "{wl} envió {size} en {m} min — {x}× su media de 7 días ({avg})",
    "watch.ev.egress_new": "{wl} envió {size} en {m} min — nada en los 7 días anteriores",
    "watch.silent.recurring_egress": "transferencia recurrente: esta carga envió lo mismo en los últimos 7 días (copia, sincronización)",
    "set.w.egress_factor": "× la media de 7 días de la carga",
    "set.w.egress_min_mb": "y al menos (MB)",
    "set.w.egress_exclude": "Excluir estos namespaces",
    "set.w.egress_help": "Lee los bytes salientes por carga de trabajo desde Prometheus (cAdvisor). Solo volumen, nunca "
                         "contenido; el tráfico a otros pods también cuenta. Vacío = lista por defecto; - = no excluir nada.",
    "set.w.egress_no_prom": "Necesita una fuente Prometheus (sources.prometheus) para este entorno.",
}

DE: dict[str, str] = {
    "watch.trigger.egress": "Ungewöhnliche ausgehende Übertragung (mögliches Datenleck)",
    "watch.ev.egress": "{wl} sendete {size} in {m} min — das {x}-Fache seines 7-Tage-Durchschnitts ({avg})",
    "watch.ev.egress_new": "{wl} sendete {size} in {m} min — nichts in den 7 Tagen davor",
    "watch.silent.recurring_egress": "wiederkehrende Übertragung: diese Workload sendete in den letzten 7 Tagen ebenso viel (Backup, Sync)",
    "set.w.egress_factor": "× der 7-Tage-Durchschnitt der Workload",
    "set.w.egress_min_mb": "und mindestens (MB)",
    "set.w.egress_exclude": "Diese Namespaces auslassen",
    "set.w.egress_help": "Liest ausgehende Bytes pro Workload aus Prometheus (cAdvisor). Nur Volumen, nie Inhalt; "
                         "Verkehr zu anderen Pods zählt mit. Leer = Standardliste; - = nichts auslassen.",
    "set.w.egress_no_prom": "Benötigt eine Prometheus-Quelle (sources.prometheus) für diese Umgebung.",
}

EXTRA = {"en": EN, "tr": TR, "es": ES, "de": DE}
