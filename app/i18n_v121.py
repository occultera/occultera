# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Messages added or changed in 0.12.1 (the spike trigger names the rules behind a burst)."""
from __future__ import annotations

EN: dict[str, str] = {
    "watch.ev.spike": "{n} alerts at level {lvl}+ in {m} min — {x}× the 7-day average ({avg}). Mostly: {rules}",
    "watch.ev.spike_new": "{n} alerts at level {lvl}+ in {m} min — none in the previous 7 days. Mostly: {rules}",
    "watch.silent.recurring": "recurring burst: the same rules did this in the last 7 days",
    "set.w.spike_factor": "× the 7-day average",
    "set.w.spike_min_level": "count alerts from level",
    "set.w.spike_exclude": "Leave out these groups",
    "set.w.spike_exclude_help": "Scheduled scans come in bursts by design. Empty = the default list; - = leave out nothing.",
}

TR: dict[str, str] = {
    "watch.ev.spike": "{m} dk içinde seviye {lvl}+ {n} alarm — 7 günlük ortalamanın ({avg}) {x} katı. Çoğu: {rules}",
    "watch.ev.spike_new": "{m} dk içinde seviye {lvl}+ {n} alarm — önceki 7 günde hiç yoktu. Çoğu: {rules}",
    "watch.silent.recurring": "tekrarlayan patlama: aynı kurallar son 7 günde de bunu yaptı",
    "set.w.spike_factor": "× 7 günlük ortalama",
    "set.w.spike_min_level": "şu seviyeden itibaren say",
    "set.w.spike_exclude": "Bu grupları sayma",
    "set.w.spike_exclude_help": "Planlı taramalar doğası gereği toplu gelir. Boş = varsayılan liste; - = hiçbirini çıkarma.",
}

ES: dict[str, str] = {
    "watch.ev.spike": "{n} alertas de nivel {lvl}+ en {m} min — {x}× la media de 7 días ({avg}). Sobre todo: {rules}",
    "watch.ev.spike_new": "{n} alertas de nivel {lvl}+ en {m} min — ninguna en los 7 días anteriores. Sobre todo: {rules}",
    "watch.silent.recurring": "ráfaga recurrente: las mismas reglas lo hicieron en los últimos 7 días",
    "set.w.spike_factor": "× la media de 7 días",
    "set.w.spike_min_level": "contar alertas desde el nivel",
    "set.w.spike_exclude": "Excluir estos grupos",
    "set.w.spike_exclude_help": "Los escaneos programados llegan en ráfagas. Vacío = lista por defecto; - = no excluir nada.",
}

DE: dict[str, str] = {
    "watch.ev.spike": "{n} Alarme ab Level {lvl} in {m} min — das {x}-Fache des 7-Tage-Mittels ({avg}). Vor allem: {rules}",
    "watch.ev.spike_new": "{n} Alarme ab Level {lvl} in {m} min — keine in den 7 Tagen davor. Vor allem: {rules}",
    "watch.silent.recurring": "wiederkehrender Schub: dieselben Regeln taten das in den letzten 7 Tagen",
    "set.w.spike_factor": "× das 7-Tage-Mittel",
    "set.w.spike_min_level": "Alarme zählen ab Level",
    "set.w.spike_exclude": "Diese Gruppen auslassen",
    "set.w.spike_exclude_help": "Geplante Scans kommen absichtlich in Schüben. Leer = Standardliste; - = nichts auslassen.",
}

EXTRA = {"en": EN, "tr": TR, "es": ES, "de": DE}
