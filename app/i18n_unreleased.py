# SPDX-License-Identifier: AGPL-3.0-only
"""Messages added after 0.15.0 (unreleased)."""

EN = {
    "setup.title": "Finish setting up",
    "setup.first_report": "Run the first check (Run check now)",
    "setup.schedule": "Schedule the AI round (Settings → AI round)",
    "setup.channel": "Configure a notification channel (Teams, Telegram, e-mail …)",
    "setup.watch": "Switch on the watch for urgent alerts (Settings → Watch)",
    "setup.privacy": "Keep personal-data masking on (privacy.mode: mask)",
    "setup.note": "This list disappears when every step is done.",
    "bk.file": "Backup file (.occbak)",
    "au.month": "Month",
    "rep.status": "Status",
    "mask.yaml_only": "⚙ = set in the environment's YAML (privacy.kinds, privacy.ips); shown as it is in force.",
    "chk.proxy": "Reverse proxy",
    "chk.proxy_bad": "requests arrive through a proxy ({peer}) but TRUSTED_PROXIES is empty: every user and MCP "
                     "client shares one rate limit and one lock-out, and the audit log records the proxy. "
                     "Set FORWARDED_ALLOW_IPS (or TRUSTED_PROXIES) to the proxy's address or CIDR.",
    "chk.proxy_ok": "client address taken from X-Forwarded-For via a trusted proxy",
}
TR = {
    "setup.title": "Kurulumu tamamlayın",
    "setup.first_report": "İlk kontrolü çalıştırın (Şimdi kontrol et)",
    "setup.schedule": "Yapay zekâ turunu zamanlayın (Ayarlar → Yapay zekâ turu)",
    "setup.channel": "Bir bildirim kanalı tanımlayın (Teams, Telegram, e-posta …)",
    "setup.watch": "Acil alarmlar için nöbeti açın (Ayarlar → Nöbet)",
    "setup.privacy": "Kişisel veri maskelemesini açık tutun (privacy.mode: mask)",
    "setup.note": "Tüm adımlar tamamlanınca bu liste kaybolur.",
    "bk.file": "Yedek dosyası (.occbak)",
    "au.month": "Ay",
    "rep.status": "Durum",
    "mask.yaml_only": "⚙ = ortamın YAML'ında ayarlanır (privacy.kinds, privacy.ips); yürürlükteki hâli gösterilir.",
    "chk.proxy": "Reverse proxy",
    "chk.proxy_bad": "istekler bir proxy üzerinden geliyor ({peer}) ama TRUSTED_PROXIES boş: tüm kullanıcılar ve MCP "
                     "istemcileri tek bir hız sınırını ve tek bir kilidi paylaşır, audit kaydına proxy yazılır. "
                     "FORWARDED_ALLOW_IPS'e (ya da TRUSTED_PROXIES'e) proxy'nin adresini ya da CIDR'ını yazın.",
    "chk.proxy_ok": "istemci adresi güvenilen proxy üzerinden X-Forwarded-For'dan alınıyor",
}
ES = {
    "setup.title": "Termina la configuración",
    "setup.first_report": "Ejecuta la primera revisión",
    "setup.schedule": "Programa la ronda de IA (Ajustes → Ronda de IA)",
    "setup.channel": "Configura un canal de notificación (Teams, Telegram, correo …)",
    "setup.watch": "Activa la guardia para alertas urgentes (Ajustes → Guardia)",
    "setup.privacy": "Mantén el enmascaramiento de datos personales (privacy.mode: mask)",
    "setup.note": "Esta lista desaparece cuando todos los pasos están hechos.",
    "bk.file": "Archivo de copia (.occbak)",
    "au.month": "Mes",
    "rep.status": "Estado",
    "mask.yaml_only": "⚙ = se ajusta en el YAML del entorno (privacy.kinds, privacy.ips); se muestra como está en vigor.",
    "chk.proxy": "Proxy inverso",
    "chk.proxy_bad": "las peticiones llegan por un proxy ({peer}) pero TRUSTED_PROXIES está vacío: todos los usuarios "
                     "y clientes MCP comparten un límite y un bloqueo, y la auditoría registra el proxy. "
                     "Pon en FORWARDED_ALLOW_IPS (o TRUSTED_PROXIES) la dirección o CIDR del proxy.",
    "chk.proxy_ok": "dirección del cliente tomada de X-Forwarded-For a través de un proxy de confianza",
}
DE = {
    "setup.title": "Einrichtung abschließen",
    "setup.first_report": "Ersten Check ausführen",
    "setup.schedule": "KI-Runde planen (Einstellungen → KI-Runde)",
    "setup.channel": "Benachrichtigungskanal einrichten (Teams, Telegram, E-Mail …)",
    "setup.watch": "Wache für dringende Alarme einschalten (Einstellungen → Wache)",
    "setup.privacy": "Maskierung personenbezogener Daten aktiv lassen (privacy.mode: mask)",
    "setup.note": "Diese Liste verschwindet, wenn alle Schritte erledigt sind.",
    "bk.file": "Sicherungsdatei (.occbak)",
    "au.month": "Monat",
    "rep.status": "Status",
    "mask.yaml_only": "⚙ = wird im YAML der Umgebung gesetzt (privacy.kinds, privacy.ips); angezeigt wie in Kraft.",
    "chk.proxy": "Reverse Proxy",
    "chk.proxy_bad": "Anfragen kommen über einen Proxy ({peer}), aber TRUSTED_PROXIES ist leer: alle Benutzer und "
                     "MCP-Clients teilen sich ein Limit und eine Sperre, und das Audit-Log enthält den Proxy. "
                     "Tragen Sie die Adresse oder das CIDR des Proxys in FORWARDED_ALLOW_IPS (oder TRUSTED_PROXIES) ein.",
    "chk.proxy_ok": "Client-Adresse aus X-Forwarded-For über einen vertrauenswürdigen Proxy",
}

EXTRA = {"en": EN, "tr": TR, "es": ES, "de": DE}
