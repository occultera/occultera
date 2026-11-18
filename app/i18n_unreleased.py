# SPDX-License-Identifier: AGPL-3.0-only
"""Messages added after 0.15.0 (unreleased)."""

EN = {
    "chk.proxy": "Reverse proxy",
    "chk.proxy_bad": "requests arrive through a proxy ({peer}) but TRUSTED_PROXIES is empty: every user and MCP "
                     "client shares one rate limit and one lock-out, and the audit log records the proxy. "
                     "Set FORWARDED_ALLOW_IPS (or TRUSTED_PROXIES) to the proxy's address or CIDR.",
    "chk.proxy_ok": "client address taken from X-Forwarded-For via a trusted proxy",
}
TR = {
    "chk.proxy": "Reverse proxy",
    "chk.proxy_bad": "istekler bir proxy üzerinden geliyor ({peer}) ama TRUSTED_PROXIES boş: tüm kullanıcılar ve MCP "
                     "istemcileri tek bir hız sınırını ve tek bir kilidi paylaşır, audit kaydına proxy yazılır. "
                     "FORWARDED_ALLOW_IPS'e (ya da TRUSTED_PROXIES'e) proxy'nin adresini ya da CIDR'ını yazın.",
    "chk.proxy_ok": "istemci adresi güvenilen proxy üzerinden X-Forwarded-For'dan alınıyor",
}
ES = {
    "chk.proxy": "Proxy inverso",
    "chk.proxy_bad": "las peticiones llegan por un proxy ({peer}) pero TRUSTED_PROXIES está vacío: todos los usuarios "
                     "y clientes MCP comparten un límite y un bloqueo, y la auditoría registra el proxy. "
                     "Pon en FORWARDED_ALLOW_IPS (o TRUSTED_PROXIES) la dirección o CIDR del proxy.",
    "chk.proxy_ok": "dirección del cliente tomada de X-Forwarded-For a través de un proxy de confianza",
}
DE = {
    "chk.proxy": "Reverse Proxy",
    "chk.proxy_bad": "Anfragen kommen über einen Proxy ({peer}), aber TRUSTED_PROXIES ist leer: alle Benutzer und "
                     "MCP-Clients teilen sich ein Limit und eine Sperre, und das Audit-Log enthält den Proxy. "
                     "Tragen Sie die Adresse oder das CIDR des Proxys in FORWARDED_ALLOW_IPS (oder TRUSTED_PROXIES) ein.",
    "chk.proxy_ok": "Client-Adresse aus X-Forwarded-For über einen vertrauenswürdigen Proxy",
}

EXTRA = {"en": EN, "tr": TR, "es": ES, "de": DE}
