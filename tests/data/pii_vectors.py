# SPDX-License-Identifier: AGPL-3.0-only
"""Turkish-first PII test vectors for app.privacy (default profile, ips: keep).

Each vector: (category, log line, value that must / must not survive, expected).
expected = "masked"  -> the value must not appear in the masked text (a miss is a regression)
expected = "kept"    -> the value must survive (a change is a false positive)
expected = "miss"    -> a KNOWN gap: personal data the default profile does not detect (documented in Privacy)
Run `python -m tools.pii_eval` for the table published on the Privacy page.
"""

VECTORS = [
    # e-mail
    ("email", "sshd: Accepted password for ayse.yilmaz@firma.com.tr from 10.1.2.3", "ayse.yilmaz@firma.com.tr", "masked"),
    ("email", 'user="Mehmet.Öz+test@example.org" action=login', "Mehmet.Öz+test@example.org", "masked"),
    ("email", "mail to=<destek@sirket.com.tr> status=sent", "destek@sirket.com.tr", "masked"),
    # phone
    ("phone", "SMS gönderildi: 0532 123 45 67", "0532 123 45 67", "masked"),
    ("phone", "callerid=+90 532 123 45 67", "+90 532 123 45 67", "masked"),
    ("phone", "tel:05321234567 doğrulama", "05321234567", "masked"),
    ("phone", "ref:05321234567", "05321234567", "kept"),      # glued to another prefix: an identifier, not a phone
    ("phone", "dahili 2145 aradı", "2145", "kept"),
    # TCKN
    ("national_id_tr", "basvuru tckn=10000000146 onaylandi", "10000000146", "masked"),
    ("national_id_tr", "kimlik no: 10000000147 (hatalı)", "10000000147", "kept"),
    # IBAN
    ("iban", "odeme IBAN TR33 0006 1005 1978 6457 8413 26 alindi", "TR33 0006 1005 1978 6457 8413 26", "masked"),
    ("iban", "iban=TR330006100519786457841326", "TR330006100519786457841326", "masked"),
    # card
    ("card", "pan=4539 1488 0343 6467 declined", "4539 1488 0343 6467", "masked"),
    ("card", "ts=1730100000000 epoch", "1730100000000", "kept"),
    # secrets
    ("password", "POST /login parola=Gizli123! basarisiz", "Gizli123!", "masked"),
    ("password", '{"şifre": "Kuzey2026"}', "Kuzey2026", "masked"),
    ("bearer", "Authorization: Bearer abcdEFGH1234.xyz", "abcdEFGH1234.xyz", "masked"),
    ("aws_key", "key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE", "masked"),
    # IP (default ips: keep)
    ("ip", "Failed password from 203.0.113.7 port 22", "203.0.113.7", "kept"),
    # known gaps
    ("name", "Kullanıcı Ayşe Yılmaz oturum açtı", "Ayşe Yılmaz", "miss"),
    ("username", "sshd: Invalid user mehmet.kaya from 198.51.100.4", "mehmet.kaya", "miss"),
    ("address", "teslimat: Atatürk Cd. No:12 Kadıköy İstanbul", "Atatürk Cd. No:12", "miss"),
    ("plate", "otopark giris 34 ABC 123", "34 ABC 123", "miss"),
    # things that must not be touched
    ("noise", "run rosca-20261028073001-712bbf v4.14.8 port 55000", "rosca-20261028073001-712bbf", "kept"),
    ("noise", "rule 100213 level 12 agent 007", "100213", "kept"),
]

# Optional detectors (privacy.kinds must list them): person_name = common Turkish given name + Capitalised surname.
OPTIONAL_VECTORS = [
    ("person_name", "Kullanıcı Ayşe Yılmaz oturum açtı", "Ayşe Yılmaz", "masked"),
    ("person_name", "onaylayan: Mehmet Ali Kaya", "Mehmet Ali Kaya", "masked"),
    ("person_name", "Deniz kenarı sensörü alarm verdi", "Deniz", "kept"),
    ("person_name", "Sultan Ahmet camii kamerası", "Sultan Ahmet", "masked"),     # known false positive
    ("person_name", "kullanıcı mehmet.kaya kilitlendi", "mehmet.kaya", "miss"),
]
