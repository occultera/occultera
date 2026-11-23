# Yol haritası

Occultera bugün ne yapıyor, şu an ne geliştiriliyor, sırada ne var. Wazuh 4.x tam desteklenmeye devam ediyor; Wazuh 5.x desteği, Wazuh 5.0 genel kullanıma çıktıktan sonra 1.0 ile geliyor.

Güncel sürüm: **0.18.0** · Güncellendi 2026-11-23

## ✅ Yayında

| Madde | Size ne kazandırır |
|---|---|
| **Wazuh için MCP sunucusu** | Claude Desktop, Cursor, VS Code ya da herhangi bir MCP istemcisi salt okunur araçlarla canlı veriyi inceler. |
| **Kendi modelinizle AI alarm triage** | Claude, OpenAI, Gemini, DeepSeek ya da yerel model (Ollama, vLLM): kanıtlı bulgular, sorular ve kural taslaklarıyla tek rapor. |
| **KVKK / GDPR maskeleme** | Algılanan kişisel veriler yapay zekâya ve her MCP istemcisine gitmeden takma adla değiştirilir; sırlar silinir. |
| **Yapay zekâsız acil alarm nöbeti** | Kritik alarm, başarısız denemelerden sonra giriş, ani artış, susan ajan, olağandışı dışarı aktarım — dakikalar içinde. |
| **Güvenilir kural taslakları** | İki haftalık gerçek alarmlarda denenir, iki yönlü logtest, geri almalı yayılım, canlı doğrulama. |
| **Küme nabzı** | Prometheus ve Thanos, bir Wazuh arkasında birden çok Kubernetes ve OpenShift kümesi, yapay zekâyla açıklanan alarmlar. |
| **Aylık denetim raporu ve PDF** | Hacim, kararlar, kural değişiklikleri, kesintiler, ajan kapsamı, zafiyet SLA — ISMS kanıtı. |
| **Helm, Kustomize, Docker Compose; imzalı imajlar** | Tek container, ek veritabanı yok, salt okunur dosya sistemi; sürüm imajları cosign ile imzalı, her derlemede SBOM. |
| **Wazuh 5 için iç hazırlık (0.17)** | Occultera ile Wazuh arasında şema katmanı; 4.x sorguları değişmedi, altın raporla doğrulandı. |
| **API anahtarı olmadan AI turu** | Günlük incelemeyi bir MCP istemcisinde (daily_review) yapın ya da maskeli brifingi Gemini, ChatGPT veya Claude'a verip cevabı yükleyin. |
| **Önerili indexer sağlığı** | Heap, circuit breaker (“Data too large”), GB heap başına shard, atanmamış shard — ne yapılacağıyla birlikte. |
| **Wazuh sürüm algılama** | Bağlantı testi Wazuh sürümünü gösterir; 5.x sunucu tanınır ve açıklanır. |
| **Hata bildirimi ve anonim kullanım verisi** | Varsayılan açık, Ayarlar'dan kapatılır; yalnız yapısal veri, alarm ya da log içeriği asla; toplayıcı açık kaynak. |
| **Kural geçiş aracı: özel 4.x XML → Sigma** | Basit kuralları çevirir, kişi gerektirenleri listeler, alanları eşler, örnek olaylarda eşleşmeyi kontrol eder. Tek başına da çalışır. |
| **Denetim raporunda ISO 27001 Annex A eşlemesi** | Aylık raporun her bölümü kanıtladığı kontrollere bağlanır. |

## ⬜ Sırada (0.19)

| Madde | Size ne kazandırır |
|---|---|
| **Wazuh 4.x ve 5.x için herkese açık demolar** | 4.x verisiyle demo.occultera.dev, 5.x önizlemesi olarak demo5.occultera.dev. |

## ⬜ 1.0'a doğru

| Madde | Size ne kazandırır |
|---|---|
| **Wazuh 5.x desteği — Occultera 1.0** | Sürüm adaptörüyle findings, events ve states; önem eşlemesi; 5.x'te Sigma taslakları. Wazuh 5.0 genel kullanıma çıktıktan sonra. |
| **Decoder taslakları; PagerDuty ve Opsgenie** | Kural taslaklarının yanında yeni log kaynakları; gerçek olayların nöbet eskalasyonu. |

Eksik bir şey mi var? Bir issue açın ya da yazın: hello@occultera.dev · https://github.com/occultera/occultera/issues · https://occultera.dev/tr/yol-haritasi/
