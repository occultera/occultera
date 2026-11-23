# Yol haritası

Occultera bugün ne yapıyor, şu an ne geliştiriliyor, sırada ne var. Wazuh 4.x tam desteklenmeye devam ediyor; Wazuh 5.x desteği, Wazuh 5.0 genel kullanıma çıktıktan sonra 1.0 ile geliyor.

Güncel sürüm: **0.17.0** · Güncellendi 2026-11-22

**1.0 önizlemesi** olarak işaretlenen maddeler `feat/1.0-wazuh-adapter` geliştirme dalında uygulanmıştır;
yayımlanmış 0.17.0 sürümüne dahil değildir.

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

## 🚧 1.0 önizlemesi — geliştirme dalı

| Madde | Size ne kazandırır |
|---|---|
| **API anahtarı olmadan AI turu** | Günlük incelemeyi bir MCP istemcisinde yapın ya da maskeli brifingi bir sohbet asistanına verip yanıtı geri yükleyin. |
| **Önerili Indexer sağlığı** | Heap, circuit breaker, heap başına shard ve atanmamış shard için önerilen kontroller. |
| **Wazuh sürüm algılama** | Bağlantı testi sunucu sürümünü belirler; Wazuh 5'in algılanması şemasının desteklendiği anlamına gelmez. |
| **Hata bildirimi ve anonim kullanım verisi** | Ayarlanabilir telemetri; yalnız yapısal tanılama verisi, alarm veya log içeriği gönderilmez. |
| **Kural geçiş aracı (önizleme): özel 4.x XML → Sigma** | Desteklenen kuralları çevirir, insan incelemesi gerekenleri işaretler, alanları eşler ve örnek olaylarda eşleşmeleri karşılaştırır. |
| **Annex A kanıt özeti** | On seçili kontrol için kanıt/boşluk durumu, SoA istisnaları ve referanslar. ISMS incelemesine destek olur; sertifika değildir. |

## ⬜ Sırada (0.18)

| Madde | Size ne kazandırır |
|---|---|
| **Wazuh 4.x ve 5.x için herkese açık demolar** | 4.x verisiyle demo.occultera.dev, 5.x önizlemesi olarak demo5.occultera.dev. |

## ⬜ 1.0'a doğru

| Madde | Size ne kazandırır |
|---|---|
| **Wazuh 5.x desteği — Occultera 1.0** | Sürüm adaptörüyle findings, events ve states; önem eşlemesi; 5.x'te Sigma taslakları. Wazuh 5.0 genel kullanıma çıktıktan sonra. |
| **Decoder taslakları; PagerDuty ve Opsgenie** | Kural taslaklarının yanında yeni log kaynakları; gerçek olayların nöbet eskalasyonu. |

Eksik bir şey mi var? Bir issue açın ya da yazın: hello@occultera.dev · https://github.com/occultera/occultera/issues · https://occultera.dev/tr/yol-haritasi/
