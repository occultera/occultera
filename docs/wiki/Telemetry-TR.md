# Hata bildirimi ve kullanım verisi

**Kimin için:** Occultera çalıştıran ve kurulumdan neyin dışarı çıktığını bilmek isteyen herkes. *(1.0)*

Occultera **çökme raporları** ve haftada bir **hangi sürüm ve özelliklerin kullanıldığını** gönderir. Varsayılan
olarak açıktır, tek bir ayarla kapatılır. Amaç: haberimiz olmayan çökmeleri düzeltmek ve kurulumların Wazuh 5.x'e ne
hızla geçtiğini görmek.

## Seviyeler

| `TELEMETRY` | Ne gönderilir |
|---|---|
| `errors+usage` (varsayılan) | çökme raporları ve haftalık kullanım bilgisi |
| `errors` | yalnız çökme raporları |
| `off` | hiçbir şey |

Herkese açık demo (`WDT_PUBLIC_DEMO`) hiçbir şey göndermez. Dışarıya HTTPS kapalıysa gönderim sessizce başarısız
olur, başka hiçbir şey etkilenmez. **Ayarlar → Hakkında → Hata bildirimi ve kullanım verisi** seviyeyi ve bir olayın
tam olarak neye benzediğini gösterir.

## Çökme raporunda ne var

| Alan | Örnek |
|---|---|
| istisna sınıfı | `KeyError` |
| hata kategorisi | `internal`, `timeout`, `auth` … (MCP istemcilerinin gördüğü kategoriler) |
| uygulama içindeki çerçeveler | `app.collector.core:collect`, `app.agent.tools:call` — yalnız modül ve fonksiyon |
| parmak izi | sınıf ve son beş çerçevenin özeti; tekrarları gruplamak için |
| sürümler | Occultera, Python, kurulum türü (`helm`, `kustomize`, `compose`) |
| kurulum kimliği | gizli tuzunuzdan türetilen 16 karakter — geri çevrilemez; `TELEMETRY_ID` ile değişir |

**Asla gönderilmez:** istisna mesajı, log satırları, alarm ya da rapor içeriği, IP adresleri, host, ajan ya da
kullanıcı adları, dosya yolları, URL'ler, model adları, anahtar ya da token'lar. Olay gönderilmeden önce sabit bir
anahtar listesine göre kontrol edilir; başka anahtar taşıyan olay atılır. Aynı çökme günde en fazla bir kez, günde en
fazla 20 rapor gönderilir.

## Haftalık kullanım bilgisinde ne var

Occultera sürümü, ortamların Wazuh sürümleri (Wazuh API'den), ortam sayısı, LLM sağlayıcı *türü* (`anthropic`,
`openai`, `none` … — model ya da uç nokta asla), kurulum türü ve evet/hayır bayrakları: MCP, Prometheus, Loki,
Kubernetes, maskeleme, kural yayılımı, SSO.

## Nereye gider

`https://telemetry.occultera.dev/v1/events` — Cloudflare Worker ve D1 veritabanı. Yalnız bu iki olay biçimini kabul
eder, IP adresi ve istek başlığı saklamaz, kayıtları 90 gün sonra siler ve her yeni çökme parmak izi için bir GitHub
issue'su (`crash` etiketi) açar. Kaynağı açıktır (`occultera/telemetry`). Kendi toplayıcınızı kullanmak için
`TELEMETRY_URL` ayarlayın.

## Sorunu kendiniz bildirin

**Ayarlar → Hakkında → Sorunu kendiniz bildirin** GitHub issue formunu (`crash`) açar. Yalnız maskelenmiş log satırı
yapıştırın.
