# Wazuh 5

**Kimin için:** Wazuh kullanan ve 5.x'e geçmeyi planlayan herkes. **Durum:** Occultera **1.0** için planlandı.
Wazuh 4.x tam olarak desteklenmeye devam ediyor; bu sayfadaki hiçbir şey çalışan bir kurulumu değiştirmez.

> Wazuh 5.0 sürüm adaylarına (rc1/rc2, Ekim–Kasım 2026) dayanır. 5.0 genel kullanıma çıkınca bu sayfa gözden
> geçirilecek.

## Wazuh 5.0'da neler değişiyor

| | Wazuh 4.x | Wazuh 5.0 | Occultera için anlamı |
|---|---|---|---|
| Alarmlar | `wazuh-alerts-4.x-*` | olaylar `wazuh-events-v5-*`, tespitler `wazuh-findings-v5-*`, durum `wazuh-states-*` | toplama, nöbet ve MCP araçları yeni indeksleri okur |
| Alan adları | `rule.level`, `rule.description`, `agent.name`, `data.srcip` | Wazuh Common Schema: `wazuh.rule.level`, `wazuh.rule.title`, `wazuh.agent.name`, `source.ip` | her sorgu bir alan eşlemesinden geçer |
| Önem | sayı, 0–16 | informational, low, medium, high, critical | eşikler ve grafikler kategori kullanır |
| Algılama | Manager'da XML kurallar | Indexer'da Sigma uyumlu detector'lar | kural taslakları Sigma taslağı olur |
| Özel XML kurallar | var | otomatik taşınmıyor | aşağıdaki geçiş aracına bakın |
| Kural testi | `wazuh-logtest`, API `/logtest` | dashboard'a ve API'ye taşındı | iki yönlü logtest şimdilik yalnız 4.x'te |
| Kural kimliği | sayı (5710) | UUID | gürültü haritası ve bilgi tabanı kural kimliği ve başlığıyla eşleşir |
| Manager yolları | `/var/ossec`, `ossec.conf` | `/var/wazuh-manager`, `wazuh-manager.conf` | promotion betikleri |
| Indexer | OpenSearch 2.x | OpenSearch 3.x | sorgular ikisinde de test edilir |

## Durum (22 Kasım 2026)

| Parça | Durum | Nerede |
|---|---|---|
| Occultera ile Wazuh arasında şema katmanı (4.x sorguları değişmedi, altın rapor) | ✅ yayında | 0.18.0 |
| Bağlantı testinde Wazuh sürüm algılama | ✅ yayında | 0.18.0 |
| Tek sorgu dili: AI ve MCP istemcileri 4.x alan adlarını kullanır, sürüme göre çevrilir | ✅ yayında | 0.18.0 |
| Kural geçiş aracı, 4.x XML → Sigma (önizleme, alan adları 5.0 sürüm adaylarından) | 🚧 önizleme | 0.18.0 |
| 5.x şeması: findings / events / states, kategorik önem, kural UUID'leri | ⬜ planlandı | 5.0 lab'ı gerekiyor |
| 5.x'te araç sonuçlarının 4.x adlarına çevrilmesi | ⬜ planlandı | 5.x şemasıyla |
| 5.x'te Sigma kural taslakları | ⬜ planlandı | |
| demo5.occultera.dev ve 4.x / 5.x smoke-test matrisi | ⬜ planlandı | |
| **Wazuh 5.x desteği** | ⬜ **Occultera 1.0**, Wazuh 5.0 genel kullanıma çıktıktan sonra | |

## Plan

1. **Sürüm adaptörü** (geliştiriliyor). Wazuh'a bakan kod, 4.x ve 5.x uygulaması olan tek bir arayüzün arkasına
   taşınıyor. Occultera sürümü Wazuh API'sinden ve indeks kalıplarından algılar; ortamda `wazuh_version: 4 | 5`
   ile elle verilebilir. Rapor, nöbet, pano ve MCP sunucusu iki sürümde de aynı görünür.
2. **Önem eşlemesi.** Wazuh, 4.x seviyeleriyle 5.x önem dereceleri arasında bir eşleme yayımlamıyor. Occultera'nın
   varsayılanı (ortam başına değiştirilebilir):

   | 4.x seviye | 5.x önem |
   |---|---|
   | 0–3 | informational |
   | 4–6 | low |
   | 7–9 | medium |
   | 10–12 | high |
   | 13–16 | critical |

3. **5.x'te Sigma taslakları.** 4.x'te yapay zekâ, doğrulayıp test ettiğiniz ve uyguladığınız XML kurallar yazar
   ([Kural yaşam döngüsü](Rule-Lifecycle-TR)). 5.x'te Sigma kuralı yazar; Wazuh içerik API'si oturunca onun
   üzerinden uygulama da gelecek.
4. **Kural geçiş aracı** (planlandı, 1.0'dan önce önizleme), aşağıda.
5. **Wazuh 5.x desteği 1.0'da**, Wazuh 5.0 genel kullanıma çıktıktan sonra.

## Özel 4.x kuralları için geçiş aracı

Occultera içinden ya da uygulamanın geri kalanı olmadan tek başına kullanılabilir.

| Girdi | Çıktı |
|---|---|
| `local_rules.xml` ve diğer özel kural dosyaları | temiz çevrilen kurallar için Sigma kuralları |
| özel decoder'lar, CDB listeleri | kural başına gerekçesiyle "insan gerekiyor" listesi |
| isteğe bağlı: örnek olaylar | kural başına eşleşme kontrolü: aynı olaylarda 4.x kuralı ve Sigma kuralı |
| nöbet kurallarınız | 4.x alan adları Wazuh Common Schema'ya eşlenmiş aynı kurallar |

Otomatik çevrilenler: alan eşleşmeleri, `match` / `regex`, gruplar, seviye → önem, MITRE ATT&CK.
İncelemeye ayrılanlar: `if_sid` / `if_matched_sid` zincirleri, `frequency` / `timeframe`, CDB listeleri,
`overwrite="yes"` kuralları, regex lehçe farkları. Özel decoder'lar ilk sürümde çevrilmez, raporlanır.

### Önizlemeyi deneyin (0.18)

```sh
docker run --rm -v "$PWD:/w" -w /w ghcr.io/occultera/occultera:0.18.0 \
  python -m app.migrate /w/local_rules.xml --events /w/alerts.jsonl --out /w/migrate-out --json
```

`migrate-out/` içine çevrilebilen her kural için bir Sigma dosyası (`wazuh-<id>.yml`; `frequency` taşıyan kurallarda
ayrıca Sigma *correlation* taslağı), kural başına durum, inceleme gerekçeleri ve eşleşme kontrolünü içeren
`report.md` ve alan eşlemesi yazılır. `--events` satır başına bir JSON olarak 4.x alarm dokümanı alır — örneğin
`wazuh-alerts-4.x-*`'ten bir günlük dışa aktarım; her olay hem 4.x kuralından hem Sigma kuralından geçer, rapor nerede
uyuştuklarını gösterir. Üst kuralı (`if_sid`) aynı dosyada olan kurallarda üst kuralın koşulları içe alınır; stok üst
kural incelemeye listelenir. Alan adları 5.0 sürüm adaylarına göredir, GA'da yeniden kontrol edilir.

## Şimdi ne yapabilirsiniz

- Üretimde Wazuh 4.x'te kalın; 5.0 yerinde bir yükseltme değil, bir geçiş.
- Özel kurallarınızı `local_rules.xml` ya da kendi ID aralığınızla ayrı dosyalarda tutun; geçiş aracı onları böyle
  bulur.
- Bir 5.0 test sisteminiz var ve önizlemeyi denemek isterseniz hello@occultera.dev adresine yazın.
- [Sürümleri](https://github.com/occultera/occultera/releases) ve
  [CHANGELOG](https://github.com/occultera/occultera/blob/main/CHANGELOG.md)'u takip edin.

Ayrıca: [Uyumluluk](Compatibility-TR) · [Yükseltme](Upgrade-TR) · [English](Wazuh-5)
