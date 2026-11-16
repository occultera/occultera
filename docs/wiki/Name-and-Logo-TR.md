# Ad ve logo

[English](Name-and-Logo) · **Türkçe**

<p align="center"><img src="images/occultera-mark.svg" alt="Occultera logosu" width="220"></p>

**Occultera**'nın 0.11.1 sürümüne kadarki adı **wazuh-daily-triage** idi. Kod, yapılandırma ve veri aynı; yalnız
ad, logo ve adresler değişti (bkz. [Yükseltme](Upgrade-TR#0120)).

## Ad nereden geliyor

Çok parlak bir kaynağın yanındaki sönük bir şeyi görmek isteyen gökbilimciler, parlak kaynağın önüne bir disk
koyar. Bu diske **occulter** (örtücü) denir. Parlaklık örtülünce yanında saklanan görünür hale gelir: Güneş'in
koronası ya da yıldızının yanındaki sönük bir gezegen. Yerdeki ve uzaydaki koronagraflar böyle çalışır.

SIEM'in derdi de aynı. Günde binlerce alarm parlak ve çoğu beklenen şeyler; önemli olan sönük ve tam onların
yanında duruyor. Occultera bilinen gürültüyü — baseline'ları, kabul edilmiş bulguları, anlamını bildiğiniz
kuralları — örter; geriye insanın bakmaya değer bulacağı şey kalır.

## Logo ne anlatıyor

| Parça | Anlamı |
|---|---|
| Karanlık disk | örtücü: bilerek örtülen bilinen gürültü |
| Altın ve mavi korona | hâlâ orada olan her şey, bağlamıyla |
| Kenardaki tek parlak ışık | içeri sızan sinyal |
| Işığın çevresindeki mavi parantezler | nöbet ona kilitlendi |
| Çizgili radar yayı | bir insan karar verene kadar izleniyor |

**Slogan:** *Find the signal in the dark.* (Karanlıkta sinyali bul.)

## Dosyalar

Kaynak dosyalar [`docs/assets`](https://github.com/occultera/occultera/tree/main/docs/assets) içinde:
`occultera-mark.svg` (logo), `occultera-lockup.svg` (logo, ad ve slogan), `occultera-square.svg` ve
`occultera-social-1280x640.png`. Renkler: zemin `#0A0F1A`, disk `#05080F`, altın `#FFD27A`, mavi `#7FD3FF`,
yazı `#F2EFE6`. Yazı tipi: Space Grotesk (SIL Open Font License).

## Değişmeyenler

Ortam değişkenleri (`WDT_*`), indeks adları (`daily-triage-*`), metrik adları (`wdt_*`) ve Kustomize kaynak
adları aynı kaldı; mevcut kurulumlar veri taşımadan yerinde yükseltilir. Helm chart'ı ve yedek arşivleri yeni adı
taşır (bkz. [Yükseltme](Upgrade-TR#0120)).

---

*0.12.0 için geçerlidir · gözden geçirme: 2026-11-16*
