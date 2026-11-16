# Nöbet: yapay zekâsız acil uyarılar

*0.10.0'dan beri.* İşleri farklı iki döngü:

| | Nöbet | AI turu |
|---|---|---|
| Ne zaman | birkaç dakikada bir (varsayılan 5) | günde bir ya da iki kez, sizin belirlediğiniz saatlerde |
| Nasıl karar verir | yerel kurallarla — **model çağrılmaz** | model tüm dönemi inceler |
| Ne yapar | hemen bildirir: "kural tabanlı uyarı — yapay zekâ incelemedi" | her nöbet olayı için hüküm, bulgular, eşik önerileri |
| Maliyet | yok | tur başına bir model çağrısı |

Nöbet, bir yönetici **Ayarlar → Nöbet** (`/e/<ortam>/settings`) bölümünden açana kadar **kapalıdır**.

## Ne acil sayılır?

| Tetikleyici | Ne zaman çalışır | Ayar |
|---|---|---|
| Kritik seviye | `critical_level` veya üstünde bir alarm (varsayılan 12; 15 ve üstü *kritik*) | seviye |
| İzlenen kural | listedeki bir kuralın herhangi bir alarmı (varsayılan: ortamın `watch_rules` listesi) | liste |
| İzlenen grup | izlenen bir grubun `group_min_level` veya üstündeki alarmı (varsayılan 10) | liste, seviye |
| Active Response | Wazuh otomatik bir işlem yaptı (`rule.groups: active_response`) | — |
| Başarısız denemelerden sonra giriş | aynı kaynak adresten, öncesindeki `brute_window_minutes` içinde en az `brute_failures` başarısız denemeden sonra başarılı giriş — her zaman *kritik* | sayı, süre |
| Ani artış | bir aralıktaki `spike_min_level` (varsayılan 7) ve üstü alarmlar, 7 günlük ortalamalarının `spike_factor` katı ve en az `spike_min` (varsayılan 50). Tarama grupları (`syscheck`, `sca`, `vulnerability-detector`, `rootcheck`, `syscollector`, `ciscat`, `oscap`) sayılmaz. Mesaj, artışı yapan kuralları adıyla verir | kat, en az, seviye, gruplar |
| Olağan dışı dışarı aktarım (varsayılan kapalı) | bir Kubernetes iş yükü bir aralıkta pod'larından en az `egress_min_mb` (varsayılan 500 MB) ve 7 günlük ortalamasının en az `egress_factor` (varsayılan 5) katı veri gönderdi. Prometheus kaynağı gerekir; bkz. [aşağısı](#olağan-dışı-dışarı-aktarım) | kat, MB, namespace'ler |
| Küme alarmı (varsayılan kapalı) | kümenin kendi Prometheus'u seçilen önem derecesinde bir alarm ateşlemeye başladı (`prom_alert_severities`, varsayılan `critical`); küme, alarm ve önem derecesi başına tek olay. İlk görüldüğünde iki saatten uzun süredir ateşlenen alarm *hâlâ ateşleniyor* olarak sessiz kalır | önem dereceleri |
| Ajan koptu | `agent_minutes` süresinden uzun bağlantısız ajan (`ignore_agents` atlanır; aynı anda 5 ve fazlası *kritik*). Açılıştan sonraki ilk tarama yalnızca mevcut durumu öğrenir | dakika |

## Ayıklama

Bir olay şu durumlarda bildirime girmez (yine kaydedilir ve AI yine değerlendirir):

- anahtarı **susturma** listesindeyse (tam anahtar, `*` ile biten önek ya da `rule:<id>`),
- kuralı bilgi tabanında etkin bir **baseline** kaydıysa (kritik olaylar için asla),
- aynı anahtar `repeat_hours` (varsayılan 6) içinde zaten bildirildiyse — mevcut olayın sayısı artar,
- **tekrarlayan bir patlamaysa**: kuralları son 7 gün içinde aynı uzunlukta bir aralıkta en az yarısı kadar bir
  patlama yapmış bir ani artış (planlı işler, gece toplu işleri),
- **tekrarlayan bir aktarımsa**: aynı iş yükünün son 7 gün içinde aynı uzunlukta bir aralıkta en az yarısı kadar
  yaptığı bir dışarı aktarım (yedek, eşitleme, dışa aktarma işleri).

### Ani artış neden böyle çalışıyor

Her alarmı saymak tetikleyiciyi planlı işlerde çalıştırıyordu: bir Windows masaüstündeki kayıt defteri taraması
(750–752, seviye 5, bir dakikada binlerce), güncelleme sonrası zafiyet tarayıcısının CVE kapatması (23502, seviye
3), bir SCA taraması (19007) ya da rootcheck. Bunların hiçbiri saldırı değil; eski mesaj hangi kural olduğunu da
söylemiyordu. Artık yalnız önemli alarmlar sayılıyor, taramalar dışarıda kalıyor, 24 saatlik ortalamanın yerini 7
günlük ortalama aldı, olay anahtarı ana kural oldu (`spike:<kural no>`) ve bu sayede her kural gibi susturulabiliyor
ya da baseline olarak kaydedilebiliyor; aynı kuralların bu hafta zaten yaptığı bir patlama bildirim göndermeden
nöbet sayfasında kalıyor. Eski davranışa dönmek için seviyeyi 0, grupları `-` yapın.

### Olağan dışı dışarı aktarım

Bir veri sızıntısı çoğu zaman kendi başına bir Wazuh alarmı üretmez: çalınmış bir token ya da ele geçirilmiş bir
uygulama yalnızca dışarı çok veri gönderir. Bu tetikleyici o hacmi izler. Her aralıkta ortamın Prometheus
kaynağından cAdvisor'ın `container_network_transmit_bytes_total` değerini okur, namespace ve **iş yükü** başına
toplar (ReplicaSet ya da DaemonSet son eki atılmış pod adı; böylece bir rollout geçmişini korur, StatefulSet
pod'ları ayrı kalır) ve aralığı aynı iş yükünün 7 günlük ortalamasıyla karşılaştırır. Olay iş yükünü, hacmi ve katı
söyler, örneğin *erp/odoo 5 dk içinde 900 MB dışarı gönderdi — 7 günlük ortalamasının (2.0 MB) >100 katı*;
anahtarı `egress:<namespace>/<iş yükü>` olduğu için her olay gibi susturulabilir.

Yapmadıkları:

- **İçeriğe asla bakmaz.** Bir yedek, bir eşitleme işi ve bir sızıntı aynı görünür; kararı AI turu ve insan verir.
- **Pod'un bütün arayüzünü sayar**, yani diğer pod'lara giden trafik de (veritabanı, nesne depolama, replikasyon)
  sayılır. Küme altyapısı namespace'leri varsayılan olarak dışarıda kalır (`kube-system`, `longhorn-system`,
  `cattle-*`, `monitoring`, `logging`, `calico-system`, `tigera-operator`, `cert-manager`); kendi
  namespace'lerinizi ekleyin ya da hiçbirini çıkarmamak için `-` yazın.
- **`hostNetwork` kullanan pod'lar** düğümün trafiğini bildirir ya da hiç bildirmez; Kubernetes dışındaki trafik
  görülmez.

Ayarlar → Nöbet bölümünden açın. Varsayılan olarak kapalıdır ve `sources.prometheus` yoksa onay kutusu
kullanılamaz. Varsayılanlarla başlayın: yoğun bir kümede bu hafta zaten olmuş bir patlama (Kafka yeniden
dengelemesi, gece yedekleri) tekrarlayan aktarım olarak sessiz kalır.

## Kanallar ve sessiz saatler

Nöbet, işaretlediğiniz kanalları kullanır; seçim **yapılandırma dosyasında tanımlı kanallar arasından** yapılır.
Adres, belirteç ve webhook adresi arayüzden asla girilmez. Sessiz saatlerde — bu seçeneği açık bırakırsanız
kritik olaylar dışında — hiçbir şey gönderilmez; bekletilenler sessiz süre bitince tek mesajla gider.

## AI turu

Planlı koşu, hükmü olmayan tüm olayları tek istekte alır ve `event_verdicts` ile cevaplar: `real_incident`
(gerçek olay), `investigate` (incelenmeli), `expected` (beklenen) ya da `noise` (gürültü), her biri gerekçesiyle.
Bir öneri ekleyebilir: bu olay anahtarını sustur ya da bir eşiği değiştir. **Öneri hiçbir şeyi değiştirmez**:
Ayarlar → "Nöbet için AI önerileri" bölümünde görünür, yönetici kabul eder ya da reddeder. Kabul denetim
kaydına yazılır.

Tur saatlerini **Ayarlar → AI turu** bölümünden belirleyin (günde bir ya da iki). Boş bırakılırsa yapılandırma
dosyasındaki `schedule` kullanılır. Elle başlatılan koşular ("Run now") ve olay kaydı taslakları sınırlanmaz.

## Nerede saklanır?

`<önek>-events` olayları ve hükümleri, `<önek>-settings` ayar belgesini ve küçük durum bilgisini (tarama
imleci, bilinen kopuk ajanlar) tutar. 180 günden eski olaylar silinir (`backup.keep_events_days`).

## Nasıl denenir?

Nöbeti varsayılan ayarlarla açın, bir hafta sessiz saatleri kapalı tutun ve her AI turundan sonra Nöbet
sayfasındaki hükümleri okuyun. Doğru olan susturma önerilerini kabul edin; zaten bildiğiniz bir şey için her
gün çalışan tetikleyicinin eşiğini yükseltin.

Ayrıca: [Yedekleme](Backup-TR) · [Yapılandırma](Configuration-TR) · [Özellikler](Features-TR)

---

[English](Watch) · [Türkçe](Watch-TR)
