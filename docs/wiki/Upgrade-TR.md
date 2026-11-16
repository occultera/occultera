# Yükseltme ve geri dönüş

**Kimin için:** operatörler. Aşağıdaki adımlar **önerilen işletim prosedürüdür**. Uygulamanın yerleşik bir
yükseltme ya da sürüm düşürme komutu yoktur: yükseltme, aynı yapılandırma ve aynı veriyle yeni bir imajdır.

## Yükseltme neye dokunur

| | Nerede durur | Yükseltmeyle değişir mi? |
|---|---|---|
| Uygulama | konteyner imajı | evet: yükseltme budur |
| Yapılandırma | `.env`, `config/environments.yaml` ya da Helm değerleri | yalnız sürüm notları bir anahtarın değiştiğini söylüyorsa |
| Raporlar, bilgi tabanı, nöbet olayları, ayarlar | Wazuh Indexer'ınızdaki `<storage_prefix>-*` indeksleri | geçiş adımı yok; yeni sürüm yeni bir indeks ekleyebilir |
| Denetim izi | `audit` birimi ya da log gönderiminiz | hayır |

Durum Indexer'da olduğu için konteyneri değiştirmek hiçbir şey kaybettirmez. Yükseltmedeki risk, değişen bir
varsayılan ya da yeni bir gerekliliktir; bu yüzden önce sürüm notları okunur.

## Yükseltmeden önce

1. Kendi sürümünüzden hedef sürüme kadar
   [CHANGELOG.md](https://github.com/occultera/occultera/blob/main/CHANGELOG.md) dosyasını ve
   aşağıdaki sürüm notlarını okuyun.
2. Çalışan sürümü (**Hakkında** sayfası) ve kullanılan imaj etiketini ya da digest'ini not edin.
3. Yedek alın: **Ayarlar → Yedekleme** bölümünden oluşturup indirin ve parolayı bulabileceğiniz bir yerde
   saklayın. Yeni sürüm eskisinin okuyamadığı bir şey yazarsa geri dönüş yolunuz bu yedektir. Bkz.
   [Yedekleme](Backup-TR).
4. Süren bir koşu olmadığından emin olun.

## Yükseltme

Sürümleri sabitleyin. `:latest` ile ne çalıştırdığınızı söyleyemez, ona geri dönemezsiniz.

```sh
# Docker Compose: docker-compose.yml içinde imaj etiketini ayarlayın, sonra
docker compose pull
docker compose up -d
docker compose exec triage python -m app.check
```

```sh
# Helm
helm upgrade occultera occultera/occultera \
  --namespace occultera --version <chart sürümü> -f my-values.yaml
```

Kustomize'da overlay'inizdeki uzak base'in `?ref=` değerini ve imaj etiketini değiştirip `kubectl apply -k .`
çalıştırın.

## Yükseltmeden sonra

- Konteyner logu ortamları ve zamanlamayı gösterir, yeni bir güvenlik uyarısı yoktur.
- `python -m app.check` geçer.
- **Ayarlar → Depolama güvenliği** sorunsuzdur.
- Bir koşu başlatın ve raporu açın.
- Eski raporlar ve bilgi tabanı yerinde durur.

## Geri dönüş

Önceki imaj etiketini ya da digest'ini önceki yapılandırmayla kurun:

```sh
# Helm
helm -n occultera history occultera
helm -n occultera rollback occultera <revizyon>
```

Compose'da önceki etiketi yazıp `docker compose up -d` çalıştırın.

**Geri dönüşün sınırları.** Proje sürüm düşürmeyi test etmez. Yeni sürümün yazdığı belgeler indekslerde kalır
ve eski sürüm bilmediği alanları yok sayabilir. Yalnız yeni sürümde bulunan ayarlar geri dönüşten sonra
etkisizdir. Eski sürüm yeni veriyle düzgün çalışmazsa yükseltmeden önce aldığınız yedeği içe aktarın.

## Sürüm notları

### 0.13.0

- `sources.prometheus_extra` ile **ortam başına birden çok küme** (ad zorunlu). Tek Prometheus'lu ortamlarda hiçbir
  şey değişmez. Bkz. [Özellikler](Features-TR#tek-wazuh-arkasında-birden-çok-küme).
- `openshift-*` namespace'leri dışarı aktarım panellerinde ve tetikleyicide varsayılan olarak dışarıda kalır.

### 0.12.3

- Düzeltme: Prometheus'a ulaşılamadığında küme nabzı sayfası artık HTTP 500 vermiyor. Yapılacak bir şey yok.

### 0.12.2

- **Yeni nöbet tetikleyicisi: olağan dışı dışarı aktarım** (olası veri sızıntısı). Varsayılan olarak kapalı;
  Prometheus kaynağı gerekir. Ayarlar → Nöbet bölümünden açılana kadar hiçbir şey değişmez. Bkz.
  [Nöbet](Watch-TR#olağan-dışı-dışarı-aktarım).
- **Yeni sayfa: küme nabzı** (Prometheus). Dışarı aktarım, girişte 401/403/5xx, secret okumaları, DNS, CPU
  sapmaları, yeniden başlatmalar, sertifikalar ve düşük izleme hedefleri. Yalnız `sources.prometheus` tanımlı
  ortamlarda görünür. Bkz. [Küme nabzı](Cluster-Pulse-TR).
- Hakkında sayfası: ad ve logonun hikâyesini anlatan kısa bir satır.

### 0.12.1

- **Ani artış** yalnız seviye 7 ve üstü alarmları sayar, tarama gruplarını dışarıda bırakır, 7 günlük ortalamayla
  karşılaştırır ve artışı yapan kuralları adıyla verir. Tekrarlayan bir patlama bildirim göndermez. Varsayılan en
  az değer artık 50; eski sürümden kayıtlı 500, 50'ye çekilir. Bkz. [Nöbet](Watch-TR#ani-artış-neden-böyle-çalışıyor).

### 0.12.0

- **Projenin adı artık Occultera.** Başka hiçbir şey değişmedi: yeni ayar yok, veri taşıma yok.
- **Yeni imaj adresi:** `ghcr.io/occultera/occultera:0.12.0`. Yükseltirken `image:` (Compose), `images.newName`
  (Kustomize) ya da `image.repository` (Helm değerleri) satırını değiştirin. Eski etiketler
  `ghcr.io/dururustem68/wazuh-daily-triage` adresinde kalır.
- **Kustomize uzak tabanları:** `https://github.com/occultera/occultera//deploy/kubernetes/base?ref=v0.12.0`. Eski
  adres yönlendirilmeye devam eder.
- **Helm:** chart'ın adı artık `occultera` (chart 0.4.0), adresi `https://occultera.github.io/occultera`
  (`helm repo add occultera …`, `helm install occultera occultera/occultera`). Kaynak adları release adını izler.
  Eski `wazuh-daily-triage` chart'ıyla kurulmuş bir release yenisine yükseltilmez: yeni chart'ı yeni bir release
  olarak kurun, sonra eskisini kaldırın.
- **Yedek arşivleri** artık `occultera-<ortam>-<zaman>.occbak` adında ve yeni bir biçim işaretiyle yazılıyor;
  0.11.x'in yazdığı arşivler içe aktarılamaz. Varsayılan S3 anahtar öneki `occultera`. Yükseltmeden sonra yeni
  bir yedek alın.
- **Maskeleme profili dışa aktarımı** `format: occultera-mask-profile` taşıyor.
- **Bildirim başlıkları** artık `[Occultera]` ile başlıyor. Eski konuya göre süzen e-posta kurallarını güncelleyin.
- Yapılandırmanızda `title: Wazuh Daily Triage` varsa değiştirin ya da satırı silin, yeni ad görünsün.

### 0.11.1

- **Uzun işlemler arka planda çalışır.** Kural dağıtma ve kaldırma, bağlantı testi, olay kaydı taslakları ve
  *Ne yapardı?* bir iş ile `202` yanıtı verir; sayfa `GET /api/e/<env>/jobs/<id>` adresini yoklar ve dağıtım
  adımlarını canlı gösterir. Hiçbir vekil zaman aşımı (oauth2-proxy'nin 30 sn'si) bunları artık kesemez. Bu
  rotaları çağırıp sonucu yanıtta bekleyen betikler `?wait=true` ekler.
- **Durum tutan kurallar doğru logtest edilir.** Frekans / `if_matched_*` kuralları logtest adımında her seferinde
  başarısız olup geri alınıyordu (tek olay yalnız üst kurala ulaşır). Örnekler artık tek logtest oturumunda tekrar
  oynatılır.
- **Yarıda kalan dağıtımlar görünür.** Dağıtım ortasında yeniden başlatma, *Uygulanıyor*'da takılı kayıt yerine
  *Yarıda kaldı — yöneticiyi kontrol edin* bırakır.
- **Kubernetes:** `terminationGracePeriodSeconds: 420` (temel manifest ve chart değeri); böylece süren bir dağıtım
  rollout sırasında bitebilir; `JOB_DRAIN_SECONDS` (varsayılan 400) uygulamanın bekleme süresidir.

### 0.11.0

- **SSO rolleri (SSO vekili arkasında işlem gerekir).** 0.11 öncesinde her SSO kullanıcısı yöneticiydi. Artık rol,
  vekilin grup başlığından gelir: `SSO_ADMIN_GROUPS` (isteğe bağlı olarak `SSO_VIEWER_GROUPS`) ayarlayın ve vekilin
  grupları iletmesini sağlayın (`X-authentik-groups`, `X-Auth-Request-Groups`). Bunlar olmadan her SSO kullanıcısı
  salt okunur görüntüleyicidir. Geçiş için `SSO_DEFAULT_ROLE=admin` eski davranışı korur; açılışta uyarı verilir.
  Ayrıntı: [SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR).
- **Yeni arayüz.** Kenar çubuğu menüsü, grafikli pano ve ATT&CK sayfası. Yapılandırma gerekmez; yer imleri
  çalışmaya devam eder. Pano `?env=` ve `?period=24h|7d|30d` parametrelerini alır.
- **Bulgularda ATT&CK etiketleri.** Yeni koşular bulgulara `mitre` ve `mitre_tactics` yazar; eski raporlar etiketsiz
  görünür.
- Pano açıldığında ortam başına iki toplama sorgusu daha (bir dakika önbellekli). Indexer rolüne yeni yetki
  gerekmez.

### 0.10.1

- **Kişisel veri maskeleme varsayılan olarak açık.** `privacy:` bloğu olmayan kurulum artık maskeler. Önceki
  davranışı korumak için açıkça `privacy.mode: off` yazın.
- Docker Compose: denetim izi `audit` adlı birimdedir (önceden `./logs`). Saklamak istiyorsanız mevcut
  `./logs/audit.jsonl` dosyasını birime taşıyın.
- Demonun kendi `.env.demo` dosyası var; `.env.example` artık `WDT_DEMO` ayarlamaz.

### 0.10.0

- İlk açılışta iki yeni indeks oluşturulur: `<önek>-events` ve `<önek>-settings`. `<önek>-*` desenli bir
  Indexer rolü bunları kapsar; `-runs` ve `-knowledge` adlarını tek tek sayan bir rol kapsamaz.
- **Ayarlar**'dan nöbet açılana kadar davranış değişmez.
- SSO modu (`AUTH_DISABLED=true`): kullanıcı başlığı taşımayan istekler `401` alır. Proxy, `USER_HEADER`
  başlıklarından birini iletmelidir.
- Helm: `networkPolicy.enabled` artık `true`; `networkPolicy.ingressNamespace` değerini ayarlayın.
- Eksik depolama indeksi artık sessizce yeniden oluşturulmaz; bkz. [Yedekleme](Backup-TR).
- İlk yedeği alın; hatırlatma yükseltmeden itibaren sayar.

### 0.9.2

- Tarayıcının kökeni uygulamanın gördüğü sunucu adı değilse düğmeler `403` "cross-origin request refused"
  döner: `WDT_TRUSTED_ORIGINS` ayarlayın.
- Üretim modunda, denetim izi yazılamadığı sürece durum değiştiren istekler `503` döner.

Daha eski sürümler: değişiklik günlüğü.

Ayrıca: [Yedekleme](Backup-TR) · [Uyumluluk](Compatibility-TR) · [Sorun giderme](Troubleshooting-TR)

*0.11.1 için geçerlidir · gözden geçirme: 2026-11-12*

---

[English](Upgrade) · [Türkçe](Upgrade-TR)
