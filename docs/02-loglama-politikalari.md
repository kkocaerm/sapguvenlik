---
layout: default
title: "Bölüm 2: Loglama Politikaları"
nav_order: 2
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/02-loglama-politikalari/
---


## Neden Bu Bölüm Her Şeyin Önünde Gelir

Bölüm 1'de işlediğimiz yedi senaryonun ortak bir önkoşulu var: hepsi, ilgili olay SAP tarafında *loglanmış* olduğunda anlamlı hale gelir. Bir SIEM ne kadar iyi kurulmuş olursa olsun, ne kadar zekice korelasyon kuralı yazılmış olursa olsun, kaynağında üretilmeyen bir olayı tespit edemez. SAP güvenliğinde en sık karşılaşılan hayal kırıklığı budur: aylar süren bir SIEM entegrasyon projesinin sonunda, "neden SAP_ALL ataması hiç alarm üretmedi" sorusunun cevabının "çünkü o olay sınıfı hiç açılmamıştı" olması.

Bu bölümde SAP'ın sunduğu farklı loglama mekanizmalarını, bunların nasıl yapılandırıldığını, performans ve depolama ile nasıl dengelendiğini ve en sık yapılan yapılandırma hatalarını işliyoruz. Bölüm 3'te bu logların SIEM'e nasıl aktarılacağını göreceğiz — ama önce kaynakta doğru şeyin üretildiğinden emin olmamız gerekiyor.

## SAP'ta Loglama Katmanları: Tek Bir "Audit Log" Yok

SAP'a yeni başlayan bir SOC mühendisinin en sık yaptığı kavramsal hata, "SAP audit log" diye tek bir şeyin var olduğunu düşünmektir. Gerçekte birbirinden bağımsız, farklı amaçlara hizmet eden, farklı şekilde yapılandırılan beş ayrı mekanizma vardır:

| Mekanizma | Neyi Yakalar | Nasıl Yapılandırılır | Tipik Kullanım |
|---|---|---|---|
| Security Audit Log (SAL) | Logon olayları, transaction/report başlatma, kullanıcı yönetimi, sistem yönetimi olayları | SM19 / RSAU_CONFIG, kernel parametreleri | SOC'un ana besleme kaynağı, kimlik ve erişim odaklı |
| System Log (SM21) | Kernel seviyesi olaylar, work process hataları, sistem yeniden başlatmaları | Otomatik, syslog parametreleri ile ayarlanabilir | Sistem sağlığı + güvenlikle kesişen olaylar (örn. tekrarlanan başarısız login'lerin kernel seviyesinde görünmesi) |
| Tablo Loglama (DBTABLOG) | Belirli tablolara yapılan veri değişiklikleri | rec/client parametresi + tablonun teknik ayarlarında "Log data changes" bayrağı | Hassas tablolara (kullanıcı, yetki, banka bilgisi) doğrudan erişimi izleme |
| Change Documents (CDHDR/CDPOS) | İş nesnesi (business object) seviyesinde değişiklikler | Uygulama içinde nesne bazlı yapılandırma (SCDO) | Fonksiyonel değişiklik takibi (örn. tedarikçi banka hesabı değişikliği) |
| Gateway Logging | RFC çağrıları, gateway erişim denemeleri | secinfo/reginfo ACL dosyaları, gw/logging parametresi | Sistemler arası erişim ve RFC istismarlarının izlenmesi |

Bu beş mekanizmayı ayrı ayrı, ama birbirini tamamlayacak şekilde yapılandırmak gerekir. Birini diğerinin yerine kullanmaya çalışmak (örneğin sadece Change Documents'a güvenip Security Audit Log'u ihmal etmek) ciddi kör noktalar yaratır, çünkü her biri farklı bir katmanı görür.

```
┌────────────────────────────────────────────────────┐
│  Kullanıcı / RFC İstemcisi                           │
└───────────────────┬──────────────────────────────────┘
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
   Gateway Log   Security Audit  System Log
   (RFC erişimi)  Log (logon,    (kernel olayları)
                  T-code, admin)
        │            │             │
        └────────────┼─────────────┘
                     ▼
            ABAP Application Server
                     │
        ┌────────────┴─────────────┐
        ▼                           ▼
  Tablo Loglama (DBTABLOG)   Change Documents
  (teknik, generic)          (iş nesnesi bazlı)
        │                           │
        └─────────────┬─────────────┘
                       ▼
              Merkezi SIEM'e Aktarım
                  (Bölüm 3)
```

## Security Audit Log: Ana Omurga

Security Audit Log (SAL), SOC için en kritik besleme kaynağıdır çünkü kimlik doğrulama, yetkilendirme ve sistem yönetimi olaylarının büyük çoğunluğunu kapsar. Eski sistemlerde SM19/SM20 transaction çifti üzerinden yönetilir (SM19 yapılandırma, SM20 görüntüleme); NetWeaver 7.50 ve sonrasında bu, daha esnek bir model sunan **RSAU_CONFIG** ve **RSAU_READ_LOG** transaction'larına evrilmiştir. Konsept aynıdır, arayüz ve bazı yetenekler (örn. veritabanında saklama seçeneği, log bütünlük koruması) genişlemiştir.

### Statik ve Dinamik Yapılandırma

SAL iki şekilde yapılandırılabilir. **Statik yapılandırma**, kernel parametreleri üzerinden tanımlanır ve sistem yeniden başlatıldığında etkinleşir; değişiklik için restart gerekir ama yapılandırma garanti altındadır. **Dinamik yapılandırma**, sistem çalışırken anlık olarak değiştirilebilir ama sistem yeniden başladığında sıfırlanabilir (yapılandırma ayrıca statik olarak kaydedilmediği sürece). Bu ayrım operasyonel açıdan önemlidir: bir kriz anında "hemen şu kullanıcıyı detaylı loglamaya başla" ihtiyacı dinamik yapılandırmayla karşılanır, ama kalıcı politika her zaman statik olarak da kaydedilmelidir — aksi halde bir sonraki restart'ta sessizce kapanan bir loglama kuralıyla karşılaşılır.

### Olay Sınıfları: Neyi Önceliklendirmeli

SAL'ın yakaladığı olaylar kategorilere ayrılır. Tam filtre kodları SAP release'ine göre değişebileceğinden (güncel referans için SAP'ın ilgili güvenlik notlarına bakılmalı), burada kavramsal kategoriler ve SOC açısından önceliklendirme önerisi veriyoruz:

| Olay Kategorisi | Açıklama | Öncelik | Bölüm 1'deki İlgili Senaryo |
|---|---|---|---|
| Logon (Dialog) — başarılı/başarısız | Kullanıcı arayüzü üzerinden giriş denemeleri | Kritik | Senaryo 4 (hesap devralma) |
| Logon (RFC/CPIC) — başarılı/başarısız | Sistemler arası veya servis hesapları ile girişler | Kritik | Senaryo 3 (RFC trust suistimali) |
| Transaction başlatma (yetkisiz deneme) | Bir kullanıcının yetkisi olmayan bir T-code'u çalıştırmaya çalışması | Kritik | Senaryo 1 (yetki suistimali) |
| Kullanıcı master kaydı değişiklikleri | Kullanıcı oluşturma/silme/kilitleme, parola değişikliği, yetki/profil atama | Kritik | Senaryo 1, Senaryo 4 |
| Sistem yönetimi fonksiyonları | Profil parametre değişikliği, audit log'un kendisinin açılıp kapanması | Kritik | Tüm senaryolar (meta-izleme) |
| Report başlatma | Bir ABAP raporunun doğrudan çalıştırılması (SE38/SA38) | Önemli | Senaryo 2 (debug & replace ile ilişkili) |
| Spool ve yazdırma işlemleri | Çıktı/rapor üretimi | Düşük-Orta | Veri sızıntısı bağlamında destekleyici |
| Dijital imza olayları | Onay/imza süreçlerindeki dijital imza kullanımı | Orta | Senaryo 7 (workflow vekalet) ile dolaylı ilişki |

Pratik öneri: bir SAP sisteminde loglamaya sıfırdan başlanıyorsa, önce "Kritik" olarak işaretlenen kategoriler tüm client'larda ve mümkünse tüm kullanıcılar için açılmalı; "Önemli" ve "Orta" kategoriler ise önce kritik kullanıcı grupları (yöneticiler, generic/servis hesapları, geliştirme yetkisi olanlar) için açılıp kademeli olarak genişletilmelidir.

### Filtre Tasarımı: Genişlik ile Gürültü Arasındaki Denge

SAL yapılandırması "filtre" denilen birimlerle yapılır; her filtre bir client, bir kullanıcı (veya wildcard ile kullanıcı grubu) ve bir olay sınıfı kombinasyonunu tanımlar. Eski sistemlerde filtre sayısı sınırlıydı (örneğin 10 ile sınırlı), bu da kapsamı genişletmek isteyen ekipleri zor bir önceliklendirmeye zorluyordu; daha yeni release'lerde bu sınır gevşetilmiştir ama disiplin hâlâ gereklidir.

İki uç durumdan kaçınmak gerekir. Çok dar bir filtre seti (örneğin sadece "başarısız logon" olayları) kritik olayların büyük bir kısmını kaçırır — Bölüm 1'deki Senaryo 1'de SAP_ALL ataması "başarılı" bir kullanıcı master kaydı değişikliğidir ve "başarısız" olayları izleyen bir filtre bunu hiç görmez. Çok geniş bir filtre seti (örneğin tüm client'larda tüm kullanıcılar için tüm olay sınıfları) ise hem performans/disk maliyetini artırır hem de SIEM tarafında anlamlı sinyali gürültüye gömer.

Pratikte önerilen yaklaşım kademelidir: kritik olay kategorileri (logon, kullanıcı yönetimi, sistem yönetimi) tüm kullanıcılar için açık tutulur; generic/servis hesapları (genellikle en yüksek risk taşıyan, en az izlenen hesap tipi) için daha kapsamlı bir filtre tanımlanır; yüksek yetkili kullanıcılar (SAP_ALL, S_DEVELOP sahipleri) için ayrıca rapor/transaction başlatma seviyesinde detaylı loglama eklenir.

### SM19: Adım Adım Yapılandırma

SM19 (veya 7.50+ sistemlerde RSAU_CONFIG) üzerinden bir loglama profili oluşturmak şu adımları içerir:

**Adım 1 — Transaction'a giriş.** SM19 girilir (eski release'lerde doğrudan filtre ekranı açılır; RSAU_CONFIG'de sihirbaz benzeri bir arayüz, "Parameters" ve "Define Filters" sekmeleri ile karşılanır).

**Adım 2 — Profil oluşturma.** "Profile" menüsünden yeni bir statik profil tanımlanır ve anlamlı bir isim verilir (örneğin ZSEC_AUDIT_PROD). Bir sistemde birden fazla profil tanımlanabilir ama herhangi bir anda yalnızca bir profil "aktif statik profil" olabilir.

**Adım 3 — Filtre slotlarının doldurulması.** Her filtre için üç şey tanımlanır: **Client** (belirli bir client numarası veya tüm client'lar için `*`), **Kullanıcı** (belirli bir kullanıcı ID'si, `RFC_*` gibi bir wildcard örüntüsü veya tüm kullanıcılar için `*`), ve **olay sınıfları matrisi** — Dialog Logon, RFC/CPIC Logon, Transaction Start, Report Start, User Master Record Change, System Administration Function, Other Events gibi kategorilerin her biri için ayrı ayrı işaretleme yapılır ve her kategori için kayıt seviyesi (Critical / Important / Non-Critical olaylar) seçilir.

**Adım 4 — Detaylı kayıt seçeneği.** Bazı olay sınıfları (özellikle Report/Transaction başlatma) için "detaylı kayıt" etkinleştirilebilir; bu, sadece "X raporu çalıştırıldı" değil, çalıştırma sırasındaki ek parametre bilgisini de kaydeder. Bu seçenek log hacmini artırdığından, yalnızca yüksek riskli kullanıcı/işlem kombinasyonlarında açılması önerilir.

**Adım 5 — Kaydetme ve aktivasyon.** Filtreler tanımlandıktan sonra profil kaydedilir (Profile > Save) ve ardından aktive edilir (Profile > Activate). Aktivasyon, profili sistemin "geçerli statik profil" olarak işaretler — ama bu, logun hemen üretilmeye başlayacağı anlamına gelmez; bir sonraki adım buna bağlıdır.

**Adım 6 — Kernel parametresi doğrulaması.** `rsau/enable` parametresinin `1` olarak ayarlı olduğu doğrulanmalıdır (genellikle DEFAULT.PFL içinde tanımlanır). Bu parametre olmadan, profil aktif olsa bile audit log hiçbir kayıt üretmez — sahada en sık görülen "profili doğru kurdum ama log gelmiyor" şikayetinin kaynağı genellikle budur.

**Adım 7 — Dağıtım ve restart kararı.** Statik profildeki değişikliklerin tüm application server instance'larında tam olarak etkili olması genellikle bir restart gerektirir. Acil durumlar için SM19 içindeki **Dinamik Yapılandırma** sekmesi kullanılabilir; burada yapılan değişiklik restart beklemeden anında etkin olur, ama sistem yeniden başladığında bu dinamik değişiklik kaybolur — kalıcı olması isteniyorsa aynı değişiklik ayrıca statik profile de işlenmelidir.

**Adım 8 — Çoklu instance doğrulaması.** Birden fazla application server instance'ı olan sistemlerde, her instance kendi yerel audit log dosyasını yazar. Profilin tüm instance'larda etkin olduğunu (ve her instance'ın audit log dosyasının SIEM toplama mekanizması tarafından okunduğunu) doğrulamak gerekir — aksi halde bazı instance'lardan gelen olaylar sessizce kaçırılabilir.

### SM20 / RSAU_READ_LOG: Logu Görüntüleme ve Doğrulama

SM20 (yeni release'lerde RSAU_READ_LOG), yapılandırılmış profilin fiilen ne ürettiğini doğrulamak için kullanılır — bu adım, yapılandırma sonrası mutlaka yapılması gereken bir sağlık kontrolüdür:

**Adım 1 — Tarih/saat aralığı seçimi.** Görüntülenecek zaman penceresi belirlenir; varsayılan olarak genelde güncel gün gösterilir.

**Adım 2 — Client ve kullanıcı filtresi.** Belirli bir client veya tüm client'lar, belirli bir kullanıcı veya wildcard ile bir kullanıcı grubu seçilebilir — bu, "filtrem gerçekten bu kullanıcıyı/clienti kapsıyor mu" sorusunu doğrulamak için kullanılır.

**Adım 3 — Terminal, T-code, olay sınıfı ve önem derecesi filtreleri.** İhtiyaca göre sonuç kümesi daraltılabilir; örneğin sadece "User Master Record Change" sınıfındaki olaylar görüntülenebilir.

**Adım 4 — Sonuçların incelenmesi.** Liste üzerinde bir kayda çift tıklanarak uzun metin (long text) detayı görüntülenir; bu, hangi T-code'un, hangi parametrelerle, hangi kullanıcı tarafından çalıştırıldığını gösterir.

**Adım 5 — Arşivden yeniden okuma.** Eğer ilgili zaman aralığındaki log dosyaları rotate edilip arşivlenmişse, "Reread from archive" seçeneğiyle arşivlenmiş dosyalardan tekrar okuma yapılabilir — bu, retention politikasının pratikte nasıl işlediğini test etmenin de bir yoludur.

**Adım 6 — Dışa aktarma.** Sonuçlar dosyaya veya tabloya aktarılabilir; bu, SIEM'e ulaşan veri ile kaynaktaki veri arasında bir tutarlılık kontrolü (reconciliation) yapmak istendiğinde faydalıdır — Bölüm 3'te bu doğrulamayı nasıl periyodik bir kontrol haline getirebileceğimizi göreceğiz.

 (DBTABLOG) ve Change Documents: İki Farklı Mekanizma, İki Farklı Soru

Bu iki mekanizma sıklıkla birbiriyle karıştırılır ama farklı sorulara cevap verir.

**Tablo Loglama (DBTABLOG)**, teknik ve generic bir mekanizmadır: `rec/client` profil parametresi hangi client'larda loglama yapılacağını belirler, ardından her tablonun teknik ayarlarında (SE13) "Log data changes" bayrağı işaretlenmesi gerekir. Bu mekanizma "bu tabloya kim ne zaman ne yazdı" sorusuna cevap verir ve özellikle SE16N gibi araçlarla yapılan doğrudan tablo erişimlerini yakalamak için kritiktir — Bölüm 1'deki "veritabanı katmanını bypass etme" riskinin doğrudan karşılığıdır.

**Change Documents (CDHDR/CDPOS)** ise iş nesnesi (business object) seviyesinde çalışır ve uygulama mantığına gömülüdür: bir tedarikçi kaydı, bir kullanıcı profili veya bir malzeme master verisi değiştirildiğinde, ilgili nesne için Change Document yapılandırması (SCDO üzerinden) etkinse, "ne değişti, eski değer neydi, yeni değer ne" bilgisi otomatik olarak kaydedilir. Bu mekanizma "bu iş kaydı zaman içinde nasıl değişti" sorusuna cevap verir ve Senaryo 6'daki (client copy) veya tedarikçi banka hesabı değişikliği gibi fonksiyonel risklerin izlenmesinde tablo loglamadan daha anlamlı bağlam sağlar.

İkisi birbirinin yerini tutmaz. Hangi tabloların/nesnelerin loglanacağına dair önceliklendirme örneği:

| Tablo / Nesne | Risk | Önerilen Mekanizma |
|---|---|---|
| USR02 (kullanıcı master, parola hash referansları) | Kimlik suistimali | Tablo Loglama + SAL kullanıcı yönetimi olayları |
| AGR_1251 / AGR_USERS (rol/yetki atamaları) | Privilege escalation | Tablo Loglama |
| LFA1 / LFBK (tedarikçi master, banka bilgisi) | Finansal sahtekarlık (Senaryo 5) | Change Documents (tedarikçi nesnesi için etkin olmalı) |
| T000 (client/mandant tanımları) | Sistem bütünlüğü | Tablo Loglama |
| PA0008 (bordro/ücret verisi) | Veri gizliliği, finansal kayıp | Tablo Loglama, kısıtlı erişim ile birlikte |
| Z* özel (custom) tablolar | Kurum içi geliştirilen kritik veri | Genelde unutulur — ayrıca değerlendirilmeli |

Bu son satır özellikle önemli: çoğu kurumda standart SAP tabloları için loglama düşünülür ama kurumun kendi geliştirdiği Z-tablolar (özellikle finansal hesaplama, entegrasyon ara katmanı veya özel onay mantığı taşıyanlar) bu değerlendirmenin dışında kalır. Bu, generic araçların SAP'ı kaçırmasının bir başka versiyonudur — bu sefer kurumun kendi geliştirme ekibi tarafından yaratılan bir kör nokta.

## Gateway Logging ve RFC Güvenliği

Bölüm 1'deki Senaryo 3, bir RFC trust ilişkisinin kötüye kullanılmasıydı. Bu riski sınırlamak ve izlemek için iki seviye kontrol gerekir.

**Erişim kontrolü:** Gateway'in `secinfo` ve `reginfo` ACL dosyaları, hangi sistemlerin/programların gateway üzerinden hangi fonksiyonları çağırabileceğini sınırlar. Bu dosyalar yapılandırılmamışsa (ki çok yaygın bir durumdur), gateway varsayılan olarak büyük ölçüde izin verici davranır — bu hem bir sertleştirme (hardening) hem de bir loglama sorunudur, çünkü kontrolsüz erişim genellikle yeterince loglanmış erişim de değildir.

**Loglama:** `gw/logging` parametresi ve ilgili izleme araçları (SMGW) ile gateway üzerinden yapılan çağrılar kaydedilebilir. Bu loglar, hangi sistemin hangi fonksiyon modülünü ne zaman çağırdığını gösterir ve trust ilişkilerinin fiili kullanım örüntüsünü ortaya çıkarır — Senaryo 3'teki gibi bir kötüye kullanımı yakalayabilecek tek mekanizma çoğu zaman budur, çünkü network seviyesinde trafik tamamen "normal" görünür.

Bu ikisi birlikte düşünülmeli: sadece loglamak (ACL olmadan) saldırıyı durduramaz, sadece ACL koymak (loglama olmadan) ileride "bu kısıtlama neden var, ne işe yaradı" sorusuna cevap veremez ve anomali tespiti için veri sağlamaz.

## Sistem Logu (SM21): Audit Log'un Tamamlayıcısı

System Log, kernel seviyesinde çalışır ve work process hataları, sistem yeniden başlatmaları, bazı düşük seviye güvenlik olaylarını (örneğin tekrarlanan başarısız login denemelerinin kernel seviyesinde tetiklediği uyarılar) yakalar. SAL ile karıştırılmamalıdır — SAL uygulama seviyesinde, kullanıcı ve yetkilendirme odaklı çalışırken, SM21 daha alt seviyede, sistem sağlığı ile kesişen bir görünüm sunar.

SOC için pratik değeri şu noktada ortaya çıkar: bir saldırgan veya kötü niyetli bir iç kullanıcı, SAL'ı geçici olarak devre dışı bırakmaya çalışırsa (bu, ileride bahsedeceğimiz bir meta-tehdit), bu işlemin kendisi bazı durumlarda sistem logunda da bir iz bırakabilir. İki log kaynağını birlikte değerlendirmek, tek bir kaynağa güvenmekten daha dayanıklı bir izleme sağlar.

### SM21'in Yapılandırma Mantığı: SAL'dan Farkı

SM21'in yapılandırma modeli SAL'dan temelde farklıdır. SAL'da "hangi olayı loglayacağım" sorusunu filtre tanımlayarak siz cevaplarsınız; System Log'da ise kernel, önceden tanımlı bir olay setini otomatik olarak üretir ve sizin yapabileceğiniz şey bu üretimin hedefini, hacmini ve görünürlük kapsamını ayarlamaktır. Yani SM21'de "filtre oluşturma" değil, **parametre ve görüntüleme kriterleri ayarlama** söz konusudur. İlgili parametreler şunlardır (tam parametre adları ve varsayılan değerleri kernel sürümüne göre değişebilir; kesin isimler için ilgili SAP Basis dokümantasyonu veya güncel SAP Notes referans alınmalıdır):

| Parametre Alanı | Ne İşe Yarar |
|---|---|
| Yerel log dosyası yolu ve boyutu | Sistem logunun diskte nerede ve ne büyüklükte tutulacağını belirler |
| Eski dosya/rotasyon ayarları | Dosya dolduğunda kaç eski jenerasyonun saklanacağını belirler — retention için kritik |
| Merkezi sistem grubu (central system log) ayarları | Bir sistem grubundaki birden fazla instance'ın logunu tek bir merkezi instance'da toplamayı sağlar (legacy bir mekanizma, ama hâlâ bazı landscape'lerde kullanılır) |
| Merkezi log güvenlik seviyesi | Merkezi log iletiminin hangi düzeyde korunduğunu belirler |

### SM21: Adım Adım Görüntüleme ve Analiz

**Adım 1 — Transaction'a giriş.** SM21 girilir; varsayılan ekran genelde son birkaç saatin/günün özetini gösterir.

**Adım 2 — Zaman aralığının genişletilmesi.** "Tarih/Saat" seçim alanından, incelenecek dönem (örneğin son 7 gün) tanımlanır.

**Adım 3 — Detaylı seçim kriterleri.** "Diğer seçim kriterleri" (further selections) ekranından client, kullanıcı, transaction code, work process türü ve **problem sınıfı** (önem derecesi — çok kritik, kritik, sadece bilgi gibi seviyeler) filtrelenebilir. Bir SOC analistinin günlük kullanımında en sık başvurulan filtre, önem derecesini "kritik ve üzeri" ile sınırlamaktır; aksi halde rutin sistem mesajları arasında anlamlı sinyal kaybolur.

**Adım 4 — Sonuç listesinin incelenmesi.** Listede bir kayda çift tıklanarak uzun açıklama metni (long text) görüntülenir; bu, olayın tam bağlamını (hangi work process, hangi kullanıcı, hangi hata kodu) verir.

**Adım 5 — Instance kapsamının belirlenmesi.** Birden fazla application server instance'ı olan sistemlerde, görüntüleme "tüm instance'lar" veya belirli bir instance ile sınırlandırılabilir. Merkezi sistem grubu yapılandırılmışsa, tüm grup tek bir görünümde incelenebilir.

**Adım 6 — Arşivlenmiş dosyalardan yeniden okuma.** Eski/rotate olmuş dosyalar hâlâ diskte duruyorsa, "Reread old files" benzeri bir seçenekle bu dosyalardan tekrar okuma yapılabilir — SAL'daki arşiv okuma mantığına benzer.

### Özel (Custom) Olayları Sistem Loguna Yazma

ABAP geliştiricileri, kurumun kendi Z-programlarından sistem logu yazmak için ilgili kernel çağrılarını/fonksiyon modüllerini kullanabilir. Bu, kurumun kendi kritik özel işlemlerini de SM21 üzerinden görünür kılmanın bir yoludur. Pratikte bu yaklaşım nadiren tercih edilir; çoğu kurum kendi özel kritik işlemleri için Change Documents veya özel bir Z-tablo loglama mekanizmasını tercih eder, çünkü bu mekanizmalar iş bağlamını (hangi nesne, hangi alan değişti) daha doğal şekilde taşır. Ancak sistem genelinde tek bir "olay zaman çizelgesi" görmek isteyen ekipler için bu seçenek bilinmeye değer bir araçtır.

## Retention, Depolama ve Performans Dengesi

Loglama politikası belirlenirken üç pratik kısıtlama göz önünde bulundurulmalı:

**Performans etkisi.** Security Audit Log'un genel performans etkisi göreceli olarak düşüktür (tipik olarak tek hane CPU/IO yüzdesi mertebesinde), ama yüksek hacimli tablolar için tam tablo loglama (DBTABLOG) açmak ciddi bir IO yükü oluşturabilir. Bu yüzden tablo loglama kararı tablo bazında, hacim ve kritiklik değerlendirmesiyle verilmelidir — "her şeyi logla" yaklaşımı SAP'ta genellikle sürdürülebilir değildir.

**Depolama ve saklama süresi.** Loglar dosya sisteminde veya (7.50 sonrası seçenek olarak) veritabanında saklanabilir; her ikisinin de kapasite planlaması gerekir. Saklama süresi belirlenirken iki farklı ihtiyaç ayrı ayrı düşünülmeli: SOC'un operasyonel ihtiyacı (genellikle SIEM'e aktarıldıktan sonra kaynak sistemde kısa süre tutmak yeterlidir) ve uyumluluk/denetim ihtiyacı (SOX gibi çerçeveler genellikle daha uzun bir asıl kayıt saklama süresi gerektirir — bu konuyu Bölüm 8'de raporlama bağlamında detaylandıracağız).

**SIEM'e aktarım gecikmesiyle uyum.** Bu kritik ve sık atlanan bir noktadır: yerel log dosyası belirli bir boyuta ulaştığında veya belirli bir süre sonunda rotate/arşivlenirse, SIEM tarafındaki toplama mekanizması bu rotasyondan önce logu okuyup aktarmış olmalıdır. Aktarım sıklığı ile yerel rotasyon/saklama süresi arasında bir uyumsuzluk varsa, log SIEM'e ulaşmadan kaybolabilir — bu, "loglama açıktı ama SIEM'de hiçbir şey yok" şikayetinin en sık nedenlerinden biridir. Bu konuyu Bölüm 3'te aktarım mimarisini işlerken tekrar ele alacağız.

## Log Bütünlüğü: Audit Trail'in Kendisi Bir Saldırı Hedefidir

Kritik bir nokta: Security Audit Log'u kapatmak veya filtrelerini değiştirmek, kendisi bir profil parametre değişikliği veya SM19/RSAU_CONFIG üzerinden yapılan bir işlemdir ve doğru yetkilendirme kontrolleri yoksa, yeterli yetkiye sahip biri (örneğin S_ADMI_FCD objesi olan biri) izlemeyi sessizce devre dışı bırakabilir. Bu, klasik bir "kim bekçiyi bekliyor" sorunudur.

İki savunma katmanı önerilir. Birincisi, SAL yapılandırmasını değiştirme yetkisini son derece kısıtlı tutmak ve bu yetkiye sahip kullanıcı sayısını minimumda tutmak. İkincisi — ve daha önemlisi — **audit log'un kendisinin açılıp kapanmasını veya filtrelerinin değiştirilmesini, SAL'ın "Sistem yönetimi fonksiyonları" kategorisi altında ayrıca loglamak ve bu olayı SIEM tarafında en yüksek öncelikli alarm olarak tanımlamak.** Daha yeni SAP release'leri, log dosyalarının bütünlüğünü dijital imza ile koruyan bir mekanizma da sunar; bu, logların sonradan değiştirilip değiştirilmediğinin doğrulanmasını sağlar ve özellikle adli analiz (forensics) senaryolarında değerlidir — Bölüm 7'de bu konuya döneceğiz.

## Yaygın Yanlış Yapılandırmalar

Sahada en sık karşılaşılan loglama yapılandırma hataları şunlardır:

Security Audit Log yalnızca production client'ında açık, ama saldırı yüzeyinin önemli bir kısmını oluşturan test/sandbox client'larında kapalı — oysa Bölüm 1'deki Senaryo 3 tam olarak böyle bir client'tan başlıyordu.

Filtreler yalnızca "başarısız" olayları kapsıyor; "başarılı" ama anomali olan olaylar (örneğin normalde giriş yapmayan bir servis hesabının başarılı interaktif logonu) tamamen görünmez kalıyor.

Generic/servis hesapları filtre kapsamı dışında tutulmuş — bu hesaplar genellikle en yüksek yetkiye sahip, en az insan gözetimine tabi ve dolayısıyla en riskli hesap tipidir.

Tablo loglama yalnızca standart SAP tablolarında etkin; kurumun kendi geliştirdiği kritik Z-tablolar tamamen kör nokta olarak kalıyor.

Yerel log dosyalarının rotasyon/saklama süresi, SIEM'e aktarım sıklığından daha kısa tutulmuş; bu da loglar SIEM'e ulaşmadan kaybolmasına yol açıyor.

Gateway ACL dosyaları (secinfo/reginfo) hiç yapılandırılmamış veya boş bırakılmış, gateway varsayılan izin verici modda çalışıyor.

Audit log yapılandırmasının kendisindeki değişiklikler ayrıca izlenmiyor — yani izleme mekanizmasının kendisi izlenmeden bırakılmış.

## Bölüm 1 Senaryolarına Geri Bağlantı

Bölüm 1'de işlediğimiz yedi senaryonun, bu bölümde anlatılan hangi mekanizmayla yakalanabileceğini özetlemek faydalı:

| Senaryo | Yakalayan Mekanizma |
|---|---|
| 1 — Unutulan SAP_ALL | Security Audit Log (kullanıcı master kaydı değişikliği) |
| 2 — Debug & Replace ile onay bypass | Security Audit Log (report/debug oturumu) + Change Documents (sonuçtaki kayıt değişikliği) |
| 3 — RFC trust suistimali | Gateway Logging + Security Audit Log (RFC logon) |
| 4 — Şifre sıfırlama ile hesap devralma | Security Audit Log (kullanıcı master kaydı, parola değişikliği) |
| 5 — SoD ihlali (tedarikçi + ödeme onayı) | Change Documents (tedarikçi nesnesi) + ayrıca GRC tabanlı statik analiz (loglama tek başına yetersiz) |
| 6 — Client copy ile veri sızması | Sistem yönetimi olayları (client copy işlemi) + test ortamı erişim logları |
| 7 — Workflow vekalet suistimali | Change Documents (workflow/vekalet ayarları) + dijital imza/onay olayları |

Bu tablo aynı zamanda önemli bir gerçeği gösteriyor: Senaryo 5 gibi bazı riskler, tek başına loglamayla değil, loglama ile statik yetki/yapılandırma analizinin (GRC) birleşiminde yakalanabilir. Loglama her şeyin temelidir ama her şeyin cevabı değildir — bu noktayı Bölüm 6'da operasyonel güvenlik bağlamında tekrar ele alacağız.

## Pratik Başlangıç Noktası: İlk Hafta İçin Minimum Yapılandırma

Sıfırdan başlayan bir ekip için önerilen öncelik sırası:

Birinci adım, tüm production client'larında (ve evet, test/sandbox client'larında da) Security Audit Log'u açmak ve en az "Kritik" olarak işaretlenen olay kategorilerini (logon, kullanıcı master değişiklikleri, sistem yönetimi) tüm kullanıcılar için etkinleştirmek.

İkinci adım, generic/servis hesapları için ayrı ve daha kapsamlı bir filtre tanımlamak — bu hesaplar varsayılan kapsamın dışında kalmamalı.

Üçüncü adım, en kritik 10-15 tabloyu (kullanıcı/yetki tabloları, finansal master veri, kurumun kendi Z-tabloları dahil) belirleyip tablo loglamayı bu sette etkinleştirmek; aynı anda tüm tabloları açmaya çalışmamak.

Dördüncü adım, gateway ACL dosyalarını (secinfo/reginfo) en azından "bilinen sistemler" listesiyle başlatmak ve gateway loglamayı açmak.

Beşinci adım, audit log yapılandırma değişikliklerinin kendisini izleyen bir meta-kural tanımlamak — bu, ileride kuracağımız tüm detection mantığının üzerine oturacağı güvenin temelidir.

Bu beş adım tamamlandığında, Bölüm 3'te ele alacağımız SIEM aktarımı için kaynakta anlamlı ve yeterli veri üretiliyor olacak. Bir sonraki bölümde bu logların SAP Add-on for Splunk üzerinden nasıl toplanacağını, QRadar için log source yaklaşımını, normalizasyon sürecinde sık karşılaşılan sorunları (zaman damgası, multi-client bağlamı, encoding) ve veri hacmi/lisans planlamasını işleyeceğiz.
