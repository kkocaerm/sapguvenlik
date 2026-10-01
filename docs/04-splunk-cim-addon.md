---
layout: default
title: "Bölüm 4: Splunk CIM Modeli ve Add-on Use-Case'leri"
nav_order: 4
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/04-splunk-cim-addon/
---


## Bu Bölümün Konumu: Aktarımdan Tespite Geçiş

Bölüm 3'te logların SAP'tan Splunk'a nasıl aktarıldığını, connector mimarisini, CIM mapping'in ne olduğunu ve parsing sürecindeki kritik sorunları işledik. Artık elimizde şunlar var: kaynakta doğru şekilde üretilen loglar (Bölüm 2), bunları taşıyan ve normalize eden bir entegrasyon katmanı (Bölüm 3). Sıra bunların üzerine detection kuralları inşa etmeye geldi.

Ama hemen özel kural yazmaya başlamadan önce, SAP Add-on for Splunk'ın kutusundan ne çıktığını ve CIM data model'inin SAP bağlamında tam olarak nasıl çalıştığını anlamak gerekiyor. Çünkü "hazır ne var, ne yazmamız lazım" sorusuna cevap vermeden yazılan özel kurallar çoğunlukla Add-on'un zaten yaptığını tekrar eder ya da Add-on'un yapamadığı şeyi yapmaya çalışırken temel eksikliği atlıyor. Bu bölüm, Bölüm 5'teki özel SPL kurallarına girmeden önce o haritayı çıkarmak için var.

## CIM Nedir ve SAP Bağlamında Neden Önemli

Splunk CIM (Common Information Model), farklı kaynaklardan gelen event'leri standart alan adlarıyla tanımlayan bir şema çerçevesidir. Bir Windows logon olayındaki "kullanıcı adı" alanı ile SAP logon olayındaki kullanıcı adı alanı farklı ham isimler taşır; CIM ikisini de `user` adıyla çağırır. Bu normalizasyon, korelasyon kurallarının belirli bir kaynağa değil, soyut bir veri modeline bakmasını sağlar.

SAP bağlamında CIM'in kritik değeri şudur: Bölüm 1'de tanımladığımız yedi senaryo, SAP'tan gelen verinin yanı sıra başka kaynaklardan gelen veriyle korelasyon gerektirebildiğinde — örneğin aynı kullanıcının SAP'ta SAP_ALL aldığı anda Active Directory'de de yetki değişikliği geçirip geçirmediği — bu korelasyon ancak her iki kaynağın da aynı CIM alanlarına eşlenmiş olması durumunda mümkündür. CIM'siz bir entegrasyonda her kaynak kendi adacığında kalır.

### Data Model Kavramı: Pivot'un Temel Birimi

CIM'deki temel yapı **data model**'dir — her biri belirli bir olay kategorisini (Authentication, Change, Network Traffic gibi) modelleyen, kendi alanları olan bir şema. Bu şemalar üzerinde "pivot" yapılır: ham SPL sorgularının tersine, pivot arayüzü veya `tstats` komutu, normalleştirilmiş alan adları üzerinden hızlı ve index'i atlayan sorgular çalıştırır.

Ama bu hızın bir önkoşulu var: **data model acceleration**. Splunk, bir data model için önceden hesaplanmış bir summary index tutabilir (TSIDX dosyaları); bu sayede `tstats` komutunun ham veriyi okumak yerine bu özeti sorgulaması mümkündür. SAP verisi bu özetlere dahil değilse, CIM tabanlı sorgular ham SPL kadar yavaş çalışır — veya hiç sonuç dönmez.

## SAP İçin İlgili CIM Data Model'leri

SAP Add-on for Splunk, birkaç farklı CIM data model'ine eşleme yapar. Her birinin SAP bağlamındaki kapsamı ve sınırları ayrı ayrı değerlendirilmelidir.

### 1. Authentication Data Model

SAP'tan gelen en hacimli ve en kritik data model eşlemesi budur. SAP Security Audit Log'daki logon olayları (dialog ve RFC), başarılı ve başarısız girişler bu modele eşlenir.

**Model üzerindeki temel alanlar:**

| Alan | Açıklama | SAP Bağlamındaki Önemi |
|---|---|---|
| `user` | Giriş yapan kullanıcı | SAP kullanıcı ID'si (örn. BASISUSR, RFC_CONNECTOR) |
| `src` | Bağlantı kaynağı IP/hostname | Terminal veya kaynak sistem |
| `dest` | Hedef sistem | SAP sistem ID'si (PRD, DEV vb.) |
| `app` | Uygulama/client | SAP mandant numarası (100, 200 vb.) |
| `action` | Sonuç | "success" veya "failure" |
| `signature` | Olay tanımı | Olay kodu (AU1, AU3 vb.) |
| `signature_id` | Olay kodu | SAP olay kategorisi kodu |
| `authentication_method` | Doğrulama yöntemi | Dialog, RFC, CPIC, SAML vb. |
| `session_id` | Oturum ID'si | SAP logon ID (mümkünse) |

**Bu model neyi yakalar:** Başarılı ve başarısız dialog giriş denemeleri, RFC/CPIC logon'ları, oturum açma/kapatma olayları.

**Bu model neyi kaçırır:** Başarılı bir girişten sonra yapılan transaction/T-code kullanımı, yetki atamaları, tablo erişimleri. Authentication data model yalnızca *giriş* olaylarını modeller; giriş sonrasında neler yapıldığını modellemeye çalışmak bu data model'in kapsamı dışındadır.

**Hızlandırma (acceleration) notu:** Dialog ve RFC giriş olaylarının hacmi yüksek olduğundan, bu data model için acceleration açılması önerilir. Ancak SAP mandant bilgisinin (`app` alanı) acceleration summary'sine dahil edildiğinden emin olunmalıdır — aksi halde production/test ayrımı özet sorguların sonuçlarında kaybolur.

### 2. Change Analysis Data Model

Kullanıcı hesabı değişiklikleri, yetki/rol atamaları, sistem yapılandırma değişiklikleri ve tablo değişiklikleri bu modele eşlenir. SAP güvenliği açısından özellikle kritik bir modeldir çünkü Bölüm 1'deki senaryoların büyük çoğunluğu (1, 2, 4, 5, 7) doğrudan bir *değişiklik* olayıyla temsil edilir.

**Model üzerindeki temel alanlar:**

| Alan | Açıklama | SAP Bağlamındaki Önemi |
|---|---|---|
| `user` | Değişikliği yapan kullanıcı | SAP kullanıcı ID'si |
| `object_category` | Değiştirilen nesne tipi | Tablo adı, nesne sınıfı (USER, ROLE, TABLE vb.) |
| `object_id` | Nesne tanımlayıcısı | Etkilenen SAP kullanıcısı/kaydı/satırı |
| `action` | Yapılan işlem | "modified", "created", "deleted" |
| `old_value` | Değişiklik öncesi değer | Önceki profil, eski değer |
| `new_value` | Değişiklik sonrası değer | Yeni profil, yeni değer (örn. SAP_ALL) |
| `change_type` | Değişiklik kategorisi | Otomasyon mı, manuel mi |
| `command` | Kullanılan araç/T-code | SU01, SU10, SE16N vb. |
| `status` | Değişiklik sonucu | Başarılı/başarısız |

**Bu modelin SAP'taki iki kaynağı vardır:** Kullanıcı/yetki değişiklikleri Security Audit Log'dan gelir (AU1 kategorisi); iş nesne değişiklikleri ise Change Documents (CDHDR/CDPOS) üzerinden gelir. İki kaynağın aynı modele eşlenmesi tutarlıdır ama parsing seviyesinde her iki kaynak farklı sourcetype kullandığından (`sap:audit` ve `sap:change`), model acceleration söz konusu olduğunda her iki sourcetype'ın da modele dahil edildiğini doğrulamak gerekir.

**Bu model neyi kaçırır:** DBTABLOG üzerinden takip edilen raw tablo değişiklikleri, Change Documents'ın tanımlanmadığı özel (Z-) nesnelerdeki değişiklikler. Bu, tablo loglamanın ayrı ve tamamlayıcı bir kaynak olarak tutulmasının sebebidir.

### 3. Network Traffic Data Model

SAP Gateway üzerinden geçen RFC çağrıları, sistemler arası trafik bu modele eşlenir. Add-on bu eşlemeyi Gateway Log sourcetype'ı üzerinden yapar.

**SAP bağlamındaki kritik alanlar:**

| Alan | Açıklama |
|---|---|
| `src` | RFC çağrısını yapan kaynak sistem |
| `dest` | RFC çağrısının hedef SAP sistemi |
| `transport` | Protokol (RFC, CPIC, HTTP) |
| `signature` | Çağrılan fonksiyon grubu/modül |
| `action` | Sonuç (allowed, blocked) |
| `bytes_out` | Veri transferi miktarı (mümkünse) |

Bu model, Bölüm 1 Senaryo 3 (RFC trust suistimali) için birincil tespit katmanıdır. Ancak Gateway loglama yapılandırılmamışsa (Bölüm 2'deki yaygın hata listesinde yer aldığı gibi), bu model tamamen boş kalır.

### 4. Endpoint / Inventory Data Model (Tamamlayıcı)

SAP doğrudan bir "endpoint" değildir, ama bazı kurumlar SAP uygulama sunucu bilgilerini (hostname, IP, sistem ID) bu modele ekleyerek diğer kaynaklarla (örneğin network cihazları, endpoint detection) korelasyon kurar. Bu kullanım kuruma özgüdür ve Add-on'un standart eşlemesinde yer almaz; özelleştirilmiş bir lookup tablosu ve ek transforms.conf tanımı gerektirir.

### Data Model'lerin Birlikte Kullanımı: Bir Örnek

Senaryo 4'teki hesap devralma örneğini (şifre sıfırlama → başka hesapla logon → yetkisiz onay) CIM data model'leri üzerinden izlemek şöyle görünür:

```
┌─────────────────────────────┐
│  Change Analysis Data Model  │
│  user = HELPDESKUSR          │
│  action = modified           │
│  object_id = FINANCEUSER     │
│  object_category = PASSWORD  │
└────────────────┬────────────┘
                 │ Zaman sırası: Şifre sıfırlandı
                 ▼
┌─────────────────────────────┐
│  Authentication Data Model   │
│  user = FINANCEUSER          │
│  action = success            │
│  src = HELPDESKUSR_terminal  │
│  (normalde farklı terminal)  │
└────────────────┬────────────┘
                 │ Zaman sırası: Anormal terminalle giriş
                 ▼
┌─────────────────────────────┐
│  Change Analysis Data Model  │
│  user = FINANCEUSER          │
│  action = modified           │
│  object_category = PAYMENT   │
│  (onay kaydı değişti)        │
└─────────────────────────────┘
```

Bu üç adımı bağlayan bir korelasyon kuralı, tek bir data model üzerinde değil üç model arasında çalışır. Bu, CIM'in gerçek gücünün ortaya çıktığı noktadır — ve Add-on'un hazır use-case'lerinin büyük çoğunluğunun tek model üzerinde durduğu için kaçırdığı senaryodur.

## SAP Add-on for Splunk: Hazır İçerik Envanteri

SAP Add-on for Splunk, kurulumla birlikte bir dizi hazır içerik sunar. Bu içeriği doğru değerlendirmek için iki kategoriyi ayırt etmek gerekir: **teknik içerik** (props.conf, transforms.conf, lookups — parsing altyapısı) ve **operasyonel içerik** (saved searches, dashboards, alerts — detection ve görünürlük).

### Teknik İçerik (Altyapı)

Add-on'un en sağlam yanı teknik altyapısıdır:

**props.conf** — Her sourcetype için zaman damgası formatı, karakter seti, satır sonu karakteri, alan ayrıştırma tanımları. Bu dosya doğru yapılandırılmış ve SAP sisteminin parametreleriyle uyumlu hale getirilmişse, ham SAP logunu Splunk'a taşır taşımaz parse edilmiş alanlara dönüştürür.

**transforms.conf** — Alan çıkarma (field extraction) tanımları, lookup table referansları, sourcetype yönlendirme kuralları. Özellikle SAP olay kodu (AU1, AU3 vb.) ile olay açıklaması arasındaki eşlemeyi sağlayan lookup tabloları burada tanımlanır.

**SAP Olay Kodu Lookup Tablosu** — Bu, Add-on'un en değerli bileşenlerinden biridir: SAP'ın sayısal/kısa olay kodlarını (AU1, AU3, AUW vb.) insan tarafından okunabilir açıklamalarla eşler. Bu tablo olmadan, SIEM'de "AU1" gören bir analist bunun "kullanıcı master kaydı değişikliği" olduğunu bilemez.

**CIM field aliases** — Yukarıda anlattığımız CIM data model eşlemelerini gerçekleştiren alias tanımları. Örneğin `AuSubNum` alanının CIM `user` alanına eşlenmesi burada tanımlanır.

### Operasyonel İçerik: Hazır Saved Searches ve Dashboards

Add-on ve SAP için hazırlanmış içerik paketleri, kurumdan kuruma değişen lisans ve versiyon kombinasyonlarına bağlı olarak farklı sayı ve derinlikte saved search içerir. Tipik olarak şu kategorilerde hazır içerik sunulur:

**Başarısız logon yoğunluğu:** Belirli bir zaman penceresi içinde belirli bir kullanıcı için eşik değerini aşan başarısız giriş denemelerini raporlar. Klasik bir brute-force veya credential stuffing göstergesidir.

```spl
-- Tipik yapı (Add-on'un saved search mantığı) --
index=sap_audit sourcetype="sap:audit"
| search action="failure" AND signature_id IN ("AU3","AU1")
| bucket _time span=5m
| stats count AS failure_count BY user, src, _time, sap_system, sap_client
| where failure_count >= 5
| table _time, user, src, sap_system, sap_client, failure_count
```

**Kritik T-code kullanımı:** SE16, SE16N, SU01, SU10, SM59, SA38 gibi yüksek riskli transaction'ların kullanımını loglar ve raporlar. Add-on genellikle bu T-code'ları içeren bir lookup listesi ile birlikte gelir; listedeki bir T-code çalıştırıldığında kayıt oluşturulur.

**Kullanıcı master kaydı değişiklikleri:** AU1 kategorisindeki olayları filtreler; yeni kullanıcı oluşturma, yetki/profil atama, parola değişikliği gibi olaylar raporlanır.

**Generic/servis hesabı interaktif logonu:** Normalde yalnızca RFC veya background job için kullanılması gereken sistem/servis hesaplarının (genellikle isim kalıbıyla tanımlanır) dialog logon yapması anomalidir. Add-on bu hesapları tanımlayan bir lookup tablosu referans alarak bu kuralı çalıştırır.

**RFC logon anomalileri:** Belirli bir sistemden beklenmedik sayıda veya beklenmedik bir fonksiyon grubu için RFC bağlantısı geldiğinde uyarı üretir.

**Sistem parametresi değişikliği:** Profil parametre değişikliklerini (özellikle güvenlikle ilgili parametreler) takip eder.

### Add-on'un Güçlü Yanları

**Zaman kazandıran altyapı:** Sıfırdan bir SAP SIEM entegrasyonu kuruyorsanız, Add-on'un props.conf ve transforms.conf tanımlarını sıfırdan yazmak yerine buna dayandığınızda aylarca zaman kazanırsınız.

**Olay kodu normalizasyonu:** SAP'ın olay kodu terminolojisini Splunk'a taşıması, analistlerin ham SAP dokümantasyonuna sürekli başvurmasını önler.

**CIM uyumu:** Doğru yapılandırıldığında, SAP verisi diğer kaynaklarla (Windows, Linux, network) korelasyona hazır hale gelir.

**Başlangıç use-case seti:** Hiçbir şeyden başlamak yerine, yaygın senaryolar için bir başlangıç noktası sağlar.

### Add-on'un Sınırları ve Boşlukları

Bu bölümün en önemli kısmı burasıdır, çünkü Add-on'un sınırlarını bilmeden "SIEM kuruldu, SAP korunuyor" yanılgısına düşmek kolaydır.

**Sınır 1 — Tek model, tek olay:** Hazır use-case'lerin büyük çoğunluğu tek bir data model üzerinde ve tek bir event tipine bakarak çalışır. Yukarıda gösterdiğimiz gibi, Senaryo 4 (hesap devralma) üç ayrı model üzerinde ardışık olayların korelasyonunu gerektiriyor — bu, Add-on'un hazır içeriğinin kapsamı dışında.

**Sınır 2 — SAP bağlamı yok:** Add-on'un saved search'leri, "bu T-code'u çalıştırmak bu kullanıcı için normal mi" sorusunu sormaz. Bir finans kullanıcısının SE16N ile BKPF tablosuna (muhasebe belgesi başlıkları) bakması farklı risk taşır; bir Basis yöneticisinin aynı şeyi yapması farklıdır. Bu bağlam bilgisi — hangi kullanıcı grubu için hangi T-code normaldir — kuruma özgüdür ve hiçbir hazır Add-on tarafından bilinemez.

**Sınır 3 — Workflow ve SoD körlüğü:** Add-on, SAP'ın workflow motoru veya SoD matrisine erişimi olmadığından, Senaryo 5 (SoD ihlali) ve Senaryo 7 (workflow vekalet suistimali) için anlamlı bir hazır kural içermez. Bu senaryolar için GRC entegrasyonu veya özel lookup tabloları gerekir.

**Sınır 4 — Custom (Z-) nesneler kapsam dışı:** Add-on, standart SAP T-code ve tablo listesini bilir; kurumun geliştirdiği Z-transaction'lar veya Z-tablolar bu listelerin dışındadır. Z-nesnelerin Add-on'un kritik T-code listesine manuel olarak eklenmesi gerekir.

**Sınır 5 — Threshold değerleri kurum bağlamından kopuk:** "5 dakikada 5 başarısız giriş" eşiği, yüzlerce kullanıcının paralel oturduğu büyük bir SAP sisteminde aşırı gürültülü olabilir; 10 kullanıcılı küçük bir sistem için ise çok gevşek. Add-on bu eşikleri siz ayarlayana kadar anlamlı değildir.

**Sınır 6 — Multi-client bağlamı sınırlı:** Bazı hazır use-case'ler, aynı olayın hangi client'ta gerçekleştiğini alarm metninde yeterince ön plana çıkarmaz. Production ve test client'ındaki aynı olay, farklı aksiyon gerektirirken aynı format ve öncelikte raporlanabilir.

## Data Model Acceleration: Performansın Önkoşulu

CIM tabanlı sorgular ve Bölüm 5'te yazacağımız bazı detection kuralları, veri hacmi büyüdükçe `tstats` komutuna ihtiyaç duyacak — bu da data model acceleration olmadan gerçek zamanlı alarm olarak çalışamayacakları anlamına gelir.

SAP verisi için acceleration yapılandırırken dikkat edilmesi gerekenler:

**Acceleration'ı açmadan önce:** Index ve sourcetype tanımlarının doğru ve kararlı olması gerekir. Eğer parsing hâlâ değişiyorsa (yeni bir SAP sistemi eklendi, yeni bir sourcetype tanımlandı), acceleration'ı açmak için beklemek daha iyidir — parsing değişikliği acceleration summary'sini geçersiz kılır ve yeniden oluşturulması hem zaman hem kaynak harcar.

**Hangi data model'ler için:** En kritik iki model Authentication ve Change Analysis'dir. Network Traffic modeli, Gateway loglama hacmine göre karar verilmelidir.

**Saklama süresi:** Data model acceleration summary'sinin saklama süresi, detection kurallarının ne kadar geriye baktığıyla uyumlu olmalıdır. "Son 90 günde ilk kez SAP_ALL alan kullanıcılar" gibi bir kural, 90 günlük acceleration gerektirir.

**SAP system ve client alanları:** Acceleration summary oluşturulurken `sap_system` ve `sap_client` alanlarının summary'ye dahil olduğunu doğrulamak kritiktir — sonradan bu alanlar eksik bulunursa summary yeniden oluşturmak gerekir.

## Hazır Use-Case'lerden Özel Kurallara: Önceliklendirme Haritası

Add-on'un hazır içeriğini değerlendirdikten sonra, neyin yeterli neyin yetersiz kaldığını netleştiren bir harita çıkarmak, Bölüm 5'e doğru ilerlemenin en doğru yoludur:

| Use-Case | Add-on Hazır İçerik | Yeterli mi? | Bölüm 5'te Özel Kural |
|---|---|---|---|
| Başarısız logon yoğunluğu | Var | Eşik ayarı gerektirir | Opsiyonel (ince ayar için) |
| Servis hesabı interaktif logon | Var | Lookup tablosu güncel tutulmalı | Opsiyonel |
| Kritik T-code kullanımı | Var (standart liste) | Z-T-code'lar eksik | Evet — Z-T-code eklenmeli |
| SAP_ALL atama (Senaryo 1) | Kısmi (user change var) | SAP_ALL özelinde filtre yok | Evet — özel filtre |
| Debug & Replace (Senaryo 2) | Yok | — | Evet — kritik |
| RFC trust suistimali (Senaryo 3) | Kısmi (RFC anomali) | Yeterince bağlamsal değil | Evet — kaynak sistem bağlamı |
| Şifre sıfırlama + logon (Senaryo 4) | Parçalı (her olay ayrı) | Korelasyon yok | Evet — çapraz model korelasyon |
| SoD ihlali (Senaryo 5) | Yok | — | Evet — GRC entegrasyonu ile |
| Client copy (Senaryo 6) | Yok | — | Evet — sistem yönetimi odaklı |
| Workflow vekalet (Senaryo 7) | Yok | — | Evet — change docs + onay |
| Audit log kapatılması (meta) | Kısmi | Yeterince önceliklendirilmemiş | Evet — en yüksek öncelik |

Bu tablo Bölüm 5'in çerçevesini oluşturuyor: Add-on'un "yeterli" veya "opsiyonel" dediğimiz satırları ince ayar ve threshold optimizasyonu gerektiriyor; "Evet — özel kural" satırları ise ya kurumun kendi lookup tablolarını, ya çapraz model korelasyonu ya da Add-on'un hiç kapsamadığı senaryolara özel SPL mantığı gerektiriyor.

## Lookup Tablolarının Rolü: Add-on'u Kurumunuza Uyarlamak

Add-on'un hazır use-case'lerini gerçekten işlevsel kılmanın en pratik ve en sık atlanan yolu, Add-on'un referans aldığı **lookup tablolarını kurum gerçekliğiyle doldurmaktır.** Bu tablolar şunları içerir:

**Kritik T-code listesi:** Add-on'un izlediği yüksek riskli transaction listesi. Kurumun kendi geliştirdiği Z-T-code'lar bu listeye manuel olarak eklenmelidir. Ayrıca iş birimine özel T-code'lar (sadece finans ekibinin kullandığı belirli raporlar gibi) da değerlendirilmelidir.

```csv
tcode,description,risk_level,expected_user_groups
SE16N,Generic Table Browser,CRITICAL,BASIS
SU01,User Maintenance,CRITICAL,BASIS,SECURITY
SE38,ABAP Editor,CRITICAL,DEVELOPMENT
ZFI_RPT01,Özel Finans Raporu (Z),HIGH,FINANCE
ZHR_PAY,Özel Bordro İşlemi (Z),CRITICAL,HR
```

**Servis/generic hesap listesi:** Hangi kullanıcı ID'lerinin teknik hesap olduğu (interaktif logon yapmaması gereken), hangi sistemlere hangi RFC hesabının bağlanmasının beklendiği bilgisiyle doldurulur.

**Kritik kullanıcı grubu listesi:** SAP_ALL, S_DEVELOP, S_USER_GRP gibi kritik yetkilere sahip kullanıcıların listesi. Bu liste statik değildir; otomatik bir yetki sorgusundan günlük güncellenmesi idealdir.

**Normal çalışma saatleri ve lokasyon:** Hangi kullanıcı grubunun hangi saatler ve hangi terminal/IP aralığından bağlanmasının bekleneceği. Bu tablo sayesinde "finans hesabı mesai dışında SAP'a bağlandı" kuralı, false positive üretmeden çalışabilir.

**Hassas tablo listesi:** DBTABLOG'dan gelen değişiklik olaylarını değerlendiren kurallarda, hangi tablolara yapılan değişikliğin hangi risk seviyesinde kabul edileceği bilgisi.

Bu lookup tablolarını canlı tutan bir otomasyon olmadan, tablolar zamanla bayatlar ve use-case'ler giderek artan false positive veya false negative üretmeye başlar. Bölüm 6'da operasyonel güvenlik bağlamında bu tabloların bakım döngüsünü de ele alacağız.

## Splunk ES (Enterprise Security) Entegrasyonu

Kurumun Splunk ES lisansı varsa, SAP verisi bu platformun ek yeteneklerinden yararlanabilir: **Adaptive Response** (alarm üzerine otomatik aksiyonlar, örneğin bir hesabın kilitlenmesi için Basis ekibine otomatik ticket açılması), **Asset ve Identity Framework** (SAP kullanıcılarının CMDB/AD ile eşleştirilmesi), **Risk-Based Alerting** (tek bir olayın değil, zamanla biriken risk puanının alarm üretmesi — özellikle Senaryo 4 ve 7 gibi çok adımlı insider threat senaryoları için).

Risk-Based Alerting SAP bağlamında özellikle değerlidir: aynı kullanıcı için "mesai dışı giriş (+10 puan)", "kritik T-code kullanımı (+20 puan)", "normalde bağlanmadığı bir client'ta oturum (+30 puan)" gibi olaylar tek tek alarm üretmeyebilir ama birikince bir risk eşiğini aşar ve analist dikkatini çeker. Bu model, düşük profilli insider threat senaryolarını yakalamak için geleneksel rule-based detection'dan çok daha etkilidir.

Splunk ES'siz bir ortamda bu Risk-Based yaklaşımı emüle etmek için özel bir lookup tablosu ve her saatte bir çalışan bir SPL scheduled search yazılabilir; daha az zarif ama işlevsel bir alternatiftir.

## Bu Bölümden Bölüm 5'e Geçiş

Bu bölümde şunu netleştirdik: Add-on, kurulum ve temel görünürlük için değerli bir başlangıç noktasıdır ama SAP güvenlik izlemesinin gerçek ağırlığını taşıyamaz. Bölüm 1'de tanımladığımız yedi senaryonun beşi için özel SPL kuralları gerekiyor; geri kalan ikisi için ise Add-on'un eşik değerleri ve lookup tabloları kurum gerçekliğiyle güncellenmelidir.

Bir sonraki bölüm, bu haritanın "Evet — özel kural" satırlarını birer birer dolduruyor: her senaryo için somut bir SPL kuralı, o kuralın mantığının açıklaması, neden o şekilde yazıldığı ve kritik senaryolarda QRadar AQL karşılaştırması ile birlikte.
