---
layout: default
title: "Bölüm 6: Operasyonel Güvenlik"
nav_order: 6
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/06-operasyonel-guvenlik/
---


## Detection'dan Operasyona: Neden Bu Bölüm Var

Bölüm 5'te on detection kuralı yazdık. Bu kuralların her biri belirli bir anı — bir SAP_ALL atamasını, bir RFC anomalisini, bir workflow suistimalini — yakalar. Ama bir kurumun SAP güvenlik duruşu, yalnızca o anların tespitine indirgenemez. Detection reaktiftir; bir şey olduğunda görür. Operasyonel güvenlik ise proaktiftir: saldırı yüzeyini daraltır, açıkları kapatır ve detection kurallarının üzerine oturduğu güvenli bir temel inşa eder.

Bu bölümde dört operasyonel alan ele alınıyor: **SAP Security Notes ve patch yönetimi**, **transport onay süreçlerinin SOC'a entegrasyonu**, **SoD matrisinin canlı tutulması**, **RFC ve trust ilişkileri yönetimi**. Bunların her biri hem Basis ekibinin günlük sorumluluğudur hem de SOC'un detection kalitesini doğrudan etkiler — çünkü bir zafiyet yamalanmamışsa, bir transport onaysız production'a geçmişse, bir RFC trust ilişkisi gereksiz yere açık tutulmuşsa, detection kuralları bu boşlukları tek başına kapatamaz.

## SAP Security Notes ve Patch Yönetimi

### SAP Patch Ekosistemi: Neden Standart Patch Yönetiminden Farklı

Kurumsal IT patch yönetimi, genellikle işletim sistemi ve üçüncü taraf yazılım yamalarının aylık döngülerle uygulanması üzerine kuruludur. SAP ortamı bu modele kısmen uyar ama birkaç kritik farkla:

**Security Notes sistemi:** SAP, güvenlik açıklarını "Security Note" olarak yayımlar. Her Note bir SAP sistemine bir ABAP programı, kernel yaması veya yapılandırma değişikliği olarak uygulanır. Notlar SAP Service Marketplace (support.sap.com) üzerinden yayımlanır ve aylık olarak "Security Patch Day" — SAP'ın kendi Patch Tuesday'i, her ayın ikinci Salı günü — kapsamında topluca açıklanır ama kritik notlar arasında döngü dışında (out-of-band) yayımlanabilir.

**Bağımlılık zinciri:** Bir Security Note'un uygulanabilmesi için bazen önce başka bir Note'un veya SP (Support Package) düzeyinin uygulanmış olması gerekir. Bu bağımlılık ağacı, bir yamanın "hemen uygulayın" kategorisinde görünmesine rağmen pratikte önce birkaç SP güncellemesi gerektirmesi anlamına gelebilir.

**Test gerekliliği:** Çoğu SAP Security Note, üretim sistemine uygulamadan önce geliştirme ve test sistemlerinde doğrulanması gereken ABAP değişiklikleri içerir. Bu, Note'un geliştirme sistemine uygulanması, test edilmesi, transport ile test sistemine geçirilmesi ve son olarak production'a taşınması anlamına gelir — yani en hızlı senaryo bile geliştirme-test-production döngüsü kadar sürer.

### Vulnerability Scoring: SAP CVSS ve Önceliklendirme

SAP Security Note'ları, CVSS (Common Vulnerability Scoring System) skoru ile gelir. Ama SAP bağlamında bir CVSS skorunu yorumlamak, network ekipmanı veya işletim sistemi zafiyetinden farklı değerlendirme gerektiren ek bağlam faktörlerini kapsar:

| CVSS Skoru | SAP Bağlamı | Önceliklendirme |
|---|---|---|
| 9.0 – 10.0 (Critical) | Uzaktan kod çalıştırma, kimlik doğrulama bypass, SAP Gateway üzerinden sömürülebilir | Acil — test döngüsü hızlandırılmalı, iş onayı alınarak sıkıştırılmış test penceresiyle production'a uygulanmalı |
| 7.0 – 8.9 (High) | Kimlik doğrulamalı ancak düşük yetkiyle sömürülebilir, yetkisiz veri erişimi | Öncelikli — mevcut SP döngüsüne dahil, 30 gün içinde |
| 4.0 – 6.9 (Medium) | Kimlik doğrulama gerektirir, etkisi sınırlı | Normal döngü — bir sonraki SP güncellemesinde |
| 0.1 – 3.9 (Low) | İstismar edilebilirlik son derece düşük | SP döngüsünde değerlendirme, ertelenemez değil |

**Bağlam faktörleri:** CVSS skoru evrenseldir ama SAP ortamına özgü koşullar skoru yukarı veya aşağı taşıyabilir. Bir zafiyet, internet erişimine açık SAP Fiori veya SAP Web Dispatcher üzerinden sömürülebiliyorsa, önceliği mutlaka artırılmalıdır. Öte yandan, zafiyetin sömürülmesi için ABAP geliştirme yetkisi gerekiyorsa ve bu yetki zaten son derece kısıtlı tutuluyorsa, gerçek risk skoru düşebilir.

### Patch Yönetimi Süreci: Adım Adım

```
SAP Security Patch Day (her ayın 2. Salısı)
           │
           ▼
Yayımlanan Note'ların değerlendirilmesi
(SAP Note Analyzer veya RSECNOTE raporu)
           │
           ├─→ CVSS ≥ 9.0 → Hızlandırılmış süreç
           │                 (Acil test + onay)
           │
           └─→ CVSS < 9.0 → Normal döngüye dahil
                             (Sprint/bakım penceresi)
           │
           ▼
Geliştirme sistemine uygulama
           │
           ▼
Fonksiyonel ve regresyon testi
(test sisteminde)
           │
           ▼
Test sonuçlarının belgelenmesi
           │
           ▼
Change Advisory Board (CAB) onayı
(veya acil durum değişikliği onayı)
           │
           ▼
Production transport (bakım penceresi)
           │
           ▼
Uygulama doğrulama (RSECNOTE çıktısı)
ve SIEM/SOC bildirimi
```

**RSECNOTE Transaction'ı:** SAP sisteminde çalıştırıldığında, henüz uygulanmamış güvenlik notlarını listeler ve CVSS skorlarını gösterir. Bu raporu aylık olarak çalıştırıp sonuçları bir tracking tablosuna (veya doğrudan SIEM'e besleyerek) yönetmek, patch durumunun görünürlüğünü sağlamanın en pratik yollarından biridir.

### SAP Kernel Güncellemeleri

Security Note'larının yanı sıra SAP Kernel güncellemeleri de düzenli olarak değerlendirilmelidir. Kernel, SAP'ın işletim sistemi ile ABAP runtime arasındaki katmanıdır; kernel zafiyetleri genellikle uygulama katmanı (ABAP) güvenlik notlarından daha kritiktir çünkü işletim sistemi erişimiyle kesişirler.

Kernel güncelleme sıklığı için pratik öneri: mümkünse yılda iki kez (SAP'ın major release döngüleriyle hizalı), kritik kernel güvenlik yamalarında ise out-of-band. Kernel güncellemesi her zaman system restart gerektirdiğinden, bakım penceresi planlaması ve son kullanıcı bildirimi sürece dahil edilmelidir.

### SOC'un Patch Yönetimine Katkısı

Patch yönetimi Basis ekibinin birincil sorumluluğundadır ama SOC'un iki kritik katkısı vardır:

**İstismar girişimi tespiti:** Bir zafiyet bildirilip yamalaması tamamlanana kadar geçen sürede, o zafiyetin aktif olarak istismar edilip edilmediğini izlemek SOC'un sorumluluğundadır. Bu, ilgili zafiyetin teknik detayına göre özel bir SIEM kuralı gerektirebilir — örneğin bir SAP Gateway zafiyeti için normalin dışında Gateway log trafiği izlenmesi.

**Patch doğrulama:** RSECNOTE çıktısı SIEM'e besleniyorsa, "uygulama beklenen" durumdaki kritik notlar için SLA takibi otomatikleştirilebilir: "Bu CVSS 9.0+ note 30 gün önce yayımlandı, hâlâ uygulanmadı" alarmı, patch yönetiminin gecikmesini görünür kılar.

## Transport Yönetimi: Production'a Giden Resmi Yolun Güvenliği

### Transport Nedir ve Neden Risk Taşır

Bölüm 1'de transport sistemini kısaca tanımlamıştık: geliştirme sisteminde hazırlanan kod ve yapılandırma değişikliklerinin test ve production sistemlerine taşındığı mekanizma. Transport Management System (TMS) bu süreci yönetir.

Transport güvenliği risk taşır çünkü production'a giden her transport teorik olarak şunları içerebilir: yeni ABAP kodu (backdoor, kötü amaçlı fonksiyon), yapılandırma değişikliği (güvenlik parametresinin gevşetilmesi), yetkilendirme nesnesi değişikliği (bir role ekstra yetki eklenmesi). Bu risklerin tamamı, transport içeriğinin yeterince incelenmeden production'a geçirilmesiyle gerçekleşir.

### Transport Süreci ve Kontrol Noktaları

```
Geliştirici
    │ Değişikliği geliştirme sisteminde kodlar
    │ ve transport request oluşturur
    ▼
Transport Request (NWDI/TMS)
    │
    ├──→ İçerik incelemesi:
    │     - Hangi programlar/objeler değişti?
    │     - Güvenlik nesnesi var mı? (yetki, kullanıcı, role)
    │     - Custom code security review (Code Vulnerability Analyzer)
    │
    ▼
Test Sistemine İçe Aktarım
    │
    ├──→ Fonksiyonel test (iş birimi)
    ├──→ Güvenlik testi (güvenlik/Basis)
    ├──→ Regresyon testi
    │
    ▼
Change Advisory Board (CAB) Onayı
    │
    ├──→ Standart değişiklik → Normal bakım penceresi
    └──→ Acil değişiklik → Hızlandırılmış onay, post-facto denetim
    │
    ▼
Production'a İçe Aktarım
    │
    └──→ SOC bildirimi (hangi transport, kim onayladı,
                         hangi objeler değişti)
```

### Transport İçerik Analizi: Ne Aranmalı

Her production transportu öncesinde güvenlik açısından şu sorular sorulmalıdır:

**Güvenlik nesnesi içeriyor mu?** Authorization objesi, profil, rol, kullanıcı master kaydı içeren transportlar, yalnızca Basis tarafından değil güvenlik/GRC ekibi tarafından da incelenmelidir.

**Kritik T-code veya fonksiyon modülü içeriyor mu?** Bölüm 5'te tanımladığımız kritik T-code listesini etkileyen değişiklikler ayrıca işaretlenmelidir.

**Code Vulnerability Analyzer (CVA) taraması yapıldı mı?** SAP'ın yerleşik güvenlik kodu analiz aracı (SCI transaction — Code Inspector'ın bir parçası olarak), ABAP programlarındaki SQL injection, authorization bypass, hardcoded credential gibi güvenlik açıklarını tarar. Bu taramanın sonuçları transport onay sürecinin bir parçası olmalıdır.

**Emergency transport prosedürü var mı?** Acil bir üretim sorunu nedeniyle normal onay sürecini atlayarak transport uygulanması gerekiyorsa (emergency transport), bu durum bir exception prosedürüyle belgelenmelidir ve post-facto denetimi zorunludur.

### Transport Olaylarının SIEM'e Entegrasyonu

Transport olayları (bir transport'un production'a uygulanması) Security Audit Log'da sistem yönetimi kategorisinde kayıt üretir. Bu kayıtların SIEM'e beslenmesi, detection açısından iki değer sağlar:

**Zaman damgası korelasyonu:** Bir güvenlik olayı (örneğin yeni bir backdoor fonksiyonunun çağrılması) ile öncesinde uygulanan bir transport arasındaki zamansal ilişki, forensic analizde kritik bir ipucu olabilir.

**Onaysız transport alarmı:** Mesai saatleri dışında, CAB onay kaydı olmadan uygulanan bir transport, alarm üretmelidir:

```spl
index=sap_audit sourcetype="sap:audit"
    sap_client IN ("100","200")
    earliest=-1h latest=now
| search message="*transport*" OR message="*TRANSPORT*"
        OR message="*TP*" OR message="*STMS*"
        OR signature_id IN ("AUW","AU5")
| lookup approved_transports.csv
    transport_id OUTPUT is_approved, approved_by, approval_time
| eval is_offhours=if(
    (tonumber(strftime(_time,"%H")) < 7 OR
     tonumber(strftime(_time,"%H")) > 20),
    "YES","NO")
| eval alarm_trigger=case(
    isnull(is_approved) AND is_offhours="YES",
        "UNAPPROVED_OFFHOURS_TRANSPORT",
    isnull(is_approved),
        "UNAPPROVED_TRANSPORT",
    is_approved="YES" AND is_offhours="YES",
        "APPROVED_BUT_OFFHOURS",
    true(), "NORMAL")
| where alarm_trigger != "NORMAL"
| table _time, user, transport_id, sap_system,
        alarm_trigger, is_approved, approved_by
| sort - alarm_trigger
```

`approved_transports.csv` lookup tablosu, CAB veya change management sisteminden (ServiceNow, Remedy vb.) otomatik olarak beslenmeli; manuel güncellemeden kaçınılmalıdır.

## Segregation of Duties (SoD): Matrisin Canlı Tutulması

### SoD Neden Statik Bir Kontrol Olamaz

Bölüm 5'te SoD ihlali detection kuralı yazdık. Ama o kural, anlık bir snapshot üzerinde çalışıyor ve SoD matrisine bağımlıydı. Matrisin kendisi güncel değilse, kural yanlış sonuç üretir.

SoD matrisinin bakımını zorlaştıran iki dinamik vardır. Birincisi, kurumsal organizasyon değişiklikleri — yeni bir iş süreci, yeni bir T-code kullanımı, yeni bir departman — SoD matrisini etkiler ama bu değişiklik her zaman güvenlik ekibine yansımaz. İkincisi, SAP sistemindeki yetkilendirme modeli değişiklikleri — yeni roller, güncellenen profiller — mevcut SoD matrisini geçersiz kılabilir.

### SoD Matrisi Güncelleme Döngüsü

```
Kurum iş süreç değişikliği
VEYA SAP rol/yetki değişikliği
           │
           ▼
Etkilenen SoD kurallarının belirlenmesi
(GRC Access Control veya manuel)
           │
           ▼
Risk sahibiyle (iş birimi yöneticisi) görüşme:
"Bu çakışma kabul edilebilir mi?
 Telafi edici kontrol uygulanabilir mi?"
           │
           ├─→ Kabul edilebilir + telafi edici kontrol
           │   → SoD matrisinde "mitigated" olarak işaret
           │   → SIEM kuralında suppress edilmez,
           │     alarm notuna telafi bilgisi eklenir
           │
           └─→ Kabul edilemez
               → Yetki değişikliği için change request
               → Düzeltme transport'u
           │
           ▼
SoD matris CSV'si güncellenir
ve SIEM lookup tablosu yenilenir
```

**Kritik ilke:** Bir SoD çakışması "kabul edildi" (risk acceptance) olarak işaretlendiğinde bile, SIEM'deki ilgili kural tamamen susturulmamalıdır. Bunun yerine alarm çıktısına "bu çakışma kabul edilmiş — telafi edici kontrol: [açıklama]" notu eklenmeli ve alarm önceliği düşürülebilir. Çünkü telafi edici kontrol zamanla geçerliliğini yitirebilir; alarmın tamamen kapatılması bu durumun fark edilmesini engeller.

### GRC Access Control Entegrasyonu

SAP GRC (Governance, Risk and Compliance) Access Control modülü, SoD analizini otomatize eden yerleşik bir araçtır. GRC kullanan kurumlarda SIEM entegrasyonu iki katmanda düşünülmelidir:

**GRC → SIEM:** GRC'nin ürettiği SoD ihlal raporları ve risk değerlendirmeleri SIEM'e beslenebilir; bu, statik anlık görüntüyü SIEM'in dinamik korelasyon yetenekleriyle birleştirir.

**SIEM → GRC:** SIEM'de tespit edilen anomaliler (örneğin bir kullanıcının SoD çakışmalı yetkilerini aynı anda kullanan davranışı) GRC'ye beslenerek risk puanlamasını güncelleyebilir. Bu çift yönlü entegrasyon, ne tek başına GRC ne de tek başına SIEM'in sağlayabileceği kapsamlı bir görünürlük sunar.

GRC olmayan ortamlarda, SoD matrisinin manuel olarak Excel'de tutulması ve SIEM lookup tablosuna periyodik aktarımı da işlevseldir — sadece otomasyondan yoksundur ve bakım daha yoğun emek gerektirir.

## RFC ve Trust İlişkileri Yönetimi

### RFC Bağlantı Envanteri

Bölüm 3'te RFC bağlantılarının SIEM tarafında nasıl izleneceğini, Bölüm 5'te beklenmedik RFC kaynaklarını yakalayan detection kuralını işledik. Bu bölümde konuyu Basis perspektifinden ele alıyoruz: RFC bağlantıları nasıl envanterlenmelidir ve bu envanter nasıl canlı tutulur?

SAP'ta RFC destination'ları SM59 transaction'ında tanımlanır. Her RFC destination şu bilgileri içerir: hedef sistem host ve port, bağlantı tipi (3 = ABAP sistemi, H = HTTP, W = WebRFC vb.), kimlik doğrulama yöntemi ve kullanılan teknik kullanıcı (logon/password veya SNC/Kerberos).

RFC envanteri için periyodik olarak yapılması gereken kontroller:

```
SM59 üzerinden RFC destination envanteri çıkarımı
                   │
                   ▼
Her destination için değerlendirme:
┌─────────────────────────────────────────────────┐
│ 1. Bu bağlantı hâlâ aktif kullanımda mı?        │
│    (Son 90 günde çağrıldı mı?)                  │
│                                                  │
│ 2. Hedef sistem bilinen ve güvenilir mi?         │
│    (CMDB'de kayıtlı mı?)                        │
│                                                  │
│ 3. Kullanılan teknik kullanıcı güncel ve         │
│    minimum yetkili mi?                           │
│    (Parolası bilinen mi? Ne zaman değişti?)      │
│                                                  │
│ 4. Bağlantı tipi uygun mu?                      │
│    (HTTP yerine HTTPS kullanılıyor mu?)          │
│                                                  │
│ 5. Trusted bağlantı ise, bu gerekli mi?          │
│    (Trust, minimum yetkili alternatifle          │
│     değiştirilebilir mi?)                        │
└─────────────────────────────────────────────────┘
                   │
                   ▼
Kullanılmayan destinationlar kaldırılır
Trusted olmayan alternatif mevcut olanlar revize edilir
Kullanıcı parolaları rotasyon planına dahil edilir
Envanter Bölüm 5'teki rfc_expected_sources.csv güncellenir
```

### Trusted System İlişkileri ve Risk

SAP'ın trusted system mekanizması, iki sistem arasında "sistem A, sistem B'ye belirli kullanıcılar adına kimlik doğrulama gerektirmeksizin bağlanabilir" anlamına gelir. Bu mekanizmanın iş gerekçesi genellikle Single Sign-On veya sistemler arası veri entegrasyonunu kolaylaştırmaktır — ama güvenlik riski yüksektir.

Bir trusted system ilişkisinin ne anlama geldiğini somutlaştıralım: Sistem A'ya erişimi olan bir saldırgan, A'dan B'ye trusted bağlantı üzerinden, B'deki herhangi bir kullanıcı (hatta yüksek yetkili bir kullanıcı) adına geçebilir — parola gerektirmeden. Bu, B sisteminin bağımsız bir güvenlik perimetresi olmaktan çıktığı anlamına gelir.

Bu nedenle trusted system ilişkileri için üç kural:

**Kural 1 — Minimum scope:** Trusted ilişki, sadece ihtiyaç duyulan kullanıcılar ve fonksiyon grupları için tanımlanmalı; "tüm kullanıcılar" kapsamında bir trust ilişkisi neredeyse hiçbir zaman meşru değildir.

**Kural 2 — Geliştirme → Production yasağı:** Geliştirme veya test sisteminin production'a trusted olarak tanımlanması kesinlikle engellenmeli. Bölüm 1 Senaryo 3 tam olarak bu konfigürasyonu sömürüyordu.

**Kural 3 — Periyodik inceleme:** Trusted ilişkiler en az yılda iki kez gözden geçirilmeli; artık ihtiyaç olmayan ilişkiler kaldırılmalı. Bu gözden geçirmenin sonucu belgelenmeli ve Bölüm 5'teki rfc_expected_sources.csv ile eşleştirilmeli.

### Gateway Güvenliği: secinfo ve reginfo

Bölüm 2'de kısaca değindiğimiz Gateway ACL dosyaları, operasyonel güvenlik açısından özellikle detaylandırılmayı hak ediyor.

**secinfo:** Hangi harici programların Gateway üzerinden hangi SAP fonksiyon modüllerini çağırabileceğini kontrol eder. Bir satır örneği:

```
# secinfo - SAP Gateway ACL örneği
# Sözdizimi: P TP=<program> USER=<kullanıcı> HOST=<host> ACCESS=<izin>

# Bilinen ERP entegrasyon programının belirli host'tan bağlantısına izin ver
P TP=ERPINT_CONNECTOR USER=RFC_ERP_USR HOST=10.1.2.50 ACCESS=*

# BW raporlama sistemi - sadece belirli fonksiyon grupları
P TP=BW_CONNECTOR USER=RFC_BW_USR HOST=10.1.3.100 ACCESS=RSA*

# Diğer tüm bağlantıları reddet
D TP=* USER=* HOST=* ACCESS=*
```

Boş veya eksik bir secinfo dosyası, son satırdaki "tümünü reddet" kuralı olmadan, Gateway'in tüm bağlantılara izin vermesi anlamına gelir.

**reginfo:** Hangi programların Gateway'e "program kaydı" (program registration) yapabileceğini kontrol eder. Bu, özellikle eski SAP entegrasyonlarında (RFC server programları) kritik bir güvenlik kontrolüdür.

**Operasyonel bakım:** Bu dosyaların güncellenmesi bir değişiklik yönetimi sürecine bağlanmalı; her yeni RFC entegrasyonu devreye alındığında veya kaldırıldığında bu dosyalar güncellenmeli ve değişiklik belgelenmelidir.

## Periyodik Güvenlik Kontrol Takvimi

Dört operasyonel alanın bakım aktivitelerini bir araya getiren periyodik takvim:

| Aktivite | Sıklık | Sorumlu | SOC Katkısı |
|---|---|---|---|
| RSECNOTE çalıştırma (yamlanmamış notlar) | Aylık (Patch Day sonrası) | Basis | Kritik yamalanmamış notlar için SIEM alarmı |
| Yüksek riskli SAP kullanıcıları incelemesi | Aylık | Basis + Güvenlik | SoD kural güncellemesi |
| RFC destination envanteri | Çeyreklik | Basis | rfc_expected_sources.csv güncellenmesi |
| Trusted system ilişkileri gözden geçirilmesi | Çeyreklik | Basis + Güvenlik | SIEM trust anomali kurallarının kalibrasyonu |
| SoD matris güncellemesi | Çeyreklik (veya iş değişikliği anında) | GRC/Güvenlik | Bölüm 5 use-case 5 kural güncellemesi |
| Gateway ACL (secinfo/reginfo) gözden geçirilmesi | Çeyreklik | Basis | Gateway log anomali baseline'ının güncellenmesi |
| SAP Kernel güncelleme değerlendirmesi | Altı aylık | Basis | Kernel zafiyeti exploit girişimi izleme penceresi |
| Tüm SIEM lookup tablolarının tam yenilenmesi | Altı aylık | SOC + Basis | Birlikte gerçekleştirilen tablo revizyonu |
| SAP güvenlik yapılandırması review | Yıllık | Basis + Güvenlik + İç Denetim | Detection coverage değerlendirmesi (Bölüm 9) |

Bu takvim, Bölüm 8'deki raporlama yapısıyla doğrudan bağlantılıdır: her periyodik kontrolün sonucu belgelenmeli ve uygun rapor formatında yönetime sunulmalıdır.

## Bölüm 1 Senaryolarına Operasyonel Kapanış

Bölüm 1'de tanımladığımız yedi senaryonun her biri, bu bölümdeki operasyonel kontrollerden en az biriyle önlenebilir veya riski azaltılabilir olduğunu vurgulamak faydalıdır:

| Senaryo | Önleyici Operasyonel Kontrol |
|---|---|
| 1 — Unutulan SAP_ALL | Yüksek yetkili kullanıcı aylık incelemesi; SAP_ALL geçici atama için zorunlu change ticket ve otomatik zaman sınırı |
| 2 — Debug & Replace | S_DEVELOP objesi periyodik gözden geçirilmesi; debug & replace yetkisinin production'da asgari kullanıcıyla sınırlandırılması |
| 3 — RFC trust suistimali | RFC trust ilişkileri çeyreklik envanteri; geliştirme→production trust yasağı politikası |
| 4 — Şifre sıfırlama ile hesap devralma | SU01 üzerindeki şifre sıfırlama yetkisinin kullanıcı grubu bazlı kısıtlanması; S_USER_GRP konfigürasyonu |
| 5 — SoD ihlali | SoD matris çeyreklik güncellemesi; GRC Access Control entegrasyonu |
| 6 — Client copy ile veri sızması | Client copy prosedürüne zorunlu veri maskeleme adımı eklenmesi; test sistemi erişim kontrollerinin production seviyesine yaklaştırılması |
| 7 — Workflow vekalet suistimali | Vekalet atamalarının periyodik incelenmesi; vekil kullanıcının onay limitinin açık tanımlanması |

Detection ve operasyonel güvenlik birlikte çalıştığında bir bütündür: detection, operasyonel kontrollerin başarısız olduğu anı yakalar; operasyonel kontroller, detection'ın tetiklenmesini gerektiren olayların sayısını azaltır.

Bir sonraki bölümde, bir detection kuralı gerçekten tetiklendiğinde ne yapılacağını işleyeceğiz: SAP'a özgü triage adımları, SOC ile Basis ekibinin ortak çalışma akışı ve false positive yönetiminin nasıl sürekli iyileştirme döngüsüne dönüştüğü.
