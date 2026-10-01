---
layout: default
title: "Bölüm 7: Olay Müdahalesi: Triage ve Forensics"
nav_order: 7
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/07-olay-mudahalesi/
---


## Alarm Tetiklendi — Şimdi Ne Yapılır

Bölüm 5'te yazdığımız detection kurallarından biri gerçek bir olay üzerinde tetiklendiğinde, ya da Bölüm 6'daki operasyonel kontroller sırasında beklenmedik bir bulgu ortaya çıktığında, geriye kalan tek soru şudur: bundan sonra ne yapılır?

SAP olay müdahalesi, genel SOC playbook'larının uygulanamadığı bir alandır. "Etkilenen host'u ağdan izole et" talimatı, SAP'ta işleme devam eden onlarca kullanıcı ve aktif batch job'larla dolu bir production sistemine doğrudan uygulanamaz. "Zararlı işlemi sonlandır" komutu, SAP ABAP runtime'ında farklı bir anlam taşır. "Log topla ve analiz et" adımı, SAP forensics'in hangi araçlara, hangi sırayla bakıldığını bilmeden verimli şekilde yürütülemez.

Bu bölüm, SAP'a özgü bir olay müdahale çerçevesi sunuyor: triage akışından forensic araçlara, SOC-Basis ortak çalışma modelinden false positive kararının nasıl verildiğine ve bu kararın nasıl kalıcı bir iyileştirmeye dönüştüğüne kadar. Her adımda "SOC ne yapıyor, Basis ne yapıyor" sorusunu ayrı ayrı yanıtlıyoruz.

## Olay Müdahale Fazları: SAP Bağlamında

Klasik olay müdahale döngüsü (Hazırlık → Tespit → Kapsama → İyileştirme → Kurtarma → Öğrenme) SAP için de geçerlidir — ama her fazın SAP'a özgü içeriği vardır:

```
┌─────────────────────────────────────────────────────────┐
│  FAZ 1: TESPİT                                           │
│  SIEM alarmı veya operasyonel kontrol bulgusu           │
│  SOC: Alarmı alır, ilk sınıflandırma yapar              │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  FAZ 2: TRİAJ                                            │
│  Gerçek mi, false positive mi?                          │
│  Kritiklik seviyesi nedir?                              │
│  SOC: SIEM verisi üzerinde ilk analiz                   │
│  Basis: SAP içinde doğrulama                            │
└────────────────────┬────────────────────────────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
    FALSE POSITIVE         GERÇEK OLAY
          │                     │
    Kural/lookup          ┌──────▼──────────────────────┐
    güncelleme ve         │  FAZ 3: KAPSAMA              │
    kapat                 │  Riski sınırla, kanıtı koru  │
                          │  SOC + Basis ortak aksiyon   │
                          └──────┬──────────────────────┘
                                 │
                          ┌──────▼──────────────────────┐
                          │  FAZ 4: FORENSİCS            │
                          │  Kök neden, etki kapsamı,    │
                          │  zaman çizelgesi             │
                          │  Basis: SAP araçları         │
                          │  SOC: SIEM korelasyonu       │
                          └──────┬──────────────────────┘
                                 │
                          ┌──────▼──────────────────────┐
                          │  FAZ 5: İYİLEŞTİRME          │
                          │  Temizleme, yetki düzeltme,  │
                          │  sistem bütünlüğü doğrulama  │
                          └──────┬──────────────────────┘
                                 │
                          ┌──────▼──────────────────────┐
                          │  FAZ 6: ÖĞRENME              │
                          │  Detection kuralı iyileştir  │
                          │  Operasyonel kontrol güncelle│
                          │  Raporla (Bölüm 8)           │
                          └─────────────────────────────┘
```

## Faz 1–2: İlk Triage — SIEM'den SAP'a

### SOC'un İlk Değerlendirme Adımları

Bir SAP alarmı geldiğinde SOC analistinin önünde SIEM'den gelen veriler vardır. İlk triage, bu veriyle şu soruları yanıtlamayı hedefler:

**Soru 1 — Bu olay hangi sistemde, hangi client'ta gerçekleşti?**
`sap_system` ve `sap_client` alanları bu soruyu yanıtlar. Production client'ı (genellikle 100 veya 200) ile test client'ı arasındaki fark, önceliklendirmeyi doğrudan etkiler. Aynı olay tipi test ortamında "inceleme" düzeyindeyken production'da "acil" düzeyine çıkabilir.

**Soru 2 — Olayı gerçekleştiren kullanıcı kim ve bu kullanıcının profili nedir?**
`user` alanından hareketle: bu kullanıcı bir servis/teknik hesap mı (normalde interaktif logon yapmamalı), bir son kullanıcı mı, yoksa Basis/güvenlik yöneticisi mi? Kullanıcı profili, olayın beklenen veya beklenmedik olduğuna dair ilk bağlamı sağlar.

**Soru 3 — Olay ne zaman gerçekleşti?**
`_time` alanı ve `is_offhours` zenginleştirmesi. Mesai saatleri dışında, hafta sonu veya resmi tatil günü gerçekleşen SAP olayları ekstra dikkat gerektirir.

**Soru 4 — Bu kullanıcıdan bu sistem/client'ta benzer olaylar daha önce görüldü mü?**

```spl
-- Triage bağlamı sorgusu
index=sap_audit sourcetype="sap:audit"
    user="[ALARM_KULLANICI]"
    sap_system="[ALARM_SISTEM]"
    sap_client="[ALARM_CLIENT]"
    earliest=-30d latest=now
| timechart span=1d count BY signature_id
| addtotals
```

Bu sorgu, ilgili kullanıcı için son 30 günlük SAP aktivite trendini gösterir. Alarm tarihinde ani bir yükseliş varsa, bu sistematik bir değişikliğe işaret edebilir. Tam tersine, bu kullanıcıdan her gün benzer olaylar görülüyorsa, false positive ihtimali yüksektir.

**Soru 5 — Bu alarm aynı anda başka alarmlarla birlikte mi geliyor?**

```spl
-- Aynı kullanıcı için son 1 saatteki tüm alarmlar
index=notable sourcetype="stash"
    user="[ALARM_KULLANICI]"
    earliest=-1h
| table _time, rule_name, severity, sap_system, sap_client
| sort - _time
```

Birden fazla farklı kuralın aynı kullanıcı için kısa sürede tetiklenmesi, Bölüm 5'teki birleşik risk skoru mantığıyla uyumlu bir "örüntü" sinyalidir ve önceliklendirmeyi otomatik olarak yükseltmelidir.

### Basis Ekibinin Doğrulama Adımları

SOC ilk değerlendirmesini tamamlarken, Basis ekibine paralel olarak şu sorular sorulur:

**"Bu kullanıcı bu T-code'u/işlemi bu saatte yapması beklenen biri mi?"**
Bu soruyu Basis ekibi yanıtlar. Bir güvenlik analistin "AU1 kategorisinde kullanıcı master kaydı değişikliği" ifadesini değerlendirmesi mümkündür ama "SU01 üzerinden profil ataması bu saat bu gün normal mi" sorusu için SAP operasyon bağlamı gereklidir.

**"Bu kullanıcının mevcut yetkisi nedir?"**
SU01 veya SU56 (authorization trace) üzerinden anlık yetki durumu incelenir. Bu bilgi, alarmın arkasındaki "ne kadar yetki var" sorusunu yanıtlar.

**"Sistemde şu anda başka olağandışı bir şey var mı?"**
SM66 (global work process overview) üzerinden sistemde çalışan tüm iş süreçlerinin anlık görüntüsü alınır. Beklenmedik sayıda veya beklenmedik türde work process (örneğin alışılmadık sayıda background job) ek bir anomali sinyali verebilir.

## Faz 3: Kapsama — SAP'a Özgü Aksiyonlar

"Etkilenen host'u ağdan izole et" yaklaşımı SAP production sistemine uygulanamaz — ama benzer amaca hizmet eden SAP'a özgü kapsama aksiyonları vardır.

### Hızlı Kapsama Seçenekleri

**Kullanıcı kilitleme (SU01):**
Şüpheli kullanıcının hesabı kilitlenir. Bu, kullanıcının aktif oturumlarını sonlandırmaz (zaten bağlı oturumlar devam eder) ama yeni oturum açılmasını engeller.

```
SU01 → Kullanıcı adı → Logon Data sekmesi → "Lock User" seçeneği
```

Bu aksiyonun SIEM'de kayıt altına alınması önerilir: kim kilitledi, hangi saatte, hangi gerekçeyle. Bu kayıt hem forensics için hem de yönetim raporlaması için kullanılır.

**Aktif oturumu sonlandırma (SM04/AL08):**
SM04 (veya merkezi izleme için AL08) üzerinden şüpheli kullanıcının aktif oturumları listlenir ve gerekirse sonlandırılır. Bu, kullanıcının sisteme kilitsiz olarak bağlı kaldığı durumları kapatır.

```
SM04 → Kullanıcı adını filtrele → Oturumu seç → "Delete Session"
```

**Yetkiyi geçici olarak kaldırma:**
Hesabı tamamen kilitlemek mümkün değilse (örneğin kritik bir servis hesabıysa), ilgili profilin geçici olarak kaldırılması daha az disruptif bir kapsama yöntemi olabilir. Bu aksiyonun geri alınması mümkün olduğundan, hesabı tamamen kilitlemekten daha tercih edilebilir olduğu durumlar vardır.

**RFC destination'ın devre dışı bırakılması:**
Senaryo 3 (RFC trust suistimali) gibi durumlarda, şüpheli kaynak sistemin RFC destination'ı SM59'dan devre dışı bırakılabilir. Bu, sistemler arası bağlantıyı keser ama production'un genel işleyişini bozmaz.

**Gateway'de IP engelleme:**
Gateway üzerinden gelen şüpheli IP'den bağlantılar, SMGW (Gateway Monitor) üzerinden engellenebilir. Bu, ağ katmanındaki engellemin tamamlayıcısı olarak işlev görür.

### Kanıt Koruma: SAP Forensics'te Kritik İlk Adım

Kapsama aksiyonlarıyla birlikte, kanıt koruma kritik bir öncelik olarak ele alınmalıdır. SAP forensics'te kaybedilme riski en yüksek olan veri türleri şunlardır:

**Security Audit Log dosyaları:** Dosya rotasyonu gerçekleşmeden önce ilgili log dosyaları güvenli bir konuma kopyalanmalıdır. Eğer log zaten SIEM'e aktarıldıysa, SIEM'deki veri birincil kaynak olarak korunur.

**SM21 (System Log) geçici kaydı:** SM21 verisi yerel dosyada tutulur ve eski dosyalar üzerine yazılabilir. İlgili zaman diliminin SM21 çıktısı dosyaya veya veritabanına kaydedilmelidir.

**Tablo değişiklik geçmişi (DBTABLOG):** Loglanan tablolarda yapılan değişiklikler DBTABLOG tablosunda saklanır. Bu tablonun ilgili zaman dilimindeki kaydı SE16N veya özel bir sorguyla çıkarılmalı ve güvenli bir ortama kopyalanmalıdır.

**Memory dump (ST22):** ABAP runtime hataları ST22'de saklanır; belirli bir zaman aralığından hataların listesi forensics için değerli olabilir. ST22 kayıtları SAP sistemi tarafından otomatik olarak temizlenebilir — ilgili kayıtlar derhal kopyalanmalıdır.

## Faz 4: Forensics — SAP'ta Kök Neden Analizi

### Birincil Forensics Araçları

#### ST22 — ABAP Runtime Error (Short Dump) Analizi

ST22, bir ABAP programının çalışma sırasında hata verip durduğunda ürettiği "short dump"ları listeler ve detaylarını gösterir. Forensics bağlamında değeri birkaç noktada ortaya çıkar:

**Başarısız istismar girişimleri:** Bir saldırgan ABAP runtime'ını zorlayan beklenmedik bir input gönderdiğinde — örneğin bir debug & replace girişiminin başarısız olması — bu ST22'de bir dump bırakabilir.

**Anormal program çalıştırma:** Normalde çalışmaması gereken bir programın çalıştırılmaya çalışılması ve hata vermesi, ST22 üzerinden tespit edilebilir.

**ST22 forensics akışı:**

```
ST22 ekranında:
1. Tarih aralığı: Şüpheli zaman dilimine ayarla
2. Kullanıcı filtresi: Şüpheli kullanıcı ID'si
3. Program adı: Bilinen kötü amaçlı veya şüpheli program adları
4. Seçilen dump → "Long text" (uzun metin):
   - Error code ve mesaj
   - Program adı, include, satır numarası
   - "Active calls / Events" kısmı: hangi fonksiyon zinciriyle
     bu noktaya gelindiği (call stack)
   - "Source code extract": hatanın oluştuğu kod bölümü
```

ST22 call stack, bir exploit girişiminin anatomisini ortaya çıkarmak için değerlidir — başlangıç noktasından hata oluşana kadar tüm ABAP çağrı zinciri burada görülür.

#### SM21 — System Log Forensics Okuma

SM21'i Bölüm 2'de yapılandırma bağlamında işledik. Forensics bağlamında farklı bir gözle okunur: tek bir kullanıcı veya olay odağında değil, olayın gerçekleştiği zaman dilimini kapsayan geniş bir zaman penceresiyle tüm sistem hareketleri incelenir.

**Forensics odaklı SM21 sorgu stratejisi:**

```
Adım 1: Geniş tarama
  Tarih: Şüphelenilen olayın 2 saat öncesi – 2 saat sonrası
  Kullanıcı: * (tüm kullanıcılar)
  Önem: Kritik ve Önemli
  → Aynı zaman diliminde başka anormal olaylar var mı?

Adım 2: Odaklanmış okuma
  Tarih: Tam şüpheli zaman aralığı
  Kullanıcı: [Şüpheli kullanıcı ID'si]
  → Bu kullanıcıya ait tüm sistem seviyesi olaylar

Adım 3: Instance karşılaştırma
  Birden fazla uygulama sunucusu varsa:
  Her instance için ayrı ayrı aynı sorguyu çalıştır
  → Şüpheli aktivite tüm instance'larda mı,
    yoksa belirli birinde mi?
```

#### DBTABLOG — Tablo Değişiklik Geçmişi

Bölüm 2'de hangi tabloların loglandığını yapılandırdık. Forensics aşamasında, şüpheli zaman dilimine ait tablo değişiklikleri SE16N veya özel bir rapor üzerinden okunur.

**Kritik DBTABLOG sorgu alanları:**

```
Tablo: DBTABLOG
Filtre alanları:
  TABNAME    = [İncelenen tablo adı, örn. USR02, AGR_1251]
  USERNAM    = [Şüpheli kullanıcı]
  UDATE      = [Tarih aralığı]
  UTIME      = [Saat aralığı]
  MANDT      = [Client numarası]

Çıktı alanları:
  TABNAME    Tablo adı
  TABKEY     Değiştirilen satırın anahtarı
  USERNAM    Değişikliği yapan kullanıcı
  UDATE/UTIME Değişiklik zamanı
  TCODE      Kullanılan T-code
  CHANGEDBY  Teknik değişikliği gerçekleştiren süreç
```

Bu çıktı, "hangi kullanıcı, hangi tabloda, hangi satırı, hangi saatte değiştirdi" sorusunu doğrudan yanıtlar. Özellikle Senaryo 1 (SAP_ALL ataması sonrasında tabloya doğrudan erişim) ve Senaryo 2 (debug & replace sonrasında tablo değeri değişikliği) için birincil forensics kaynağıdır.

#### SUIM — Kullanıcı Bilgi Sistemi

SUIM (User Information System), SAP'ın yetkilendirme yapısını raporlamak için tasarlanmış kapsamlı bir araçtır. Forensics bağlamında şu sorgular özellikle değerlidir:

**"Bu T-code'u hangi kullanıcılar çalıştırabilir?"**

```
SUIM → Users → By Transaction Authorization
T-code: [İncelenen T-code, örn. SE16N]
Client: [Production client]
→ Production'da SE16N çalıştırabilen kullanıcıların tam listesi
```

Bu sorgu, "başka kim bu işlemi yapabilirdi" sorusunu yanıtlar ve soruşturmanın kapsamını belirler.

**"Bu kullanıcı son 30 günde hangi T-code'ları çalıştırdı?"**

```
SUIM → Users → By Logon Date and Password Change
[Şüpheli kullanıcı] → İlgili detay
```

SUIM'in bazı sorguları, Security Audit Log etkin olmayan sistemlerde bile yanıtlanabilir çünkü SUIM kısmen yetkilendirme objeleri üzerinden çalışır. Ama log olmadan "ne yaptı" değil, yalnızca "ne yapabilirdi" sorusu yanıtlanabilir — önemli bir fark.

#### SU53 — Başarısız Yetki Kontrolü

SU53, bir kullanıcının en son başarısız yetkilendirme kontrolünü gösterir. Forensics bağlamında değeri şudur: bir kullanıcı belirli bir işlemi yapmaya çalışıp yetersiz yetki nedeniyle başarısız olduysa, SU53 hangi authorization object'in eksik olduğunu gösterir. Bu, "saldırganın neye erişmeye çalıştığı ama başaramadığı" sorusunu yanıtlar — yani başarısız saldırı girişimini belgeler.

```
SU53 çalıştırma:
  Kendi oturumunda çalıştırılırsa: Son kendi başarısız kontrolünü gösterir
  Başka kullanıcı için:
    SM19/SM20 üzerinden o kullanıcının AU3 kayıtlarına bak
    veya Basis ekibi, yetkili bir hesapla /nSU53 çalıştırır
```

### SIEM Üzerinden Forensics Zaman Çizelgesi

Birden fazla SAP forensics aracından toplanan bilgiyi, SIEM'deki log verileriyle birleştirerek bir olay zaman çizelgesi oluşturmak, kök neden analizinin en güçlü adımıdır:

```spl
-- Belirli bir kullanıcı için kapsamlı olay zaman çizelgesi
index=sap_audit OR index=sap_change OR index=sap_syslog
    user="[ŞÜPHELI_KULLANICI]"
    sap_system="[SISTEM]"
    sap_client="[CLIENT]"
    earliest="[OLAY_BAŞLANGICI - 2 SAAT]"
    latest="[OLAY_SONU + 2 SAAT]"
| eval event_source=case(
    index="sap_audit",  "Security Audit Log",
    index="sap_change", "Change Documents",
    index="sap_syslog", "System Log",
    true(), "Other")
| eval event_summary=coalesce(
    message, object_category . " - " . action)
| table _time, event_source, signature_id,
        event_summary, src, sap_client
| sort + _time
```

Bu sorgu, tüm log kaynaklarından gelen olayları tek bir kronolojik zaman çizelgesinde birleştirir. Basis ekibinin ST22, SM21 ve DBTABLOG'dan topladığı veriler bu zaman çizelgesine entegre edildiğinde, olayın tam anatomisi ortaya çıkar:

```
Örnek Olay Zaman Çizelgesi (Senaryo 4 — Hesap Devralma):

08:47:23  Security Audit Log    HELPDESKUSR, SU01 üzerinden
                                 FINANCEUSER parolasını değiştirdi [AU1]
08:49:11  Security Audit Log    FINANCEUSER, 10.5.1.99'dan dialog logon [AU1]
                                 (Normal terminali: 10.1.x.x aralığı)
08:51:03  Change Documents      FINANCEUSER, VENDOR 1234 için
                                 ödeme koşullarını güncelledi
08:53:44  Security Audit Log    FINANCEUSER, F110 (Otomatik Ödeme)
                                 transaction'ını başlattı [AU5]
08:57:22  Security Audit Log    FINANCEUSER oturum kapattı [AU1]
08:57:45  SIEM Alarm            Rule: "Şifre sıfırlama + alışılmadık
                                 terminal logon" tetiklendi
                                 → 6 dakika 22 saniye sonra alarm geldi
```

Bu zaman çizelgesi hem forensics için hem de yönetim raporlaması için doğrudan kullanılabilir. Aynı zamanda alarmın neden 6 dakika geç geldiğini — SIEM'in detection gecikmesini — gösterir ve kural optimizasyonu için bir veri noktası sağlar.

## False Positive Yönetimi: Kapatmak Değil, Öğrenmek

Her false positive, doğru ele alındığında bir iyileştirme fırsatıdır. Yanlış ele alındığında ise giderek kör nokta haline gelen bir kural listesi üretir.

### False Positive Karar Akışı

```
Alarm geldi
     │
     ▼
SOC: SIEM verisiyle ilk analiz
     │
     ▼
Basis: SAP içinde doğrulama
     │
     ├─→ "Bu olay beklenen bir operasyondu"
     │       │
     │       ▼
     │   False Positive Kayıt Oluştur:
     │   - Kim kapattı
     │   - Neden false positive
     │   - Bu durumun tekrar görülmesi bekleniyor mu?
     │       │
     │       ├─→ Tekrar görülmesi BEKLENMEZ
     │       │   → Kaydı kapat, kural değişikliği yok
     │       │
     │       └─→ Tekrar görülmesi BEKLENIR
     │               │
     │               ▼
     │           Çözüm seçenekleri:
     │           A) Eşik değerini yükselt
     │           B) Lookup tablosuna istisna ekle
     │           C) Zaman filtresi ekle (bakım penceresi)
     │           D) Kuralı daha spesifik yaz
     │
     └─→ "Bu olay beklenmedik ve açıklanamaz"
             │
             ▼
         Gerçek Olay → Forensics fazına geç
```

### False Positive Kayıt Yapısı

Her false positive kararı, aşağıdaki bilgileri içeren bir kayıtla belgelenmelidir:

```csv
-- false_positive_log.csv örnek şema --
alarm_time, rule_name, affected_user, sap_system, sap_client,
closed_by, closed_time, fp_reason, recurrence_expected,
action_taken, review_date
```

Bu kayıt şu amaçlarla kullanılır:

**Kural kalitesi izleme:** Bir kural için aylık false positive oranı %80'in üzerindeyse, kural ciddi biçimde revize edilmeli ya da lookup tablosu güncellenmeli. Bu oran Bölüm 8'deki raporlarda takip edilmelidir.

**Örüntü tespiti:** Aynı kullanıcı için aynı kural üçüncü kez false positive kapanıyorsa, bu ya kuralın bu kullanıcı için yanlış tasarlandığının ya da kullanıcının yetkisinin gerçekten gözden geçirilmesi gerektiğinin sinyalidir.

**Denetim izi:** False positive kararları, ilerideki bir denetimde "neden bu alarm kapatıldı" sorusunu yanıtlayan belge olarak kullanılabilir.

### SOC-Basis Arasındaki False Positive Anlaşmazlıkları

Zaman zaman SOC ve Basis ekibi bir olayın gerçek mi false positive mi olduğu konusunda farklı kanaate ulaşabilir. Bu anlaşmazlıklar için yapılandırılmış bir süreç olmadığında, genellikle daha güçlü olan tarafın görüşü baskın çıkar — ki bu her durumda doğru sonucu vermez.

Önerilen yaklaşım: Anlaşmazlık durumunda, olay 48 saat boyunca "belirsiz" statüsünde tutulur ve her iki ekip de ek kanıt/bağlam toplar. Belirsizlik çözülmezse, güvenlik/GRC ekibi hakem rolüyle karar verir. Bu karar, her iki tarafın da katıldığı bir kayıtla belgelenir.

## Olay Sonrası Öğrenme: Detection'dan Operasyona Geri Döngü

Her gerçek olay ve her önemli false positive, aşağıdaki soruların sorulduğu bir "post-incident review" gerektirmelidir:

**Detection açısından:** Alarm doğru zamanda mı geldi? Gecikme kabul edilebilir miydi? Kural daha spesifik veya daha kapsamlı yazılabilir miydi? Alarm sinyali başka alarmlarla birleştirilseydi önceliklendirme daha mı doğru olurdu?

**Operasyonel açıdan (Bölüm 6 bağlantısı):** Bu olayı önleyebilecek bir operasyonel kontrol var mıydı ve o kontrol uygulanmış mıydı? Değilse, neden eksikti?

**Forensics açısından:** Tüm gerekli log verisi mevcut muydu? Yoksa hangi loglama boşluğu doldurulmalı? Zaman çizelgesini oluşturmak ne kadar sürdü ve bu süre kabul edilebilir miydi?

**İletişim açısından:** SOC ile Basis arasındaki bilgi akışı sorunsuz muydu? Eskalasyon zamanında gerçekleşti mi?

Bu soruların yanıtları, Bölüm 9'da işleyeceğimiz olgunluk modeli değerlendirmesinin ham girdilerini oluşturur.

## Örnek Playbook Özeti: SAP_ALL Ataması Alarmı

Tüm bu fazları bir araya getirerek, Senaryo 1 (unutulan SAP_ALL) için bir örnek playbook özeti:

```
ALARM: SAP_ALL Profil Ataması — [SISTEM]/[CLIENT]
ÖNCELIK: KRİTİK 🔴
SLA: 30 dakika içinde triage tamamlanmalı

ADIM 1 — SOC (0-10 dk):
  □ Atamayı yapan kullanıcıyı ve etkilenen kullanıcıyı belirle
  □ Atama saatini ve client'ı doğrula (production mu?)
  □ Son 30 günde bu kullanıcı için benzer olay var mı?
  □ Aynı anda başka alarm tetiklendi mi?

ADIM 2 — Basis Eskalasyonu (10-20 dk):
  □ SU01'de etkilenen kullanıcının mevcut yetki durumunu kontrol et
  □ Change ticket bu atamayı kapsıyor mu?
  □ Atamayı yapan kullanıcı beklenmedik bir terminal/saat mi kullanıyor?
  □ SM66'da sistemde olağandışı bir aktivite var mı?

ADIM 3 — Karar (20-30 dk):
  □ Onaylı bir atama → False positive kayıt + kural ince ayar değerlendirmesi
  □ Onaysız veya beklenmedik → Kapsama aksiyon:
      a) SAP_ALL profilini etkilenen kullanıcıdan kaldır
      b) Atamayı yapan kullanıcıyı kilitle (gerekiyorsa)
      c) Forensics fazına geç
      d) Güvenlik/GRC ekibini ve yönetimi bilgilendir

ADIM 4 — Forensics (30+ dk, gerçek olay ise):
  □ DBTABLOG: SAP_ALL atama zamanından itibaren tablo değişiklikleri
  □ SM21: Aynı zaman diliminde sistem log olayları
  □ ST22: Aynı kullanıcının ABAP dump geçmişi
  □ SIEM: Kullanıcı için kapsamlı zaman çizelgesi sorgusu
  □ SUIM: SAP_ALL ile neler yapılabilirdi — etki kapsamı

ADIM 5 — Sonuç Belgeleme:
  □ Olay raporu (Bölüm 8 formatında)
  □ False positive ise: false_positive_log.csv güncelleme
  □ Gerçek olay ise: kök neden, etki, alınan aksiyonlar, öneriler
```

Bir sonraki bölümde bu triage ve forensics süreçlerinin çıktılarını nasıl raporlayacağımızı işleyeceğiz: yönetime özet raporlar, Basis ekibine operasyonel raporlar, uyumluluk raporlaması ve periyodik metrikler.
