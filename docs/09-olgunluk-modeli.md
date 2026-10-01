---
layout: default
title: "Bölüm 9: Olgunluk Modeli ve Yol Haritası"
nav_order: 9
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/09-olgunluk-modeli/
---


## Serinin Son Bölümü: Nereden Nereye Geldik

Bu seri, bir SAP sistemini güvenli kılmanın tek bir araç veya tek bir süreçle halledilemeyeceği fikrinden yola çıktı. Bölüm 1'de bunu çerçeveledik: SAP'ın katmanlı mimarisi, generic IT araçlarının kör noktaları, Basis-SOC işbirliğinin gerekliliği. Ardından sırayla loglama politikalarını (Bölüm 2), SIEM aktarımını (Bölüm 3), CIM modeli ve hazır use-case'leri (Bölüm 4), özel detection kurallarını (Bölüm 5), operasyonel güvenliği (Bölüm 6), olay müdahalesini (Bölüm 7) ve raporlamayı (Bölüm 8) işledik.

Bu son bölümde bir adım geriye çekip tüm bu parçaların bütününe bakıyoruz: **ne kadar iyi koruyoruz, hangi boşluklar hâlâ var, bir sonraki adımlar neler** ve SAP'ın kendi güvenlik izleme aracı olan **SAP ETD ile mevcut SIEM altyapısının ilişkisi nasıl kurulmalı.**

## Olgunluk Modeli: Beş Seviye

SAP güvenlik programının olgunluğunu değerlendirmek için beş seviyeli bir model kullanıyoruz. Her seviye, bir öncekinin üzerine inşa edilir ve "şu anda neredeyiz" sorusuna somut bir referans noktası sağlar.

```
Seviye 5: OPTİMİZE
  Sürekli iyileştirme döngüsü, otomatik detection
  tuning, proaktif tehdit avcılığı, SAP ETD + SIEM
  tam entegrasyonu, coverage metrikleri KPI olarak
  yönetim gündemine taşınmış.
         ▲
Seviye 4: YÖNETİLEN
  Tüm kritik use-case'ler kapsamında, SoD/GRC
  entegrasyonu aktif, raporlama otomasyonu çalışıyor,
  olay müdahale playbook'ları belgelenmiş ve test
  edilmiş, periyodik operasyonel takvim uygulanıyor.
         ▲
Seviye 3: TANIMLANMIŞ
  Loglama politikası belgelenmiş ve uygulanıyor,
  SIEM entegrasyonu stabil, temel use-case'ler
  çalışıyor (SAP_ALL, RFC anomali, başarısız logon),
  SOC-Basis işbirliği prosedürü var, aylık rapor
  üretiliyor.
         ▲
Seviye 2: GELİŞTİRİLİYOR
  Loglama açık ama eksik, SIEM'e bazı loglar
  geliyor ama parsing sorunları var, alarmlar
  oluşturuluyor ama false positive yönetimi reaktif,
  SOC ve Basis ayrı dünyalarda çalışıyor.
         ▲
Seviye 1: BAŞLANGIÇ
  Security Audit Log kapalı veya minimal,
  SAP logları SIEM'e gitmiyor, güvenlik izleme
  yok veya manuel/dönemsel, SOC SAP'ı "kara
  kutu" olarak görüyor.
```

### Seviye Değerlendirme Matrisi

Bir kurumun hangi seviyede olduğunu nesnel olarak belirlemek için aşağıdaki değerlendirme matrisi kullanılabilir. Her kategori için 0-4 arası puan verilir; toplamın 20 üzerinden değerlendirilmesi seviyeyi belirler:

| Kategori | Kriter | Puan (0-4) |
|---|---|---|
| **Loglama Kapsamı** | 0: Log yok / 1: Sadece başarısız logon / 2: Temel olay sınıfları / 3: Kapsamlı, tüm client'lar / 4: + Z-tablolar, gateway, tam multiinstance | |
| **SIEM Entegrasyonu** | 0: Entegrasyon yok / 1: Kısmi/sorunlu / 2: Stabil, parsing hataları az / 3: CIM mapping tam, metadata zengin / 4: Acceleration aktif, reconciliation otomatik | |
| **Detection Coverage** | 0: Kural yok / 1: Sadece brute force / 2: Temel use-case'ler (3-4 kural) / 3: Tüm 7 senaryoyu kapsıyor / 4: Çapraz model korelasyon + risk skoru | |
| **Operasyonel Süreçler** | 0: Süreç yok / 1: Reaktif, yazılı değil / 2: Patch + transport takibi başladı / 3: Tüm Bölüm 6 kontrolleri / 4: Otomatik takvim + SIEM entegrasyonlu | |
| **Olay Müdahalesi** | 0: Playbook yok / 1: Genel SOC playbook / 2: SAP'a özgü triage adımları var / 3: Belgelenmiş playbook, forensics araçları / 4: Test edilmiş, SLA ölçülüyor | |
| **Raporlama** | 0: Raporlama yok / 1: Ad hoc / 2: Aylık manuel rapor / 3: Otomatik scheduled raporlar / 4: Üç katmanlı, denetim kanıt paketi dahil | |

**Toplam Puan → Seviye:**
- 0-4: Seviye 1 (Başlangıç)
- 5-9: Seviye 2 (GeliştirilIyor)
- 10-14: Seviye 3 (Tanımlanmış)
- 15-18: Seviye 4 (Yönetilen)
- 19-24: Seviye 5 (Optimize)

Bu matrisi yılda iki kez doldurmak, ilerlemenin somut bir görüntüsünü verir ve "geçen yıla göre hangi kategoride ne kadar ilerledik" sorusunu yanıtlar.

## Detection Coverage Ölçümü

"Ne kadar iyi koruyoruz" sorusunu yanıtlamanın en somut yolu, kapsanan tehdit kategorilerinin haritasını çıkarmaktır.

### SAP Tehdit Kategorileri ve Coverage Durumu

Bölüm 1'den Bölüm 5'e kadar işlediğimiz senaryoları tehdit kategorileri olarak organize ettiğimizde aşağıdaki coverage haritası ortaya çıkar:

| Tehdit Kategorisi | Örnek Senaryo | Bölüm 5 Use-Case | Coverage Durumu |
|---|---|---|---|
| Aşırı Yetki (Privilege Abuse) | Senaryo 1 — SAP_ALL | UC1 | ✅ Kapsanıyor |
| Çalışma Zamanı Manipülasyonu | Senaryo 2 — Debug & Replace | UC2 | ✅ Kapsanıyor |
| Sistemler Arası Yetkisiz Erişim | Senaryo 3 — RFC Trust | UC3 | ✅ Kapsanıyor |
| Kimlik Devralma | Senaryo 4 — Şifre Sıfırlama | UC4 | ✅ Kapsanıyor |
| Görev Ayrılığı İhlali | Senaryo 5 — SoD | UC5 | ⚠️ GRC bağımlı |
| Veri Sızıntısı (Operasyonel) | Senaryo 6 — Client Copy | UC6 | ⚠️ Kısmi |
| İş Akışı Suistimali | Senaryo 7 — Workflow Vekalet | UC7 | ⚠️ Onay limit bağımlı |
| İzleme Mekanizması Sabotajı | Meta Alarm | UC8 | ✅ Kapsanıyor |
| Kaba Kuvvet / Credential Stuffing | Brute Force | UC9 | ✅ Kapsanıyor |
| Servis Hesabı Suistimali | Generic Hesap İnteraktif Logon | UC10 | ✅ Kapsanıyor |
| ABAP Kodu Enjeksiyonu | Transport üzerinden backdoor | ❌ Henüz yok | ❌ Kapsanmıyor |
| Yamalanmamış Güvenlik Açıkları | CVSS 9+ Note istismarı | ❌ Henüz yok | ❌ Kapsanmıyor |
| Veri Exfiltration (Spool) | Toplu rapor/yazdırma | ❌ Henüz yok | ❌ Kapsanmıyor |

**Coverage yüzdesi (bu serinin sonunda):** 10 üzerinden 7 kategori tam, 3 kategori kısmi = %70 + %15 kısmi = yaklaşık %78 etkin coverage. Bu oran, pek çok kurumun SAP güvenlik programı başlangıcına göre önemli bir ilerlemeyi temsil eder — ama %100'den uzak olduğu ve üç boşluğun netleştirildiği görülür.

### Splunk ile Coverage Metriği İzleme

```spl
-- Aylık detection coverage metriği
| makeresults
| eval threat_categories=mvappend(
    "Privilege Abuse::UC1::ACTIVE",
    "Runtime Manipulation::UC2::ACTIVE",
    "Lateral RFC Movement::UC3::ACTIVE",
    "Identity Takeover::UC4::ACTIVE",
    "SoD Violation::UC5::PARTIAL",
    "Data Leakage Ops::UC6::PARTIAL",
    "Workflow Abuse::UC7::PARTIAL",
    "Monitoring Sabotage::UC8::ACTIVE",
    "Brute Force::UC9::ACTIVE",
    "Service Account Abuse::UC10::ACTIVE",
    "ABAP Code Injection::NONE::MISSING",
    "Unpatched Exploit::NONE::MISSING",
    "Spool Exfiltration::NONE::MISSING")
| mvexpand threat_categories
| eval parts=split(threat_categories,"::")
| eval category=mvindex(parts,0)
| eval use_case=mvindex(parts,1)
| eval status=mvindex(parts,2)
| stats count AS total,
        sum(eval(status="ACTIVE"))   AS active_rules,
        sum(eval(status="PARTIAL"))  AS partial_rules,
        sum(eval(status="MISSING"))  AS missing_rules
| eval coverage_pct=round(
    ((active_rules + (partial_rules*0.5)) / total) * 100, 1)
| table total, active_rules, partial_rules,
        missing_rules, coverage_pct
```

Bu sorgu her ay çalıştırıldığında coverage tablosunu günceller ve Bölüm 8'deki çeyreklik raporun coverage bölümünü besler.

## SAP Enterprise Threat Detection (ETD) ile SIEM İlişkisi

### SAP ETD Nedir

SAP Enterprise Threat Detection (ETD), SAP'ın kendi güvenlik izleme ve olay tespit platformudur. SAP'ın içine entegre bir çözüm olarak SAP HANA üzerinde çalışır ve SAP loglarını yerel olarak, SAP'a özgü bağlamla analiz eder.

SAP ETD'nin Splunk veya QRadar gibi bir genel amaçlı SIEM'den farkları şunlardır:

| Özellik | SAP ETD | Splunk/QRadar |
|---|---|---|
| SAP log kaynaklarına erişim | Yerel, native, tüm log tipleri | Connector/Add-on bağımlı |
| SAP bağlam zenginliği | T-code, yetki objesi, iş bağlamı | Add-on/lookup bağımlı |
| SAP dışı kaynaklar | Sınırlı (bazı sürümlerde genişletilmiş) | Tam destek |
| Hazır SAP use-case'leri | Kapsamlı, SAP tarafından bakımlı | Sınırlı (Add-on içeriği) |
| Multi-system korelasyon | Evet (SAP landscape dahilinde) | Evet (tüm kaynaklar) |
| Maliyet | SAP lisansı ek maliyeti | Bağımsız lisans |
| SOC entegrasyonu | SAP ekosistemiyle derin, SOC ile zayıf | SOC'un ana aracıyla entegre |
| Non-SAP olay korelasyonu | Zayıf | Güçlü |

### ETD ve SIEM Birlikte Kullanım Modelleri

SAP ETD ile SIEM'in ilişkisi "birini seç, diğerini bırak" değil, "hangisinin hangi rolü üstleneceği" sorusudur. Üç farklı model mümkündür:

**Model A — Yalnızca SIEM (bu serinin yaklaşımı):**
SAP ETD yok veya lisanslanmamış. SAP logları Add-on üzerinden Splunk/QRadar'a taşınır, tüm detection SIEM'de yapılır. Avantajı tek platform, tek öğrenme eğrisi, non-SAP kaynaklarla tam korelasyon. Dezavantajı SAP bağlam zenginliğinin Add-on sınırlarıyla kısıtlı kalması.

```
SAP → Add-on → Splunk → Tüm Detection + Raporlama
```

**Model B — ETD Önde, SIEM Arkada:**
SAP ETD SAP-özgü detection'ı üstlenir; ETD'nin ürettiği alarmlar SIEM'e iletilir ve non-SAP kaynaklarla korelasyon SIEM'de yapılır. Bu, her iki platformun güçlü yanını kullanan ama iki platform yönetimi gerektiren modeldir.

```
SAP → ETD (SAP detection)
              │ Alarm/olay çıktısı
              ▼
           Splunk (non-SAP korelasyon + SOC workbench)
```

**Model C — Paralel İzleme:**
Her iki platform da bağımsız olarak SAP loglarını izler. ETD Basis/güvenlik ekibinin arayüzüdür; SIEM SOC'un arayüzüdür. İkisi arasında alarm paylaşımı yapılır ama bağımlılık minimumdur. En yüksek maliyet ve bakım yükü, ama en yüksek esneklik.

```
SAP → ETD (Basis ekibi arayüzü)
SAP → Splunk Add-on → Splunk (SOC arayüzü)
ETD Alarmları → Splunk'a iletilir (opsiyonel)
```

### ETD Olgunluk Yolculuğunda Bir Sonraki Adım mı?

SAP ETD, Seviye 4-5 olgunluk hedefleyen kuruluşlar için değerlendirmeye alınması gereken bir araçtır. Ama bu değerlendirme şu soruları sormadan yapılmamalıdır:

Mevcut SIEM'de SAP coverage'ı ne kadar? ETD, mevcut %78 coverage'ı gerçekten %95'e çıkarıyor mu yoksa zaten kapsadığımız alanları mı kapsıyor?

SOC ETD'yi kullanacak mı? ETD, SAP'a çok derin entegre bir araçtır ve Basis ekibi için daha doğal bir arayüz sunar. SOC analistleri iki farklı platform arasında geçiş yapmak zorunda kalacaksa, operasyonel verimliliği olumsuz etkileyebilir.

Toplam sahip olma maliyeti nedir? ETD lisansı, HANA altyapısı ve bakım maliyeti SIEM'deki ek kural geliştirme maliyetiyle karşılaştırmalı değerlendirilmelidir.

Bu soruların yanıtları kuruma göre değişir. Bu seri, ETD'yi reddetmiyor — ETD'ye geçiş veya ETD ile birlikte çalışma kararı, önce SIEM'de sağlam bir temel kurulduktan sonra verildiğinde çok daha verimli sonuç üretir. Sağlam bir temel olmadan ETD satın almak, mimarinin üzerindeki güvenlik katmanını atlayıp araç satın almaya benzer.

## Sürekli İyileştirme Döngüsü

### Üç Aylık Kaizen Döngüsü

SAP güvenlik programı "kurulup bırakılan" bir yapı değildir. Aşağıdaki üç aylık döngü, programın canlı tutulmasını sağlar:

```
AY 1: ÖLÇÜM
  □ Coverage metriği güncelleme (Splunk sorgusu)
  □ False positive oranlarının analizi
  □ Alarm SLA uyum oranının hesaplanması
  □ Olgunluk matrisi skorlaması
  □ Periyodik operasyonel kontrol takvimi gözden geçirme

AY 2: ANALİZ
  □ Geçen çeyreğin gerçek olaylarından öğrenilen dersler
  □ Kapsanmayan tehdit kategorileri için önceliklendirme
  □ False positive yüksek olan kuralların kök neden analizi
  □ Log kaynakları sağlık kontrolü — yeni sistem/client var mı?
  □ Lookup tablolarının (kritik T-code, SoD matrisi, RFC whitelist)
    güncellik kontrolü

AY 3: İYİLEŞTİRME
  □ Önceliklendirilmiş yeni use-case'lerin geliştirilmesi
  □ Revize edilen kuralların test ortamında doğrulanması
  □ Güncellenmiş lookup tablolarının production'a alınması
  □ Yönetim raporuna çeyreklik değerlendirme eklenmesi
  □ Bir sonraki çeyreğin hedef coverage seviyesinin belirlenmesi
```

Bu döngü, Bölüm 6'daki periyodik operasyonel takvimiyle örtüşür ve Bölüm 8'deki çeyreklik raporun içeriğini doğal olarak üretir. Üç bölüm birlikte, programın "nerede duruyoruz → nereye gitmeliyiz → nasıl gideceğiz" sarmalını sürekli döndürür.

### Tehdit Avcılığı: Seviye 4'ten 5'e Geçiş

Seviye 4 olgunluğa ulaşılmıştır — tüm kritik use-case'ler kapsanıyor, raporlama otomatik çalışıyor, olay müdahale playbook'ları belgelenmiş. Seviye 5'e geçişin ayırt edici özelliği **proaktif tehdit avcılığıdır (threat hunting)**.

Reaktif detection "bilinen bir olay gerçekleşti" dediğinde alarm üretir. Threat hunting ise "bilmediğimiz bir tehdit şu an sistemde aktif mi?" sorusunu sormak için SIEM verisini aktif olarak araştırır — alarm beklemeden.

SAP bağlamında threat hunting başlangıç noktaları:

**Hunt 1 — Hiç alarm tetiklememiş yüksek yetkili hesaplar:**
```spl
-- SAP_ALL sahibi ama hiç alarm üretmemiş hesaplar
-- (Sessizce suistimal mi ediliyor?)
| inputlookup user_authorization_snapshot.csv
| search profile="SAP_ALL"
| join type=left username [
    search index=notable user=*
           rule_name="SAP_ALL_ASSIGNED"
           earliest=-90d
    | stats count AS alarm_count BY user
    | rename user AS username
]
| where isnull(alarm_count)
| eval risk_note="SAP_ALL sahibi, 90 günde hiç alarm yok — pasif mi?"
| table username, sap_system, sap_client, risk_note
```

**Hunt 2 — Baseline dışı fonksiyon modülü çağrıları:**
Gateway loglarında daha önce hiç görülmemiş bir RFC fonksiyon modülü çağrılıyorsa, bu yeni bir entegrasyon mu, yoksa bir backdoor'un keşfi mi?

```spl
index=sap_audit sourcetype="sap:gateway"
    earliest=-7d latest=now
| stats count AS recent_count BY signature, src_system
| join type=left signature src_system [
    search index=sap_audit sourcetype="sap:gateway"
           earliest=-90d latest=-7d
    | stats count AS historical_count BY signature, src_system
]
| where isnull(historical_count)
| eval risk_note="Son 90 günde hiç görülmemiş RFC çağrısı"
| table _time, signature, src_system, recent_count, risk_note
```

**Hunt 3 — Olağandışı saatlerde batch job aktivitesi:**
Normalde belirli saatlerde çalışan batch job'ların zaman profili değişmişse, bu bir schedule manipülasyonu veya yetkisiz işlem ekleme girişimine işaret edebilir.

Threat hunting, SOC analistlerinin SAP bağlamına yeterince hakim olmasını gerektirir — bu da Basis ekibinin hunt oturumlarına aktif katılımını zorunlu kılar. "Ortak tehdit avcılığı" seansları, SOC-Basis işbirliğini derinleştirmenin ve karşılıklı bilgi transferinin en verimli yollarından biridir.

## Yol Haritası: Kısa, Orta ve Uzun Vade

### Kısa Vade (0-3 Ay): Temeli Sağlamlaştır

Bu serinin Bölüm 2-5'ini uygulama aşamasıdır. Henüz tamamlanmamış maddelerin öncelik sırasına göre listesi:

```
□ Security Audit Log tüm client'larda etkin mi?
  → Evet: Devam
  → Hayır: Acil, Bölüm 2'nin ilk adımı

□ SIEM'e log akışı stabil ve tam mı?
  → Her sistem/client'tan beklenen log geliyor mu?
  → Reconciliation sorgusu günlük çalışıyor mu?

□ UC1 (SAP_ALL) ve UC8 (meta alarm) aktif mi?
  → Bu ikisi en kritik iki tekil kural,
    diğer her şeyden önce çalışır hale getirilmeli

□ Temel lookup tabloları hazır mı?
  → rfc_expected_sources.csv
  → system_service_accounts.csv
  → kritik_tcode_list.csv
  → user_normal_terminals.csv (90 günlük geçmişten)

□ SOC-Basis eskalasyon prosedürü yazılı mı?
  → Kimin kimi ne zaman aradığı netleştirilmeli
```

### Orta Vade (3-12 Ay): Coverage'ı Genişlet

```
□ UC4 (çapraz model korelasyon) ve UC7 (workflow)
  için gerekli lookup tablolarını üret ve kuralları
  devreye al

□ SoD matrisini GRC veya manuel olarak oluştur
  ve UC5'i buna bağla

□ Haftalık ve aylık raporları otomatikleştir
  → Bölüm 8'deki scheduled search yapılandırmaları

□ İlk SAP olay müdahale tatbikatını gerçekleştir
  → Kontrollü bir test senaryosu (örn. test client'ında
    SAP_ALL ataması) üzerinden triage-forensics-kapanma
    döngüsünü test et

□ Yamalanmamış ABAP kodu enjeksiyonu use-case'ini
  geliştir (CVA çıktısını SIEM'e besle)

□ Spool/yazdırma bazlı veri exfiltration
  use-case'ini değerlendir

□ Coverage metriğini %85+ seviyeye taşı
```

### Uzun Vade (12+ Ay): Olgunluk ve Optimizasyon

```
□ SAP ETD değerlendirmesi yap
  → Mevcut coverage boşluklarına göre ETD'nin gerçek
    ek değerini ölç
  → Model B (ETD önde, SIEM arkada) kurumun
    ihtiyaçlarına uyuyor mu?

□ Threat hunting programını başlat
  → Ayda bir ortak SOC-Basis hunt oturumu
  → Hunt bulguları use-case geliştirme backlog'una giriyor

□ SIEM lookup tablolarının otomatik güncellenmesini sağla
  → SAP'tan periyodik yetki snapshot'ı
  → GRC Access Control → SoD matrisi otomatik beslemesi
  → Change management sistemi → approved_transports.csv

□ Risk-Based Alerting'i (Splunk ES) veya muadilini
  devreye al → Bölüm 5'teki risk skoru mantığının
  platform seviyesinde uygulanması

□ Olgunluk seviyesi 4 → 5 geçişini belgelenmiş
  önce/sonra metrikleriyle raporla
```

## Serinin Tamamı İçin Hızlı Referans Checklist

Bu seriyi uygulayan bir ekibin "nerede duruyoruz" sorusunu yanıtlamak için kullanabileceği tek sayfalık checklist:

### Loglama (Bölüm 2)
```
□ Security Audit Log tüm production client'larında etkin
□ Security Audit Log tüm test/sandbox client'larında etkin
□ Kritik olay kategorileri (logon, user management, sysadmin) açık
□ Generic/servis hesapları için ayrı filtre tanımlanmış
□ Tablo loglama kritik tablolar için etkin (USR02, AGR_1251, LFA1 vb.)
□ Z-tablolar tablo loglama kapsamında değerlendirilmiş
□ Gateway loglama ve ACL dosyaları (secinfo/reginfo) yapılandırılmış
□ Log bütünlüğü koruması (imzalama) değerlendirilmiş/etkin
□ Retention politikası SIEM aktarım sıklığıyla uyumlu
□ Audit log yapılandırma değişiklikleri izleniyor (meta-kontrol)
```

### SIEM Entegrasyonu (Bölüm 3-4)
```
□ SAP Add-on for Splunk kurulu ve yapılandırılmış
□ Connector tipi seçilmiş (RFC/Java) ve güvenli yapılandırılmış
□ Tüm instance'lardan log toplanıyor (çoklu AS kontrolü)
□ props.conf zaman damgası ve encoding doğru
□ CIM field mapping (Authentication, Change, Network) doğrulanmış
□ Günlük reconciliation sorgusu çalışıyor
□ Multi-client metadata (sap_system, sap_client) her event'te mevcut
□ Data model acceleration etkin (en az Authentication + Change)
□ Kritik lookup tabloları oluşturulmuş ve güncel
```

### Detection (Bölüm 5)
```
□ UC1: SAP_ALL/SAP_NEW atama alarmı aktif
□ UC2: Debug & Replace alarmı aktif
□ UC3: Beklenmedik RFC kaynağı alarmı aktif
□ UC4: Şifre sıfırlama + terminal korelasyonu aktif
□ UC5: SoD ihlal tespiti (SoD matrisi mevcut)
□ UC6: Client copy + erişim artışı alarmı aktif
□ UC7: Workflow vekalet suistimali alarmı aktif
□ UC8: Audit log meta alarmı aktif (en kritik)
□ UC9: Başarısız logon eşik değerleri ayarlanmış
□ UC10: Servis hesabı interaktif logon alarmı aktif
□ Birleşik risk skoru sorgusu günlük çalışıyor
□ False positive log tablosu kullanımda
```

### Operasyonel Güvenlik (Bölüm 6)
```
□ Aylık RSECNOTE taraması yapılıyor
□ Transport onay süreci change management'a bağlı
□ RFC destination envanteri çeyreklik güncelleniyor
□ Trusted system ilişkileri çeyreklik gözden geçiriliyor
□ SoD matrisi çeyreklik güncelleniyor
□ Gateway ACL dosyaları çeyreklik kontrol ediliyor
□ Periyodik güvenlik kontrol takvimi belgelenmiş ve uygulanıyor
```

### Olay Müdahalesi (Bölüm 7)
```
□ SOC-Basis eskalasyon prosedürü belgelenmiş
□ SAP_ALL alarmı için playbook yazılmış
□ Forensics araçları (ST22, SM21, DBTABLOG, SUIM) SOC'a öğretilmiş
□ Kanıt koruma prosedürü var
□ False positive karar süreci yapılandırılmış
□ Post-incident review şablonu mevcut
□ En az bir tatbikat gerçekleştirilmiş
```

### Raporlama (Bölüm 8)
```
□ Günlük operasyonel özet otomatik gidiyor
□ Haftalık yetki değişikliği raporu otomatik
□ Aylık yönetim raporu üretiliyor
□ SOX denetim kanıt paketi hazır
□ KVKK hassas tablo erişim raporu aktif
□ Splunk dashboard kurulu ve güncel
□ Çeyreklik durum değerlendirmesi raporlanıyor
```

## Serinin Kapanışı

Bu seri, SAP güvenliğini "bir ürün satın al, bir araç kur" meselesi olarak değil, organizasyonun içine işlemesi gereken bir disiplin olarak ele aldı. Bölüm 1'den bu bölüme kadar sürekli tekrar eden tek mesaj şuydu: **loglama, tespit, operasyon, müdahale ve raporlama birbirinden bağımsız değildir; her biri diğerinin üzerine inşa edilir ve her birindeki boşluk diğerlerini zayıflatır.**

SAP Basis ekibi bu seriyi okuduysa, tek çıkarım şu olmalı: SOC, SAP'ı anlamadan sizi koruyamaz — ama siz SOC'a bağlam ve loglama alt yapısı sağlamadan, SOC'un elinde çalışacak hiçbir şey olmaz. İşbirliği, "iyiye sahip olunursa iyi olan" bir seçenek değil; tüm bu yapının çalışabilmesinin önkoşuludur.

SAP güvenliği sürekli değişen bir alan: yeni SAP ürünleri (SAP S/4HANA, SAP BTP, SAP Fiori), yeni saldırı teknikleri ve yeni uyumluluk gereksinimleri bu alanı sürekli güncel tutar. Bu seri bir başlangıç noktası ve referans çerçevesidir — burada inşa edilen temelin üzerine, kurumun kendi bağlamına ve önceliklerine göre katman katman ekleme yapmak bu yolculuğun doğal devamıdır.
