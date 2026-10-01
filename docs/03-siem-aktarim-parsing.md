---
layout: default
title: "Bölüm 3: Logların SIEM'e Aktarılması ve Parsing"
nav_order: 3
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/03-siem-aktarim-parsing/
---


## Bölüm 2'den Bölüm 3'e: Kaynak Hazır, Sıra Köprüde

Bölüm 2'de SM19/SM20 ile Security Audit Log'u yapılandırdık, tablo loglamayı belirli tablolara açtık, Gateway logging'i devreye aldık ve SM21'i nasıl okuyacağımızı gördük. Artık kaynakta doğru olaylar üretiliyor. Ama bu loglar SAP'ın kendi dosya sistemi veya veritabanında duruyor; henüz SIEM'in görebileceği bir biçimde ve yerde değil.

Bu bölümde logların SAP'tan Splunk'a nasıl taşındığını — ve taşınırken neden çoğu şeyin beklendiği gibi gitmediğini — işliyoruz. Mimariyi, connector seçeneklerini, veri akış modelini ve en sık karşılaşılan parsing sorunlarını adım adım ele alacağız. QRadar için ayrı bir log source yaklaşımı da bu bölümde yer alıyor.

## Veri Akış Mimarisi: Büyük Resim

Bir SAP logunu Splunk'ta anlamlı bir alarmın hammaddesi haline getirmek için en az üç ayrı eşiği geçmesi gerekir: **toplanma** (SAP'tan okunma), **aktarım** (Splunk'a gönderilme) ve **normalizasyon** (parse edilme, alan adlarının CIM'e eşlenmesi). Bu üç adımın her birinde bağımsız olarak hata yapılabilir ve her adımdaki hata sonraki adımı görünmez biçimde bozabilir:

```
┌──────────────────────────────────────────────────┐
│                  SAP Sistemi                      │
│                                                   │
│  Security Audit Log   System Log   DBTABLOG       │
│  (dosya/DB)           (SM21)       (DB tablosu)   │
│         │                  │            │          │
│         └──────────────────┼────────────┘          │
│                            │                       │
│              SAP Add-on Connector                  │
│         (ABAP Extractor veya Java Connector)       │
└────────────────────┬─────────────────────────────-┘
                     │
          Güvenli kanal (HTTPS/TLS)
          Port: 443 (veya kurum politikasına göre)
                     │
┌────────────────────▼─────────────────────────────┐
│              Splunk Heavy Forwarder                │
│         (veya Universal Forwarder + HF)           │
│                                                   │
│  - SAP Add-on for Splunk (props.conf/transforms)  │
│  - sourcetype: sap:audit, sap:syslog, vb.         │
│  - CIM field mapping (Authentication,             │
│    Change, Network Traffic data model)            │
└────────────────────┬─────────────────────────────-┘
                     │
          Splunk forwarder protokolü (9997)
                     │
┌────────────────────▼─────────────────────────────┐
│              Splunk Indexer / Cluster              │
│                                                   │
│  - Index: sap_audit, sap_change, sap_syslog       │
│  - Retention politikası (Bölüm 2 ile uyumlu)     │
│  - Arama, korelasyon, detection kuralları         │
│    (Bölüm 4 ve 5'te işlenecek)                   │
└───────────────────────────────────────────────────┘
```

Bu şemada iki kritik seçim noktası var: **connector türü** (SAP tarafında ne çalışıyor) ve **forwarder mimarisi** (Splunk tarafında ara katman var mı, yok mu). Her ikisi de hem güvenlik hem de operasyonel dayanıklılık açısından önemli kararlar içeriyor.

## SAP Add-on for Splunk: İki Connector Seçeneği

SAP Add-on for Splunk, iki farklı extractor/connector modeli sunar. Bu ikisi zaman zaman birbirinin yerine kullanılabiliyormuş gibi anlatılsa da, mimarileri, kurulum gereksinimleri ve güvenlik profilleri birbirinden önemli ölçüde farklıdır.

### ABAP Extractor (RFC Tabanlı)

```
Splunk Forwarder
      │
      │  RFC çağrısı (SAP .NET/Java RFC library)
      ▼
SAP ABAP Application Server
      │
      │  ABAP Function Module çağrısı
      ▼
Security Audit Log / DBTABLOG / SM21
      │
      └── Veri → Forwarder'a dönüyor
```

ABAP extractor, SAP'a dışarıdan bir RFC bağlantısıyla bağlanarak ABAP tarafında çalışan fonksiyon modülleri aracılığıyla log verisi çeker. Bu modelin avantajı SAP sistemi içinde hiçbir ek bileşen kurulmasına gerek olmaması ve standart RFC güvenlik mekanizmalarının (SNC/SSL, RFC kullanıcı tipi, S_RFC authorization) kullanılabilmesidir.

Dezavantajı ise RFC bağlantısının SAP ağına açık bir port gerektirmesi ve büyük log hacimlerinde RFC tabanlı veri çekiminin performans sınırlarına ulaşabilmesidir. Ayrıca, ABAP extractor'ın SAP sistemiyle aynı ağ segmentinde veya en azından RFC portuna erişimi olan bir konumda bulunması gerekir — bu, ağ segmentasyon politikalarıyla çatışabilir.

**RFC kullanıcısı için gerekli minimum yetki yapılandırması:**

```
Yetki Objesi    Alan           Değer
────────────────────────────────────────────────
S_RFC           RFC_TYPE       FUGR (Function Group)
S_RFC           RFC_NAME       SALG, SUSR, SYST, ...
                               (Add-on'un kullandığı
                               function group'lara göre)
S_RFC           ACTVT          16 (Execute)

S_TABU_DIS      DICBERCLS      &NC&, SS (gerekli
                               tablo yetki grupları)
S_TABU_DIS      ACTVT          03 (Display)
```

Bu kullanıcının türü **System** veya **Communication** olarak tanımlanmalı; interaktif giriş kapatılmalıdır. SAP_ALL kesinlikle verilmemelidir — bölüm 1'de ele aldığımız en kötü pratiklerden biri, entegrasyon kullanıcılarına kolaylık olsun diye geniş yetki vermektir.

### Java Connector (SAP JCo Tabanlı)

```
SAP Java Connector (JCo) Servisi
      │  (SAP sistemi ile aynı host'ta veya
      │   ayrı bir middleware sunucusunda çalışır)
      │
      │  JCo üzerinden SAP'a bağlantı
      ▼
SAP ABAP Application Server
      │
      └── Log verisi → JCo Servisi
                           │
                           │  HTTP/HTTPS push
                           ▼
                    Splunk HEC (HTTP Event Collector)
```

Java connector modeli, ortada bir SAP JCo servisi çalıştırır; bu servis SAP'a JCo üzerinden bağlanır ve Splunk'a Splunk HEC (HTTP Event Collector) üzerinden push yapar. Ağ topolojisi açısından daha esnektir çünkü JCo servisi ile Splunk arasındaki iletişim standart HTTPS üzerinde çalışır ve SAP ağı ile Splunk ağının doğrudan birbirine görünmesi gerekmez.

Dezavantajı, ek bir JCo middleware bileşeni yönetmek zorunda kalınmasıdır — bu, hem kurulum karmaşıklığını artırır hem de izlenmesi gereken ek bir servis/süreç demektir. JCo sürüm uyumluluğu, SAP kernel sürümleriyle bazen çatışır ve bu uyumsuzluklar sessiz veri kaybına (log hiç gelmiyor ama hata da görünmüyor) yol açabilir.

### Hangi Connector'ı Seçmeli

Her iki modeli de değerlendirirken aşağıdaki kriter tablosunu referans almak faydalıdır:

| Kriter | ABAP Extractor (RFC) | Java Connector (JCo) |
|---|---|---|
| Ağ gereksinimleri | SAP RFC portuna (33xx/48xx) doğrudan erişim | Yalnızca HTTPS (443) yeterli |
| Ek bileşen | Yok (SAP'ta ek kurulum gereksiz) | JCo middleware servisi |
| Büyük hacim performansı | RFC sınırlarına ulaşabilir | Daha ölçeklenebilir |
| Kurulum karmaşıklığı | Düşük-Orta | Orta-Yüksek |
| Güvenlik yapılandırması | RFC ACL, SNC, S_RFC yetki | JCo kimlik bilgisi yönetimi, HTTPS sertifikası |
| Ağ segmentasyonuyla uyum | Potansiyel sorun | Daha uyumlu |
| İdeal senaryo | Splunk forwarder SAP ağına yakın | SAP ağı ile Splunk ağı ayrı segmentte |

## Splunk Heavy Forwarder'ın Rolü

SAP Add-on for Splunk'ın props.conf ve transforms.conf tanımlarının çalışması için Add-on'un veriyi işleyen katmanda kurulu olması gerekir. Universal Forwarder bu dönüşümleri tek başına yapamaz; dolayısıyla SAP log akışı için mimari seçenekler ikiye ayrılır:

**Seçenek A — Heavy Forwarder (önerilen):** SAP ağına erişimi olan bir Heavy Forwarder üzerinde Add-on kurulur. Bu HF hem toplama hem parsing görevini üstlenir; sonra Splunk Indexer'a gönderirim yapar.

**Seçenek B — Universal Forwarder + Indexer'da parsing:** UF sadece veriyi ham haliyle toplar ve Indexer'a gönderir; parsing ve CIM mapping Indexer üzerinde (veya bir Search Head'de) yapılır. Bu model daha az yaygındır ve Add-on'un tüm Indexer'lara kurulmasını gerektirir.

Küçük ortamlarda bu ayrım önemsiz görünebilir; ama SAP sistemlerinin sayısı arttıkça (birden fazla landscape, birden fazla client) merkezi bir Heavy Forwarder katmanı hem yönetilebilirlik hem de tutarlılık açısından net bir avantaj sağlar.

## Sourcetype, Index ve Metadata Yapısı

SAP Add-on for Splunk, farklı log kaynaklarını ayrı sourcetype'larla etiketler. Bu ayrım hem arama performansı hem de CIM mapping doğruluğu için kritiktir:

| Log Kaynağı | Sourcetype | Önerilen Index |
|---|---|---|
| Security Audit Log (SAL) | `sap:audit` | sap_audit |
| System Log (SM21) | `sap:syslog` | sap_syslog |
| ABAP Dump (ST22) | `sap:abap:dump` | sap_audit |
| Spool Log | `sap:spool` | sap_audit |
| Gateway Log | `sap:gateway` | sap_audit |
| Change Documents (CDHDR) | `sap:change` | sap_change |

Her event'e aynı zamanda `sap_system` (SAP sistem kimliği, örn. PRD/DEV/QAS), `sap_client` (mandant numarası) ve `sap_instance` (uygulama sunucusu instance adı) gibi ek metadata alanları eklenmesi, ilerideki SIEM kurallarında "bu olay production client'ında mı, test client'ında mı" sorusunu yanıtlamak için zorunludur.

## CIM Mapping: SAP Eventlerini Ortak Bir Dile Çevirmek

Splunk CIM (Common Information Model), farklı kaynaklardan gelen eventleri standart alan adlarıyla normalize eder — böylece SAP'tan gelen bir logon başarısızlığı ile Windows'tan gelen bir logon başarısızlığı aynı `Authentication` data model alanlarını paylaşır ve korelasyon kuralları tüm kaynaklar üzerinde tutarlı çalışır.

SAP eventleri için en sık kullanılan üç CIM data model şunlardır:

### Authentication Data Model (Logon Olayları)

SAP Security Audit Log'daki dialog ve RFC logon eventleri bu modele eşlenir:

| SAP Ham Alan | CIM Alan Adı | Açıklama |
|---|---|---|
| AuSubNum (kullanıcı adı) | `user` | Giriş yapan SAP kullanıcısı |
| AuTermNm (terminal/host) | `src` | Bağlantı kaynağı |
| AuMandant (client/mandant) | `app` | Hangi SAP client'ı |
| AuTCode (transaction) | `signature` | Çalıştırılan işlem |
| AuSysId (sistem ID) | `dest` | Hedef SAP sistemi |
| Olay tipi (başarılı/başarısız) | `action` | "success" / "failure" |
| Zaman damgası (UTC dönüştürülmüş) | `_time` | Splunk event zamanı |

Dikkat edilmesi gereken nokta: SAP loglarındaki zaman damgası SAP uygulama sunucusunun yerel saatindedir — UTC değil. Bu, özellikle farklı zaman dilimlerinde çalışan sistemleri olan kurumlarda korelasyonu bozabilir. Bölüm 2'de "SIEM'e aktarım gecikmesiyle uyum" başlığında değindiğimiz zaman damgası sorununu aşağıda ayrıca detaylandırıyoruz.

### Change Analysis Data Model (Değişiklik Olayları)

Kullanıcı master değişiklikleri, rol/yetki atamaları, tablo loglama (DBTABLOG) kayıtları ve Change Documents bu modele eşlenir:

| SAP Ham Alan | CIM Alan Adı | Açıklama |
|---|---|---|
| Değiştiren kullanıcı | `user` | Değişikliği yapan SAP kullanıcısı |
| Değiştirilen nesne tipi | `object_category` | Tablo adı, nesne tipi |
| Nesne ID | `object_id` | Etkilenen kayıt/satır |
| Eski değer | `old_value` | Değişiklik öncesi |
| Yeni değer | `new_value` | Değişiklik sonrası |
| İşlem | `action` | "modified", "created", "deleted" |

Bu eşlemenin doğru çalışması, Bölüm 1'deki Senaryo 1 (SAP_ALL ataması) ve Senaryo 4 (şifre sıfırlama ile hesap devralma) gibi vakalar için kritiktir: "hangi kullanıcı, hangi hesaba, hangi yetkiyi atadı" sorusu tam olarak bu model üzerinden yanıtlanır.

### Network Traffic / Endpoint Data Model (RFC / Gateway)

Gateway logları ve RFC bazlı bağlantı olayları için:

| SAP Ham Alan | CIM Alan Adı | Açıklama |
|---|---|---|
| RFC kaynak sistem | `src` | Çağrıyı yapan sistem |
| SAP hedef sistem | `dest` | Çağrıyı alan sistem |
| Fonksiyon grubu / modül | `signature` | Çağrılan RFC |
| Bağlantı tipi | `transport` | RFC, CPIC, HTTP vb. |
| Sonuç | `action` | "allowed", "blocked" |

## Parsing: Ham SAP Logu Nasıl Görünür ve Neden Sorun Çıkar

SAP'ın ham log formatını bir kere görmek, parsing sorunlarını neden atlamamak gerektiğini anlamak için yeterlidir. Aşağıda bir Security Audit Log satırının ham hali:

```
20240315 083412 PRD 100 BASISUSR SU01 AU1
BENUTZER: TESTUSER MANDANT: 100
PROFIL ZUGEWIESEN: SAP_ALL
TERMINAL: 10.1.2.3
```

Ve aynı satırın kötü parse edilmiş hali:

```
raw_event = "20240315 083412 PRD 100 BASISUSR SU01 AU1 BENUTZER: ..."
```

Bu durumda SIEM, event'i tek bir ham metin satırı olarak görür; hangi kullanıcının hangi işlemi yaptığını, kaynağın ne olduğunu, olay tipinin ne anlama geldiğini bilmez. Korelasyon kuralları bu satır üzerinde çalışamaz.

Şimdi parsing sürecinde sık karşılaşılan dört kritik sorunu ele alalım.

### Sorun 1: Zaman Damgası Dönüşümü

SAP Security Audit Log kayıtları, uygulama sunucusunun yerel saatiyle damgalanır. Türkiye'de çalışan bir SAP sistemi UTC+3 saat diliminde olabilir; ama Splunk'un tüm kaynaklardan gelen olayları UTC'de normalize etmesi beklenir. Bu fark göz ardı edilirse:

- Aynı olaya ait iki farklı sistemden gelen log satırları 3 saatlik kayma nedeniyle korelasyon kuralında eşleşemez.
- "Mesai saatleri dışında işlem" kuralı, aslında mesai saati içindeki bir olayı gece 1'de gerçekleşmiş gibi gösterir ve alarm üretir.
- Adli analiz (Bölüm 7) sırasında olay zaman çizelgesi yanlış kurulur.

`props.conf` içinde sourcetype seviyesinde `TZ = Europe/Istanbul` veya `MAX_TIMESTAMP_LOOKAHEAD` parametreleriyle bu dönüşüm yapılabilir, ama SAP'ın tarih/saat formatı (`YYYYMMDD HHMMSS`) standart dışı olduğundan özel bir zaman damgası ayrıştırma ifadesi de gerekebilir:

```ini
# props.conf örneği
[sap:audit]
TIME_FORMAT = %Y%m%d %H%M%S
TZ = Europe/Istanbul
MAX_TIMESTAMP_LOOKAHEAD = 15
```

Bu ayarın gerçekten doğru çalıştığını doğrulamak için `index=sap_audit | eval diff=now()-_time | stats max(diff) as max_lag` gibi basit bir SPL sorgusuyla event zamanı ile Splunk'ın `_time`'ı arasındaki fark kontrol edilebilir.

### Sorun 2: Dil ve Encoding

SAP sistemleri farklı dillerde ve farklı character encoding'lerle çalışabilir. Türkçe SAP sistemleri için genellikle SAP'ın kendi karakter setleri (örn. SAP Code Page 1610 — Türk dili) veya Unicode (UTF-8) kullanılabilir. Log mesajlarının dili de SAP arayüz dilinden etkilenebilir; bazı sistemlerde mesaj metinleri Almanca'ya düşebilir (SAP'ın kendi dili Almanca olduğundan, bazı standart mesajlar varsayılan Almanca döner).

Bu iki sorunun pratik etkisi şudur: bir regex bazlı parser, "PROFIL ZUGEWIESEN: SAP_ALL" (Türkçe: "Profil Atandı: SAP_ALL") mesajını ayrıştırmak için yazılmışsa, aynı mesajın Almanca versiyonu "PROFIL VERGEBEN: SAP_ALL" biçiminde geldiğinde parser çalışmaz.

Çözüm: alan bazlı yapısal parsing'i (ham mesaj yerine yapısal alanları ayrıştırma) tercih etmek ve dil bağımsız olay sınıfı kodlarını (AU1, AU3 gibi) birincil ayrıştırma kriteri olarak kullanmak.

### Sorun 3: Multi-Client ve Multi-Instance Ortamlar

Bölüm 2'de vurguladığımız gibi, aynı SAP sistemi içinde birden fazla client çalışabilir; aynı landscape içinde birden fazla uygulama sunucusu instance'ı bulunabilir. Her instance kendi log dosyasını üretir; her client kendi olay akışına sahiptir.

Bu ortamda üç yaygın hata görülür:

**Hata A:** Yalnızca production client'ının logu alınır; test client'ından gelen olaylar (örneğin Bölüm 1 Senaryo 3'teki RFC trust suistimali başlangıcı) sessizce kaçırılır.

**Hata B:** `sap_client` alanı event'e eklenmez; dolayısıyla "bu alarm production'da mı, test'te mi" sorusu SIEM tarafında yanıtlanamaz hale gelir.

**Hata C:** Bazı instance'ların log dosyaları forwarder tarafından okunmaz; o instance'lardaki olaylar hiç görülmez. Bu, özellikle yatay ölçeklenmiş (multiple application server) ortamlarda sinsi bir kör noktadır.

Bu sorunları tespit etmek için düzenli bir reconciliation sorgus faydalıdır:

```spl
index=sap_audit earliest=-24h
| stats count by sap_system, sap_client, sap_instance
| where count < 10
```

Bu sorgu, son 24 saatte beklenenden az event gelen sistem/client/instance kombinasyonlarını ortaya çıkarır — log akışında sessiz bir kopukluk varsa ilk burada görünür.

### Sorun 4: Log Rotasyonu ile Toplama Gecikmesi Uyumsuzluğu

Bölüm 2'de teorik olarak değindiğimiz bu sorun pratikte şöyle görünür: SAP'ın Security Audit Log dosyası, yapılandırılan boyuta ulaştığında veya günlük rotasyon saatinde yeni bir dosyaya geçer. Eğer Splunk forwarder bu rotasyon gerçekleşmeden önce dosyayı okumadıysa ve eski dosya arşivlenerek farklı bir konuma taşındıysa, forwarder yeni konumu takip edemeyebilir ve o aralıktaki tüm loglar kalıcı olarak kaybolur.

Bu sorunu önlemek için üç yapısal önlem alınmalıdır: forwarder'ın checkpoint mekanizmasını (CRC check) doğru yapılandırmak, rotasyon öncesinde en az bir kez tam okuma gerçekleştiğini garanti edecek bir toplama sıklığı (polling interval) belirlemek ve rotasyon sonrası arşiv lokasyonlarını da forwarder monitörüne eklemek.

## QRadar İçin Log Source Yaklaşımı

QRadar, SAP logları için farklı bir entegrasyon mantığı kullanır. IBM QRadar'ın SAP DSM (Device Support Module), Splunk Add-on'a benzer şekilde SAP'tan veri çeker ama yapı ve yapılandırma felsefesi farklıdır.

### QRadar DSM ve SAP Log Source Tipleri

QRadar'da her log kaynağı bir "log source type" ile tanımlanır ve DSM bu tipin event'lerini nasıl parse edeceğini bilir. SAP için genellikle şu log source tipleri oluşturulur:

| Log Source Tipi | Kaynak | İletim Protokolü |
|---|---|---|
| SAP Security Audit Log | SM19/SM20 (RFC tabanlı çekim) | JDBC veya syslog-ng SAP eklentisi |
| SAP System Log | SM21 | RFC veya syslog iletimi |
| SAP HANA DB | HANA audit log | JDBC |

QRadar'ın SAP entegrasyonunda iki yaygın veri iletim yaklaşımı vardır:

**RFC / JDBC tabanlı çekim:** QRadar veya bir ara bileşen (WinCollect agent veya özel SAP log adapter), SAP'a RFC bağlantısıyla bağlanır ve log tablosunu/dosyasını okur. Bu, Splunk'taki ABAP Extractor modeline yapısal olarak benzer.

**Syslog iletimi:** SAP'tan loglar syslog-ng gibi bir araç üzerinden syslog formatına dönüştürülerek QRadar'a iletilir. Bu yaklaşım ağ katmanını standartlaştırır ama SAP'a özgü alan zenginliğini (client, system ID, T-code gibi SAP metadata) korumak için syslog mesajlarının dikkatli biçimde formatlanması gerekir.

### QRadar Custom Rule Engine ile Kritik Use-Case Karşılaştırması

SAP_ALL atamasını tespit eden bir kural, Splunk SPL'de şöyle yazılır:

```spl
index=sap_audit sourcetype="sap:audit"
| search event_category="AU1" AND message="*SAP_ALL*"
| table _time, user, sap_client, sap_system, terminal
```

Aynı kullanım senaryosu QRadar AQL ile:

```sql
SELECT
  USERNAME AS user,
  LOGSOURCENAME(logsourceid) AS sap_system,
  STARTTIME AS event_time,
  PAYLOAD
FROM events
WHERE
  LOGSOURCETYPENAME(devicetype) = 'SAP'
  AND LOWER(PAYLOAD) LIKE '%sap_all%'
  AND LOWER(PAYLOAD) LIKE '%profil%'
LAST 24 HOURS
```

Bu kısa karşılaştırmanın gösterdiği temel fark: Splunk SPL'de CIM mapping sayesinde standart alan adları (`user`, `action`) doğrudan kullanılabilirken, QRadar'da ham payload'a `LIKE` operatörüyle arama yapılması daha yaygın bir başlangıç noktasıdır — ki bu da parsing kalitesini doğrudan etkilediğini gösterir. İyi yapılandırılmış bir QRadar DSM, payload'u yapısal alanlara ayrıştırır ve AQL sorgularını çok daha temiz hale getirir. Parsing kalitesi her iki SIEM'de de belirleyicidir, sadece bu iki araç bunu farklı katmanlarda çözer.

## Veri Hacmi ve Lisans Planlaması

SAP loglarının SIEM lisans maliyetine etkisi, genellikle proje başlangıcında yeterince hesaplanmaz. Bir tahmin çerçevesi:

| Log Kaynağı | Tipik Günlük Hacim (Orta Büyüklükte SAP) | Splunk GB/gün etkisi |
|---|---|---|
| Security Audit Log (dar filtre) | 50.000 – 200.000 event | ~0.5 – 2 GB |
| Security Audit Log (geniş filtre) | 500.000 – 2.000.000 event | ~5 – 20 GB |
| DBTABLOG (seçili tablolar) | 5.000 – 50.000 event | ~0.1 – 1 GB |
| Gateway Log | 10.000 – 100.000 event | ~0.1 – 1 GB |
| System Log (SM21) | 20.000 – 200.000 event | ~0.2 – 2 GB |

Bu rakamlar yalnızca bir başlangıç referansıdır — üretim ortamının oturma sayısına, kullanıcı hacmine ve filtre genişliğine göre büyük ölçüde değişir. QRadar'da bu, EPS (Events Per Second) planlamasına çevrilir; örneğin 500.000 event/gün ortalama ~6 EPS anlamına gelir ama gün içi zirve (peak) genellikle bu ortalamanın 3-5 katına ulaşabilir.

Pratik öneri: SIEM lisans planlamasına başlamadan önce en az iki haftalık bir "ölçüm dönemi" geçirilmeli; bu süre zarfında gerçek log hacmi ölçülmeli ve filtre genişliğiyle maliyet arasındaki denge buna göre kurulmalıdır.

## Aktarım Doğrulama: "SIEM'e Gerçekten Ulaşıyor mu" Testi

Entegrasyon kurulduktan sonra "her şey çalışıyor" yanılgısı sakıncalıdır. Aşağıdaki üç kontrol, aktarım sağlığını düzenli olarak doğrulamak için kullanılmalıdır:

**Kontrol 1 — Event sayısı tutarlılığı:**

```spl
index=sap_audit earliest=-1h latest=now
| stats count by sap_system, sap_client
```

Bu sorguyu her gün belirli bir saatte çalıştırarak referans sayılar oluşturun; ani düşüşler (özellikle sıfıra düşen bir system/client kombinasyonu) aktarım kopukluğunun ilk işaretidir.

**Kontrol 2 — Zaman damgası gecikmesi:**

```spl
index=sap_audit earliest=-1h
| eval ingest_lag = (_indextime - _time) / 60
| stats avg(ingest_lag) as avg_lag_min, max(ingest_lag) as max_lag_min
  by sap_system
```

Bu sorgu, SAP'ta üretilen event'in Splunk'a ulaşması arasındaki ortalama ve maksimum gecikmeyi dakika cinsinden gösterir. 15 dakikanın üzerindeki bir gecikme, forwarder polling sıklığını veya ağ sorununu işaret eder.

**Kontrol 3 — Sourcetype dağılımı:**

```spl
index=sap_audit OR index=sap_change OR index=sap_syslog earliest=-24h
| stats count by sourcetype, index
| sort - count
```

Beklenen sourcetype'lardan birinin listede hiç görünmemesi, o log kaynağının hiç aktarılmadığının güçlü bir göstergesidir.

## Bölüm 1 Senaryolarına Geri Bağlantı

Bu bölümde kurulan entegrasyon altyapısının, Bölüm 1'deki hangi senaryoların tespitini mümkün kıldığını not etmek faydalıdır:

| Senaryo | Gerekli Log Akışı | Kritik Parsing Riski |
|---|---|---|
| 1 — Unutulan SAP_ALL | `sap:audit` → SAP_ALL içeren AU1 eventleri | Zaman damgası kayması, dil farkı |
| 2 — Debug & Replace | `sap:audit` → debug oturumu eventleri | Ham format, report başlatma satırlarının ayrıştırılması |
| 3 — RFC trust suistimali | `sap:gateway` → kaynak sistem, fonksiyon modülü | Gateway log formatının DSM'de doğru tanımlı olması |
| 4 — Şifre sıfırlama | `sap:audit` → kullanıcı master değişiklik eventleri | Multi-client bağlamı — hangi client'ta yapıldığı kritik |
| 5 — SoD ihlali | `sap:change` → CDHDR/rol atama kayıtları | Change Documents'ın ayrı bir akış olarak doğru yapılandırılması |
| 6 — Client copy | `sap:audit` → sistem yönetimi eventleri | Yetkisiz kopya bir yönetici event'i olarak loglanır; ayrıştırılmalı |
| 7 — Workflow vekalet | `sap:change` → vekalet/workflow değişiklik kayıtları | Zaman damgası + kullanıcı alanı birlikte doğru eşlenmeli |

Bu tablo, bir SAP SIEM entegrasyonunun ne kadar iyi çalıştığını test etmek için de kullanılabilir: her senaryoyu simüle eden bir test işlemi yapın (örneğin test client'ında kontrollü bir SAP_ALL ataması), sonra yukarıdaki sorguyla SIEM'in bunu yakalayıp yakalamadığını doğrulayın. Yakalamıyorsa sorun ya loglama (Bölüm 2) ya aktarım ya da parsing katmanındadır — bu üçünü sırayla elemek, hata giderme sürecini yapılandırır.

Bir sonraki bölümde Splunk CIM data model'inin SAP bağlamındaki derinliğine ineceğiz ve SAP Add-on for Splunk'ın hazır gelen saved search'lerini ve use-case'lerini inceleyeceğiz — bu bölümde kurduğumuz aktarım ve parsing altyapısının üzerine, Detection bölümüne hazırlık olarak bir "hazır ne var, ne yazmamız lazım" haritası çıkaracağız.
