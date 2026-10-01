---
layout: default
title: "Bölüm 8: Güvenlik Raporlama"
nav_order: 8
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/08-guvenlik-raporlama/
---


## Raporlama Neden Bir Güvenlik Kontrolüdür

Raporlama çoğu güvenlik ekibi için son adımdır — işin "gerçek" kısmı bittikten sonra yapılan idari bir görev. Bu bakış açısı yanlıştır ve SAP bağlamında özellikle pahalıya mal olur.

İyi tasarlanmış bir SAP güvenlik raporu üç şey yapar: yönetimin fark etmediği riskleri görünür kılar, Basis ekibinin günlük kararlarını verilere dayandırır ve uyumluluk denetçilerine gerekli kanıtı sağlar. Kötü tasarlanmış bir rapor ise tam tersini yapar: yönetim "her şey normal" okur çünkü rapor sadece yeşil ışıklar göstermektedir; Basis ekibi hangi metriğin önemli olduğunu bilmez; denetçi beklediği kanıtı bulamaz.

Bu bölümde raporlamayı üç katmanda ele alıyoruz: **yönetim/CISO katmanı** (ne kadar güvende olduğumuzu gösteren özet), **operasyonel katman** (Basis ekibinin günlük/haftalık çalışmasını yönlendiren detay), **uyumluluk katmanı** (SOX, KVKK ve sektörel gereksinimlerin kanıtı). Her katman için Splunk üzerinde otomatikleştirilebilir rapor yapıları ve zamanlamaları sunuyoruz.

## Raporlama Katmanları ve Hedef Kitleler

```
┌─────────────────────────────────────────────────────┐
│  YÖNETİM / CISO KATMANI                              │
│  Hedef: CISO, CRO, İç Denetim, Üst Yönetim          │
│  Sıklık: Aylık + Çeyreklik                           │
│  Format: Özet gösterge tablosu, trend analizi        │
│  Soru: "SAP güvenlik duruşumuz ne durumda?"          │
└─────────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────────┐
│  OPERASYONEL KATMAN                                   │
│  Hedef: Basis Ekibi, SOC, Güvenlik Ekibi             │
│  Sıklık: Günlük + Haftalık                           │
│  Format: Detaylı liste, aksiyon gerektiren kalemler  │
│  Soru: "Bugün/bu hafta ne yapmalıyız?"               │
└─────────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────────┐
│  UYUMLULUK KATMANI                                    │
│  Hedef: İç Denetim, Dış Denetim, Düzenleyici Kurum   │
│  Sıklık: Dönemsel (denetim takvimine göre)           │
│  Format: Kanıt paketi, denetim izi                   │
│  Soru: "Gereksinimlere uyuyor muyuz?"                │
└─────────────────────────────────────────────────────┘
```

## Yönetim / CISO Katmanı Raporları

### Aylık SAP Güvenlik Durum Raporu

Bu raporun amacı, teknik detaya girmeden "geçen ay SAP güvenliği açısından neler oldu, nerede duruyoruz" sorusunu yanıtlamaktır. CISO veya üst yönetim bu raporu okurken tek bir soruyu sorabilmeli: "endişelenmem gereken bir şey var mı?"

**Rapor yapısı (5 bölüm):**

**Bölüm 1 — Genel Durum Göstergesi**
Trafik ışığı modeliyle özet: Yeşil (beklenen sınırlar içinde), Sarı (dikkat gerektiren eğilimler), Kırmızı (acil aksiyon gerekli). Bu gösterge, aşağıdaki metriklerin birleşik değerlendirmesinden üretilir.

**Bölüm 2 — Kritik Alarm Özeti**

```spl
-- Aylık kritik alarm özeti (scheduled report — ayda bir)
index=notable sourcetype="stash"
    earliest=-30d latest=now
| search rule_name IN (
    "SAP_ALL_ASSIGNED",
    "DEBUG_REPLACE",
    "RFC_UNEXPECTED_SOURCE",
    "AUDIT_LOG_CONFIG_CHANGE",
    "WORKFLOW_SUBSTITUTION_ABUSE")
| stats count AS total_alerts,
        sum(eval(status="resolved"))   AS resolved,
        sum(eval(status="false_positive")) AS fp,
        sum(eval(status="open"))       AS still_open
    BY rule_name
| eval resolution_rate=round((resolved/total_alerts)*100,1)
| eval fp_rate=round((fp/total_alerts)*100,1)
| table rule_name, total_alerts, resolved, fp,
        still_open, resolution_rate, fp_rate
| sort - total_alerts
```

**Bölüm 3 — Kritik Yetki Durumu**

| Metrik | Bu Ay | Geçen Ay | Değişim |
|---|---|---|---|
| SAP_ALL profiline sahip kullanıcı sayısı | X | Y | ±Z |
| S_DEVELOP yetkili production kullanıcı sayısı | X | Y | ±Z |
| 90+ gündür giriş yapmayan aktif hesap sayısı | X | Y | ±Z |
| Paralel oturum anomalisi tespit edilen hesap sayısı | X | Y | ±Z |

Bu tablonun güzelliği karşılaştırmadadır: bu ay ile geçen ayın farkı, eğilim analizi için yeterlidir. Bir metrik sürekli artıyorsa, bu bir yönetim dikkat noktasına dönüşmelidir.

**Bölüm 4 — Yamalanmamış Kritik Güvenlik Notları**

```spl
-- RSECNOTE çıktısından beslenen yamalanmamış not takibi
index=sap_compliance sourcetype="sap:rsecnote"
    status="open"
    earliest=-30d
| eval days_open=round((now()-_time)/86400,0)
| stats count AS open_count,
        sum(eval(cvss_score >= 9.0)) AS critical_open,
        sum(eval(cvss_score >= 7.0 AND cvss_score < 9.0)) AS high_open,
        max(days_open) AS oldest_open_days
    BY sap_system
| table sap_system, open_count, critical_open,
        high_open, oldest_open_days
| sort - critical_open
```

**Bölüm 5 — Geçen Aydaki Güvenlik Olayları**
Gerçek olay sayısı, ortalama triage süresi (SLA'ya uyum), kök neden kategorileri (yetki hatası, yapılandırma açığı, insider threat girişimi vb.) ve alınan aksiyonların özeti. Gizlilik gerektiren olaylar kamuoyuyla paylaşılacak raporlarda soyutlaştırılmalıdır.

### Çeyreklik Güvenlik Durum Değerlendirmesi

Aylık raporun trend birikimidir; ek olarak şunları içerir:

**Detection coverage değişimi:** Bölüm 9'da detaylandıracağımız coverage metriği bu değerlendirmenin merkezindedir. "Geçen çeyreğe göre kaç yeni use-case devreye alındı, hangi MITRE ATT&CK/SAP risk kategorisi artık kapsanıyor?"

**Operasyonel kontrol olgunluğu:** Bölüm 6'daki periyodik takvim aktivitelerinin tamamlanma oranı. "Çeyreklik RFC envanteri yapıldı mı? SoD matris güncellemesi gerçekleşti mi?"

**Yatırım/kapasite önerisi:** Raporlama döneminde ortaya çıkan boşluklar (loglama kapsamı dışındaki sistemler, yetersiz analiz kapasitesi, araç eksiklikleri) için bir sonraki dönem önerileri.

## Operasyonel Katman Raporları

### Günlük SAP Güvenlik Özeti (Basis + SOC)

Bu rapor, her sabah mesai başlangıcında otomatik olarak ilgili dağıtım listesine gönderilir. Amacı "dün gece ne oldu, bugün nelere bakmalıyım" sorusunu yanıtlamaktır.

```spl
-- Günlük özet raporu — her sabah 07:00'de çalışır
index=sap_audit OR index=sap_change OR index=notable
    earliest=-24h latest=now

| eval category=case(
    index="notable" AND severity="critical", "🔴 Kritik Alarm",
    index="notable" AND severity="high",     "🟠 Yüksek Alarm",
    index="notable",                         "🟡 Diğer Alarm",
    index="sap_change"
        AND object_category="USERADMIN",     "👤 Kullanıcı Değişikliği",
    index="sap_change"
        AND object_category="ROLE",          "🔑 Rol/Yetki Değişikliği",
    index="sap_audit"
        AND action="failure",                "❌ Başarısız Giriş",
    true(), "ℹ️ Diğer")

| stats count BY category, sap_system, sap_client
| sort - count
```

**Günlük özet raporun sabit bölümleri:**

1. **Açık alarmlar:** Triage bekleyen, dünden devir eden alarmlar
2. **Gece gerçekleşen kritik değişiklikler:** Mesai saatleri dışında yapılan yetki/kullanıcı değişiklikleri
3. **Loglama sağlık kontrolü:** Her SAP sistem/client kombinasyonundan log gelip gelmediği (Bölüm 3'teki reconciliation sorgusunun çıktısı)
4. **Servis hesabı anormallikleri:** Gece interaktif giriş yapan teknik hesaplar
5. **Bugün bakım penceresi var mı:** Planlı değişiklikler ve transport'lar

### Haftalık Yetki Değişikliği Raporu

Bu rapor, Basis ekibinin haftalık gözden geçirme toplantısına girdi sağlamak için tasarlanmıştır. SAP'ta bir hafta boyunca gerçekleşen yetki ataması değişikliklerinin tam listesini içerir.

```spl
-- Haftalık yetki değişikliği raporu
index=sap_audit sourcetype="sap:audit"
    signature_id="AU1"
    sap_client IN ("100","200")
    earliest=-7d latest=now
| search message="*profile*" OR message="*PROFIL*"
        OR message="*role*" OR message="*ROLLE*"
        OR message="*user created*" OR message="*user deleted*"
| eval change_type=case(
    match(message,"SAP_ALL"),  "⚠️ SAP_ALL Ataması",
    match(message,"SAP_NEW"),  "⚠️ SAP_NEW Ataması",
    match(message,"S_DEVELOP"),"⚠️ Geliştirme Yetkisi",
    match(message,"created"),  "➕ Yeni Kullanıcı",
    match(message,"deleted"),  "➖ Kullanıcı Silindi",
    match(message,"locked"),   "🔒 Hesap Kilitlendi",
    match(message,"unlocked"), "🔓 Hesap Kilidi Açıldı",
    true(), "📝 Diğer Değişiklik")
| eval target_user=replace(message,
    ".*(?:BENUTZER|USER|KULLANICI):\s*(\S+).*","\1")
| stats values(change_type) AS changes,
        count AS change_count,
        values(user) AS changed_by
    BY target_user, sap_system, sap_client
| sort - change_count
| table target_user, sap_system, sap_client,
        changes, change_count, changed_by
```

Bu raporu Basis ekibi haftalık olarak inceleyerek "bu değişiklikler hepsi beklenen ve onaylı mıydı" sorusunu yanıtlar. Beklenmedik bir değişiklik görülürse (örneğin bir kullanıcıya S_DEVELOP ataması yapılmış ama change ticket'ı yok), bu retrospektif bir soruşturmayı tetikler.

### Haftalık SoD İhlal Raporu

```spl
-- Haftalık SoD ihlal durumu
| inputlookup user_authorization_snapshot.csv
| stats values(profile) AS all_profiles,
        values(role) AS all_roles
    BY username, sap_system, sap_client
| mvexpand all_profiles
| rename all_profiles AS profile_a
| join type=inner profile_a [
    | inputlookup sod_matrix.csv
    | rename role_a AS profile_a
]
| eval has_conflict=if(mvfind(all_profiles,role_b) >= 0,
                       "YES","NO")
| where has_conflict="YES"
| join type=left username [
    | inputlookup sod_exceptions.csv
    | rename user AS username
    | eval is_mitigated="YES"
]
| eval status=if(is_mitigated="YES",
                 "✅ Kabul Edilmiş Risk",
                 "🔴 Açık İhlal")
| stats count AS conflict_count,
        sum(eval(status="🔴 Açık İhlal")) AS open_violations,
        sum(eval(status="✅ Kabul Edilmiş Risk")) AS mitigated
    BY sap_system, sap_client
| append [
| inputlookup user_authorization_snapshot.csv
| stats values(profile) AS all_profiles,
        values(role) AS all_roles
    BY username, sap_system, sap_client
| mvexpand all_profiles
| rename all_profiles AS profile_a
| join type=inner profile_a [
    | inputlookup sod_matrix.csv
    | rename role_a AS profile_a
]
| eval has_conflict=if(mvfind(all_profiles,role_b) >= 0,"YES","NO")
| where has_conflict="YES"
| join type=left username [
    | inputlookup sod_exceptions.csv
    | rename user AS username
    | eval is_mitigated="YES"
]
| where isnull(is_mitigated)
| table username, sap_system, sap_client,
        profile_a, role_b, risk_level, description
| sort - risk_level
]
```

Bu raporun üst bölümü özet (kaç açık ihlal, kaç kabul edilmiş), alt bölümü ise aksiyon gerektiren açık ihlallerin detay listesini verir.

## Uyumluluk Katmanı Raporları

### SOX Bağlamında SAP Raporlama

SOX (Sarbanes-Oxley) uyumluluğu, finansal raporlama sistemleri üzerindeki kontrollerin etkinliğini kanıtlamayı gerektirir. SAP, çoğu kurumun birincil finansal raporlama platformu olduğundan, SAP güvenlik kontrolleri SOX Bölüm 404 kapsamındaki IT General Controls (ITGC) için doğrudan kanıt üretir.

SOX denetçilerinin SAP bağlamında tipik olarak sorduğu kontroller ve bu bölümün ürettiği kanıtlar:

| SOX ITGC Kontrol Alanı | Denetçi Sorusu | Rapordan Kanıt |
|---|---|---|
| Erişim Yönetimi | Production'a kimin erişimi var ve bu erişim nasıl onaylandı? | Haftalık yetki değişikliği raporu + onay kayıtları |
| Ayrıcalıklı Erişim Kontrolü | SAP_ALL gibi geniş yetkiler kimde, ne kadar süreyle? | Aylık kritik yetki durumu raporu |
| SoD | Aynı kişi hem sipariş oluşturup hem onaylayabiliyor mu? | Haftalık SoD ihlal raporu |
| Değişiklik Yönetimi | Kodlar/konfigürasyonlar production'a nasıl geçiyor? | Transport loglama ve onay kayıtları |
| İzleme | Güvenlik olayları izleniyor ve raporlanıyor mu? | Aylık alarm özeti + olay raporları |
| Denetim İzi | Kritik işlemlerin kaydı tutuluyor mu? | DBTABLOG, Security Audit Log aktif olduğuna dair kanıt |

SOX denetiminde en sık karşılaşılan SAP bulgusu: **"Denetim izi yoktu veya eksikti."** Bu bölümde raporlanan metriklerin üretilmesi için önce Bölüm 2'deki loglama yapılandırmasının ve Bölüm 3'teki SIEM aktarımının doğru yapılandırılmış olması gerekir — yoksa kanıt paketi boş olur.

**SOX Denetim Kanıt Paketi SPL:**

```spl
-- Denetim dönemi için Security Audit Log aktivite kanıtı
-- (Denetçinin "loglar aktif miydi" sorusuna yanıt)
index=sap_audit sourcetype="sap:audit"
    sap_system IN ("PRD")
    sap_client IN ("100","200")
    earliest="[DENETİM_DÖNEMİ_BAŞLANGICI]"
    latest="[DENETİM_DÖNEMİ_SONU]"
| timechart span=1d count AS daily_events BY sap_client
| addtotals
| eval coverage_check=if(Total > 0, "✅ Log Aktif", "❌ Log Eksik")
| table _time, sap_client, Total, coverage_check
```

Bu sorgunun çıktısı, denetim dönemi boyunca her gün log üretildiğini gösteren bir zaman serisi tablosudur — denetçinin "loglama kesintisi var mıydı" sorusunu doğrudan yanıtlar.

### KVKK Bağlamında SAP Raporlama

KVKK (Kişisel Verilerin Korunması Kanunu) kapsamında SAP'ta özellikle önem taşıyan iki alan vardır: kişisel veri içeren SAP modüllerine (HR — insan kaynakları, CRM — müşteri verisi) erişim kontrolü ve bu veriye yapılan erişimlerin kayıt altına alınması.

KVKK bağlamında raporlanması gereken kontroller:

**Kişisel veri içeren tablolara erişim raporu:**

```spl
-- KVKK kapsamındaki hassas tablolara erişim izleme
index=sap_audit sourcetype="sap:audit"
    sap_client IN ("100","200")
    earliest=-30d latest=now
| search message="*PA0002*"   -- Kişisel bilgiler (isim, doğum tarihi)
       OR message="*PA0008*"  -- Temel ödeme
       OR message="*PA0009*"  -- Banka bilgileri
       OR message="*KNA1*"    -- Müşteri master verisi
       OR message="*KNVK*"    -- Müşteri iletişim kişileri
| stats count AS access_count,
        dc(user) AS distinct_users,
        values(user) AS accessing_users
    BY message_table, sap_system, sap_client
| lookup kvkk_authorized_users.csv
    table_name AS message_table
    OUTPUT authorized_groups
| eval potential_unauthorized=if(
    isnull(authorized_groups),"KONTROL GEREKLİ","Tanımlı")
| table message_table, access_count, distinct_users,
        accessing_users, authorized_groups, potential_unauthorized
| sort - access_count
```

**Veri ihlali bildirimi için hazırlık:**
KVKK Madde 12 kapsamında bir veri ihlali bildirimi gerektiğinde, Bölüm 7'deki forensics sürecinin çıktısı bu bildirimin teknik temelini oluşturur. Raporun içermesi gerekenler: ihlal zamanı (SIEM zaman çizelgesinden), etkilenen kişisel veri kategorileri (DBTABLOG'dan), etkilenen veri konusu kişi tahmini sayısı ve alınan aksiyonlar.

### Finansal Sektör Uyumluluk Raporlaması

Türkiye'deki finansal kuruluşlar için BDDK ve SPK düzenlemeleri, bilgi sistemleri güvenliğini doğrudan kapsar. SAP güvenlik raporlaması bu çerçevede aşağıdaki gereksinimleri karşılamalıdır:

**Bilgi sistemleri yönetim raporu (BDDK):** Erişim yönetimi, yetkilendirme, değişiklik yönetimi ve olay yönetimi süreçlerinin etkinliğini gösteren periyodik kanıt. Bu bölümdeki operasyonel raporlar doğrudan bu kanıtı üretir.

**Kritik sistem loglarının saklanması:** BDDK bilgi sistemleri yönetmeliği kapsamında log saklama süresi gereksinimleri vardır; bu gereksinim Bölüm 2'deki retention politikasıyla ve SIEM'in saklama süresiyle uyumlu olmalıdır.

**Olay bildirimi:** Önemli bir güvenlik olayında (Bölüm 7'deki gerçek olay senaryoları) BDDK'ya bildirim yükümlülüğü doğabilir; forensics raporu bu bildirimin teknik altyapısını oluşturur.

## Splunk'ta Raporlama Otomasyonu

### Scheduled Reports ve Alert Yapılandırması

Yukarıdaki raporların büyük çoğunluğu Splunk'ta scheduled search olarak yapılandırılabilir. Yapılandırma parametreleri:

| Rapor | Çalışma Zamanı | Format | Dağıtım |
|---|---|---|---|
| Günlük güvenlik özeti | 07:00, her gün | E-posta + PDF | Basis + SOC dağıtım listesi |
| Haftalık yetki değişikliği | Pazartesi 08:00 | E-posta + CSV | Basis + Güvenlik ekibi |
| Haftalık SoD ihlal raporu | Pazartesi 08:30 | E-posta + PDF | GRC + Güvenlik ekibi |
| Aylık yönetim raporu | Ayın 1'i 09:00 | PDF | CISO + Üst yönetim |
| Çeyreklik durum değerlendirmesi | Çeyrek başı | PDF + Sunum | CISO + Yönetim kurulu |
| Loglama sağlık kontrolü | 06:00, her gün | E-posta (sadece anomali) | SOC + Basis |

### Splunk Dashboard: SAP Güvenlik Kontrol Merkezi

Scheduled report'ların ötesinde, SOC analistlerinin ve Basis ekibinin günlük çalışmasını destekleyen interaktif bir Splunk dashboard'u aşağıdaki panelleri içermelidir:

**Panel 1 — Sistem Durumu (sol üst):**
Her SAP sistem/client kombinasyonu için son 24 saatte log gelip gelmediği, renk kodlu (yeşil/kırmızı). Bu, Bölüm 3'teki reconciliation sorgusunun görsel versiyonudur.

**Panel 2 — Kritik Alarm Sayacı (orta üst):**
Son 24 saatte kritik ve yüksek öncelikli alarm sayısı, önceki 24 saatle karşılaştırmalı. Tek bir sayı ve yön oku (artış/azalış) yeterlidir.

**Panel 3 — Aktif Oturum Haritası (sağ üst):**
Kaynağa göre aktif SAP oturumlarının dağılımı. Beklenmedik lokasyon veya IP aralıkları bu görünümde hemen dikkat çeker.

**Panel 4 — Son 7 Günlük Alarm Trendi (orta):**
Günlük alarm sayılarının trend grafiği, kural bazında renk kodlu. Ani bir artış (örneğin belirli bir kuralın dünden bugüne üç kat artması) görsel olarak fark edilir.

**Panel 5 — Bekleyen Aksiyonlar (alt sol):**
Triage bekleyen alarmlar, SLA durumu ve sorumlu analist. Bu panel günlük "ne yapmam lazım" listesinin görsel versiyonudur.

**Panel 6 — Yetki Değişikliği Aktivitesi (alt orta):**
Son 7 günde kritik yetki değişikliklerinin (SAP_ALL, S_DEVELOP, kullanıcı oluşturma/silme) saatlik dağılımı. Mesai saatleri dışındaki aktivite dikkat çekici biçimde gösterilir.

**Panel 7 — SoD İhlal Sayacı (alt sağ):**
Açık ihlal sayısı, kabul edilmiş risk sayısı ve son hafta içinde kapanan/yeni açılan ihlallerin net değişimi.

### Rapor Kalitesini Ölçmek

Raporlar üretildiğinde "bu rapor işe yarıyor mu" sorusu, çoğu zaman sorulmayan ama sorulması gereken sorudur. Aşağıdaki metrikler rapor kalitesini değerlendirmeye yardımcı olur:

**Aksiyonlanabilirlik oranı:** Haftalık yetki değişikliği raporunda listelenen kalemlerden kaçı "beklendi, onaylıydı" olarak kapandı, kaçı bir soruşturmayı veya düzeltme aksiyonunu tetikledi? Eğer oran sıfıra yakınsa, rapor fazla gürültülü demektir — filtreleme iyileştirmesi gerekir.

**Tekrar eden kalemler:** Aynı kullanıcı veya aynı ihlal türü her hafta aynı raporda görünüyorsa, bu kalemin "altta yatan sorunun" çözülmediğini gösterir. Raporun "bize her hafta aynı şeyi söyleyen ama kimsenin çözmediği bir liste" haline gelmesi güven kaybına yol açar.

**Denetimde kullanılan oran:** Uyumluluk raporlarından üretilen kanıt paketlerinin ne kadarı denetçi tarafından "yeterli" bulundu? Denetçi "bu rapor istediğim soruyu yanıtlamıyor" diyorsa, format veya içerik değişikliği gerekir.

## Tüm Serinin Raporlama Bağlantıları

Bu bölümde üretilen raporların, serinin önceki bölümleriyle nasıl bağlantılı olduğunu özetlemek faydalıdır:

| Bölüm | Üretilen Veri | Bu Bölümdeki Raporlara Katkısı |
|---|---|---|
| Bölüm 2 (Loglama) | Log kapsamı ve yapılandırma | SOX kanıt paketi, günlük sağlık kontrolü |
| Bölüm 3 (Aktarım) | SIEM'e gelen log akışı | Günlük loglama sağlık kontrolü, reconciliation |
| Bölüm 4 (CIM/Add-on) | Normalize edilmiş eventler | Tüm SPL sorgularının temeli |
| Bölüm 5 (Detection) | Alarm verileri | Aylık alarm özeti, kritik yetki durumu |
| Bölüm 6 (Operasyonel) | Patch, transport, SoD durumu | Haftalık SoD raporu, RSECNOTE takibi |
| Bölüm 7 (Olay Müdahalesi) | Olay raporları, forensics | Aylık olay özeti, KVKK ihlal bildirimi |
| Bölüm 9 (Olgunluk) | Coverage metrikleri | Çeyreklik durum değerlendirmesi |

Bir sonraki ve son bölümde, tüm seriyi bir araya getiren olgunluk modeli değerlendirmesini işleyeceğiz: ne kadar iyi koruyoruz, neyi henüz kapsamıyoruz, ileriye dönük yol haritası nasıl görünmeli ve SAP ETD (Enterprise Threat Detection) ile mevcut SIEM altyapısının ilişkisi nedir.
