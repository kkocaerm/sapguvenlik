---
layout: default
title: "Bölüm 5: Kritik Detection Use-Case'leri"
nav_order: 5
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/05-detection-usecases/
---


## Bölüm 4'ten Devir: Hangi Kuralları Yazmamız Lazım

Bölüm 4'ün sonunda bir önceliklendirme haritası çıkardık. O haritada Add-on'un hazır içeriğinin karşılayamadığı sekiz senaryo ve iki ince ayar ihtiyacı tespit ettik. Bu bölüm bu listeyi birer birer tamamlıyor: her use-case için kural mantığının açıklaması, tam SPL kodu, eşik ve zaman penceresi değerlendirmesi, false positive yönetimi ve kritik senaryolarda QRadar AQL karşılaştırması.

Kurallar iki grupta sunuluyor: **tek olay kuralları** (tek bir event'i değerlendiren, hızlı ve düşük latency'li) ve **korelasyon kuralları** (birden fazla event'i veya data model'i birleştiren, daha karmaşık ama daha yüksek güvenilirlikli). İki grup için de kural öncelik etiketleri şu şekilde:

- 🔴 **KRİTİK** — Alarm tetiklendiğinde hemen müdahale; false negative kabul edilemez
- 🟠 **YÜKSEK** — Saat içinde değerlendirilmeli
- 🟡 **ORTA** — İş günü içinde değerlendirilmeli; toplu raporlama seçeneği mevcut

---

## Use-Case 1 — SAP_ALL / SAP_NEW Yetki Ataması 🔴

### Kural Mantığı

Bölüm 1 Senaryo 1'de ele aldığımız "unutulan SAP_ALL" vakası, en yüksek riskli tek olay kurallarından biridir. SAP_ALL veya SAP_NEW profili herhangi bir production client'ında herhangi bir kullanıcıya atandığında — "geçici" veya "acil" olsa dahi — bu bir kritik alarm olmalıdır. Bu profillerin production'da meşru kullanım senaryosu neredeyse hiç yoktur; dolayısıyla false positive toleransı sıfıra yakındır.

Bu kuralın içsel zorluğu şudur: SAP_ALL ataması, Security Audit Log'da AU1 (User Master Record Change) kategorisinde gelir ve mesaj metni içinde profilin adını taşır. Add-on bunu genel bir "kullanıcı değişikliği" olarak yakalar; "SAP_ALL" özelinde filtreleme ve alarm üretme Add-on'un hazır içeriğinde yoktur.

### SPL Kuralı

```spl
index=sap_audit sourcetype="sap:audit"
    signature_id="AU1"
    sap_client IN ("100","200")           -- Production client'larını listele
| search message="*SAP_ALL*" OR message="*SAP_NEW*"
| eval risk_profile=case(
    match(message,"SAP_ALL"), "SAP_ALL",
    match(message,"SAP_NEW"), "SAP_NEW",
    true(), "OTHER_CRITICAL")
| eval is_offhours=if(
    (tonumber(strftime(_time,"%H")) < 7 OR
     tonumber(strftime(_time,"%H")) > 20),
    "YES","NO")
| table _time, user, sap_system, sap_client,
        risk_profile, is_offhours, message, src
| sort - _time
```

Bu kural scheduled search olarak dakikada bir çalışacak şekilde yapılandırılmalı ve sonuç sayısı `> 0` olduğunda alarm üretmelidir. `is_offhours` alanı, alarmı alan analistin önceliklendirmesine yardımcı olmak için eklenmiştir — mesai dışında yapılan bir SAP_ALL ataması ek araştırma gerektiren bir yoğunlaştırıcı faktördür.

**False positive durumu:** Teorik olarak, sıfıra yakın olmalıdır. Eğer düzenli olarak false positive üretiyorsa, bunun sebebi büyük olasılıkla:
- Test client'larının production client listesine dahil edilmiş olması → `sap_client` listesini düzeltin
- Batch/migration kullanıcısının aynı isimde bir profil ataması → mesaj filtresini daha spesifik hale getirin

### QRadar AQL Karşılaştırması

```sql
SELECT
  USERNAME           AS assigned_by,
  PAYLOAD,
  LOGSOURCENAME(logsourceid) AS sap_system,
  STARTTIME
FROM events
WHERE
  LOGSOURCETYPENAME(devicetype) LIKE '%SAP%'
  AND CATEGORYNAME(highlevelcategory) = 'Authentication'
  AND (LOWER(PAYLOAD) LIKE '%sap_all%'
    OR LOWER(PAYLOAD) LIKE '%sap_new%')
  AND LOGSOURCENAME(logsourceid) NOT LIKE '%DEV%'
  AND LOGSOURCENAME(logsourceid) NOT LIKE '%QAS%'
LAST 10 MINUTES
```

Splunk kuralından temel fark: QRadar'da production/non-production ayrımı `sap_client` alanı yerine log source adı üzerinden yapılıyor — bu, log source isimlendirme konvansiyonunun önceden standartlaştırılmış olmasını gerektiriyor.

---

## Use-Case 2 — Debug & Replace ile Çalışma Zamanı Değişkeni Manipülasyonu 🔴

### Kural Mantığı

Bölüm 1 Senaryo 2'de ele aldığımız debug & replace tekniği, ABAP debugger içinde bir değişkenin çalışma zamanında değiştirilmesidir. SAP Security Audit Log, ABAP debugger'ın başlatılmasını ve özellikle "Replace" modunun kullanımını ayrı olaylar olarak loglar (bu olay sınıfının tam kodu SAP versiyonuna göre değişebilir; kesin doğrulama için SM20'de ilgili olay sınıfının filtrelenmesi önerilir).

Kritik nokta: production sisteminde debug & replace yetkisi olan kullanıcı sayısı minimal tutulmalı ve bu yetki kullanıldığında — ne kadar meşru görünse de — her seferinde alarm üretilmelidir.

### SPL Kuralı

```spl
index=sap_audit sourcetype="sap:audit"
    sap_client IN ("100","200")
| search (message="*DEBUG*" AND message="*REPLACE*")
       OR message="*ABAP Debugger*"
       OR signature_id IN ("AUB","AUF")
| eval debug_type=case(
    match(message,"REPLACE"),   "DEBUG_REPLACE",
    match(message,"DEBUGGER"),  "DEBUGGER_START",
    true(),                     "DEBUG_OTHER")
| eval hour_of_day=tonumber(strftime(_time,"%H"))
| eval day_of_week=strftime(_time,"%A")
| table _time, user, sap_system, sap_client,
        debug_type, hour_of_day, day_of_week,
        src, message
| sort - _time
```

Bu kural, birkaç farklı olay kalıbını birlikte arar: hem "DEBUG" hem "REPLACE" içeren mesajlar (replace modunun kullanımı), standalone debugger başlatma olayları ve ilgili olay kategorisi kodları. Kural gerçek SAP sisteminizde çalıştırılmadan önce, SM20'de "debug" ile ilgili hangi olay sınıflarının üretildiğini doğrulamak ve olay kodu listesini buna göre güncellemek kritik önem taşır.

**Öneri:** Bu kuralın sonuçları için bir "bilinen meşru kullanım" lookup tablosu oluşturun ve belgelenmiş sorun giderme aktivitelerini bu tabloya işleyin. Böylece her debug olayı için yeniden soruşturma yerine, lookup'ta olmayan olaylar önceliklendirilir.

---

## Use-Case 3 — RFC Trust Suistimali: Beklenmedik Sistemden RFC Logon 🔴

### Kural Mantığı

Bölüm 1 Senaryo 3, bir geliştirme/test sisteminden production'a trusted RFC bağlantısı kurulmasıydı. Bu kuralın can alıcı noktası şudur: RFC bağlantısının kendisi "normal" görünür; anomali, bağlantının *kaynağında* gizlidir.

Çözüm, bir "beklenen RFC kaynak sistemi" lookup tablosu tutmak ve her RFC logon olayını bu tabloyla karşılaştırmaktır. Listede olmayan bir kaynaktan gelen RFC bağlantısı, yüksek öncelikli bir alarm üretir.

```csv
-- rfc_expected_sources.csv (lookup tablosu örneği) --
src_system,dest_system,allowed_function_groups,is_trusted
PRD,PRD,*,true
ERP_EXT,PRD,Z_EXT_FG,false
BW_RPT,PRD,RSA*,false
DEV,DEV,*,true
QAS,QAS,*,true
```

### SPL Kuralı

```spl
index=sap_audit sourcetype="sap:audit"
    signature_id IN ("AU3","AUW","AU6")
    authentication_method IN ("RFC","CPIC")
    sap_client IN ("100","200")
| eval src_system=upper(coalesce(src_sap_system, src))
| lookup rfc_expected_sources.csv
    src_system AS src_system
    dest_system AS sap_system
    OUTPUT is_trusted, allowed_function_groups
| eval is_unexpected=if(isnull(is_trusted) OR is_trusted="false",
                        "YES", "NO")
| where is_unexpected="YES" OR action="failure"
| stats count AS event_count,
        values(src_system) AS sources,
        dc(user) AS distinct_users
    BY sap_system, sap_client, _time span=10m
| where event_count >= 3 OR (is_unexpected="YES")
| table _time, sap_system, sap_client,
        sources, distinct_users, event_count
| sort - event_count
```

**False positive yönetimi:** Bu kural, lookup tablosunun eksiksizliğine bağımlıdır. Yeni bir entegrasyon veya sistem kurulduğunda, RFC bağlantısı alarm üretecektir — bu istenilen bir davranıştır, çünkü "bilinen sistemler listesinin dışında" her bağlantı soruşturulmayı hak eder. Soruşturma sonucu meşruysa, kaynak lookup tablosuna eklenir ve bir sonraki seferinde alarm üretilmez. Bu süreç aynı zamanda RFC bağlantı envanterini güncel tutmanın yan ürünüdür.

### QRadar AQL Karşılaştırması

```sql
SELECT
  SOURCEIP             AS src_ip,
  USERNAME             AS user,
  LOGSOURCENAME(logsourceid) AS dest_sap_system,
  COUNT(*)             AS connection_count,
  STARTTIME
FROM events
WHERE
  LOGSOURCETYPENAME(devicetype) LIKE '%SAP%'
  AND PROTOCOLNAME(protocolid) IN ('RFC','CPIC')
  AND SOURCEIP NOT IN (
    SELECT SOURCEIP FROM reference_data.sets['rfc_allowed_sources']
  )
  AND LOGSOURCENAME(logsourceid) LIKE '%PRD%'
GROUP BY SOURCEIP, USERNAME, LOGSOURCENAME(logsourceid), STARTTIME
HAVING COUNT(*) >= 3
LAST 10 MINUTES
```

QRadar'daki temel fark: kaynak IP listesi Splunk'taki CSV lookup yerine QRadar Reference Data (reference set veya reference table) üzerinden yönetilir. Aynı mantık — farklı veri yönetim altyapısı.

---

## Use-Case 4 — Şifre Sıfırlama Sonrası Alışılmadık Terminal'den Logon (Çapraz Model Korelasyon) 🔴

### Kural Mantığı

Bu, serinin en karmaşık korelasyon kuralıdır çünkü iki farklı data model'deki olayları zaman sırası içinde birleştiriyor: Change Analysis (şifre sıfırlandı) + Authentication (sıfırlamadan sonra giriş yapıldı, üstelik farklı bir terminalden).

Her iki olayın tek başına anlamlı olması gerekmez; alarm, ikisinin ardışık gerçekleşmesindedir. Senaryo 4'te helpdesk bir kullanıcının şifresini sıfırladı, ardından o kullanıcı (veya şifreyi öğrenen biri) normalde kullanmadığı bir terminalden giriş yaptı.

### SPL Korelasyon Kuralı

```spl
-- Adım 1: Son 2 saatte şifresi sıfırlanan kullanıcıları bul
index=sap_audit sourcetype="sap:audit"
    signature_id="AU1"
    sap_client IN ("100","200")
    earliest=-2h latest=now
| search message="*password*" OR message="*parola*"
        OR message="*KENNWORT*"
| eval reset_time=_time
| eval reset_by=user
| eval target_user=replace(message,
    ".*(?:BENUTZER|USER|KULLANICI):\s*(\S+).*","\1")
| table reset_time, reset_by, target_user, sap_system, sap_client
| rename target_user AS user
| join type=inner user sap_system sap_client [
    -- Adım 2: Aynı pencerede o kullanıcının logon'larını bul
    search index=sap_audit sourcetype="sap:audit"
           signature_id IN ("AU1","AU3")
           action="success"
           sap_client IN ("100","200")
           earliest=-2h latest=now
    | table _time AS logon_time, user, src AS logon_src,
            sap_system, sap_client
]
| eval time_diff_min=round((logon_time - reset_time)/60, 1)
| where time_diff_min > 0 AND time_diff_min < 120
-- Adım 3: Normal terminal bilgisiyle karşılaştır
| lookup user_normal_terminals.csv user OUTPUT normal_src_range
| eval is_unusual_terminal=if(
    isnull(normal_src_range) OR
    NOT match(logon_src, normal_src_range),
    "YES", "NO")
| where is_unusual_terminal="YES"
| table reset_time, logon_time, time_diff_min,
        reset_by, user, logon_src,
        normal_src_range, sap_system, sap_client
| sort + time_diff_min
```

Bu kural birkaç lookup tablosuna ihtiyaç duyar: `user_normal_terminals.csv` — her kullanıcının normalde bağlandığı terminal/IP aralığı. Bu tablo, son 90 günün giriş geçmişinden otomatik olarak üretilebilir. Otomatik oluşturmak için:

```spl
-- Temel terminoloji profili (haftalık çalıştır ve CSV'yi güncelle)
index=sap_audit sourcetype="sap:audit"
    signature_id IN ("AU1","AU3")
    action="success"
    earliest=-90d latest=now
| stats mode(src) AS normal_src_range,
        dc(src) AS distinct_src_count
    BY user, sap_system, sap_client
| where distinct_src_count <= 3        -- Tek terminalden bağlananlar
| outputlookup user_normal_terminals.csv
```

**False positive durumu:** En yüksek false positive kaynağı, kullanıcının gerçekten yeni bir cihazdan ilk kez bağlandığı meşru durumlardır (yeni bilgisayar, uzaktan çalışma). Bu nedenle kural sonuçları alarm olarak değil, "araştırılacaklar listesi" olarak günlük rapora alınabilir; gerçek zamanlı alarmın eşiğine ekstra bir gösterge daha eklenmesi önerilebilir (örneğin şifre sıfırlamadan 5 dakika içinde logon).

---

## Use-Case 5 — SoD İhlali: Kritik Yetki Kombinasyonu Tespiti 🟠

### Kural Mantığı

Bölüm 1 Senaryo 5'in gösterdiği gibi, SoD ihlalleri "belirli bir kullanıcı aynı anda A ve B yetkisine sahip mi" sorusuna cevap verir. Bu, saf log bazlı bir detection değildir — statik yetki durumunun anlık görüntüsü (snapshot) gerektirir. Bunu SIEM'de çözmek için SAP'tan düzenli aralıklarla kullanıcı-yetki matrisini çekip Splunk'a beslemek gerekir.

```
SAP (SU10/SUIM üzerinden yetki raporu)
          │
          │  Günlük/haftalık otomatik extract
          ▼
  Splunk lookup tablosu:
  user_authorization_snapshot.csv
  [user, role, profile, sap_system, sap_client, snapshot_date]
          │
          ▼
  SPL korelasyon sorgusu:
  "Bu kullanıcı hem A hem B profiline sahip mi?"
```

### SPL Kuralı

```spl
-- SoD matrisini lookup olarak yükle
-- sod_matrix.csv: role_a, role_b, risk_level, description

index=sap_audit sourcetype="sap:audit"
    signature_id="AU1"
    earliest=-24h
    sap_client IN ("100","200")
| search message="*profile*" OR message="*role*"
        OR message="*PROFIL*" OR message="*ROLLE*"
| eval changed_user=replace(message,
    ".*(?:BENUTZER|USER):\s*(\S+).*","\1")
-- Anlık yetki snapshot'ını sorgula
| join type=inner changed_user [
    | inputlookup user_authorization_snapshot.csv
    | rename username AS changed_user
    | stats values(profile) AS all_profiles,
            values(role)    AS all_roles
        BY changed_user, sap_system, sap_client
]
-- SoD matrisini uygula
| mvexpand all_profiles
| rename all_profiles AS profile_a
| join type=inner profile_a [
    | inputlookup sod_matrix.csv
    | rename role_a AS profile_a
]
| eval has_conflict=if(
    mvfind(all_profiles, role_b) >= 0, "YES", "NO")
| where has_conflict="YES"
| table _time, changed_user, profile_a, role_b,
        risk_level, description,
        sap_system, sap_client
| sort - risk_level
```

**Kural sınırı:** Bu kural, bir değişiklik olduğunda tetiklenip anlık snapshot'a bakıyor; dolayısıyla değişiklik olmadan var olan eski SoD ihlallerini görmez. Eski ihlaller için, snapshot tablosunu SoD matrisiyle haftada bir tam taramak ve bulguları ayrı bir rapora almak gerekir. Bu raporu Bölüm 8'de güvenlik raporlama bağlamında ele alacağız.

---

## Use-Case 6 — Client Copy / Sistem Kopyalama Operasyonları 🟠

### Kural Mantığı

Bölüm 1 Senaryo 6'da, production verisinin maskelenmeden test sistemine kopyalanması ele alındı. Client copy operasyonu SAP'ta bir sistem yönetimi fonksiyonu olarak loglanır. Bu kural iki şeyi izler: client copy olayının kendisi (meşru mu, planlanmış mı), ve kopyalama sonrasında hedef sistemde beklenmedik erişim artışı olup olmadığı.

### SPL Kuralı

```spl
-- Parça 1: Client copy olayını yakala
index=sap_audit sourcetype="sap:audit"
    signature_id IN ("AUW","AU5")
    sap_client IN ("100","200")
    earliest=-24h
| search message="*client copy*" OR message="*MANDANTENKOPIE*"
        OR message="*CCCOPYALL*" OR message="*SCC3*"
        OR message="*SCC1*"
| eval operation="CLIENT_COPY_DETECTED"
| eval is_planned=if(
    searchmatch("user IN (planned_maintenance_users)"),
    "YES","NO")
| table _time, user, sap_system, sap_client,
        operation, is_planned, message

| appendcols [
-- Parça 2: Kopyalamadan sonraki 48 saatte hedef sistemde
-- erişim artışı var mı (baseline ile karşılaştır)
search index=sap_audit sourcetype="sap:audit"
       sap_system IN ("DEV","QAS","TST")
       earliest=-48h latest=now
| bucket _time span=1h
| stats count AS hourly_events BY sap_system, sap_client, _time
| eventstats avg(hourly_events) AS avg_hourly
             stdev(hourly_events) AS std_hourly
    BY sap_system, sap_client
| where hourly_events > (avg_hourly + (2 * std_hourly))
| eval operation="ELEVATED_ACCESS_POST_COPY"
| table _time, sap_system, sap_client, operation,
        hourly_events, avg_hourly
]
| sort - _time
```

Bu kural, client copy tespitini ikinci bir katmanla — kopyalamadan sonraki normalin üzerinde erişim aktivitesi — desteklemektedir. İkisi birlikte geldiğinde risk çok daha yüksektir.

---

## Use-Case 7 — Workflow Vekalet Suistimali 🟠

### Kural Mantığı

Bölüm 1 Senaryo 7, bir vekilin kendi onay limitini aşan işlemleri onaylamasıydı. Bu kural iki aşamalı çalışır: önce vekalet atamalarını yakalar, sonra o vekalete sahip kullanıcının üst limitli onay yapıp yapmadığını kontrol eder.

```spl
-- Parça 1: Vekalet (substitution) atamasını yakala
index=sap_change sourcetype="sap:change"
    sap_client IN ("100","200")
    earliest=-7d
| search object_category="WORKFLOW_SUBST"
        OR message="*substitution*" OR message="*VERTRETUNG*"
| eval substitution_active_from=mvindex(
    split(message,"from"),1)
| eval substitution_active_to=mvindex(
    split(message,"to"),1)
| table _time, user AS substitution_set_by,
        object_id AS substitute_user,
        substitution_active_from,
        substitution_active_to,
        sap_system, sap_client
| join type=inner substitute_user [
-- Parça 2: O vekil kullanıcının onay limitini al
    | inputlookup user_approval_limits.csv
    | rename username AS substitute_user
    | fields substitute_user, approval_limit,
             principal_user, principal_limit
]
-- Parça 3: Vekalet süresinde yapılan yüksek tutarlı onayları bul
| join type=inner substitute_user sap_system sap_client [
    search index=sap_change sourcetype="sap:change"
           sap_client IN ("100","200")
           object_category IN ("PURCHASE_ORDER","PAYMENT","INVOICE")
           action="approved"
           earliest=-7d
    | rename user AS substitute_user
    | table _time AS approval_time, substitute_user,
            object_id, amount_field,
            sap_system, sap_client
]
| eval exceeded_own_limit=if(
    tonumber(amount_field) > tonumber(approval_limit),
    "YES","NO")
| where exceeded_own_limit="YES"
| eval risk_multiplier=round(
    tonumber(amount_field) / tonumber(approval_limit), 1)
| table _time, approval_time,
        substitution_set_by, substitute_user, principal_user,
        approval_limit, principal_limit,
        amount_field, risk_multiplier,
        object_id, sap_system, sap_client
| sort - risk_multiplier
```

`user_approval_limits.csv` lookup tablosu, kurumun finansal onay hiyerarşisini (kim hangi tutara kadar onaylayabilir) içermelidir. Bu tablo tipik olarak SAP FI veya MM modülündeki release strategy yapılandırmasından çıkarılır.

---

## Use-Case 8 — Audit Log'un Kendisinin Devre Dışı Bırakılması (Meta Alarm) 🔴

### Kural Mantığı

Bölüm 2'de "audit trail'in kendisi bir saldırı hedefidir" başlığı altında işlediğimiz bu konu, tüm detection altyapısının temeline dokunuyor. SAL'ı kapatmak veya filtrelerini daraltmak, bir sonraki adımları kapatmak isteyen bir saldırganın veya kötü niyetli bir iç kullanıcının mantıklı ilk adımıdır. Bu yüzden bu alarm, hiçbir eşik değeri olmadan — tek bir event yeterli — ve en yüksek öncelikte tetiklenmelidir.

```spl
-- Meta Alarm 1: Audit log yapılandırma değişikliği
index=sap_audit sourcetype="sap:audit"
    earliest=-15m latest=now
| search signature_id IN ("AUA","AU9")
| search message="*audit*" OR message="*AUDIT*"
        OR message="*SM19*" OR message="*RSAU_CONFIG*"
| eval alarm_type="AUDIT_LOG_CONFIG_CHANGE"
| table _time, user, sap_system, sap_client,
        alarm_type, message, src

| append [
-- Meta Alarm 2: Beklenmedik şekilde log akışı durdu
search index=sap_audit sourcetype="sap:audit"
       earliest=-2h latest=now
| bucket _time span=15m
| stats count AS event_count BY sap_system, sap_client, _time
| eventstats avg(event_count) AS avg_count BY sap_system, sap_client
| where event_count < (avg_count * 0.1)    -- Normalin %10'una düşmüş
| eval alarm_type="LOG_FLOW_ANOMALY_LOW"
| table _time, sap_system, sap_client,
        alarm_type, event_count, avg_count
]

| append [
-- Meta Alarm 3: Yüksek yetkili kullanıcının SM19/RSAU_CONFIG açması
search index=sap_audit sourcetype="sap:audit"
       earliest=-15m latest=now
| search message="*SM19*" OR message="*RSAU*"
| lookup privileged_users.csv user OUTPUT is_privileged
| where is_privileged="YES"
| eval alarm_type="PRIVILEGED_AUDIT_CONFIG_ACCESS"
| table _time, user, sap_system, sap_client, alarm_type, message
]

| sort - _time
```

Meta Alarm 2 özellikle kritiktir: loglama yapılandırması değiştirilmeden bile, forwarder'ın durdurulması, log dosyasının silinmesi veya rotate edilmesi gibi yollarla log akışı kesilebilir. Bu kural, "son X dakikada normalin çok altında event geldi" durumunu bir anomali sinyali olarak değerlendirir. Kural, log akışının doğal olarak düşük olduğu bakım pencereleri sırasında false positive üretebileceğinden, planlı bakım pencerelerini kapsayan bir "maintenance window" lookup tablosuyla desteklenmelidir.

---

## Use-Case 9 — Başarısız Logon: Eşik ve Zaman Penceresi Optimizasyonu 🟡

Bu, Add-on'un hazır içeriği olan ama eşik ve zaman penceresi ayarı gerektiren use-case'dir. Standart "5 dakikada 5 başarısız giriş" kuralı, büyük SAP ortamlarında aşırı gürültülü olabilir.

```spl
index=sap_audit sourcetype="sap:audit"
    action="failure"
    signature_id IN ("AU3","AUW")
    sap_client IN ("100","200")
    earliest=-30m latest=now
| bucket _time span=10m
| stats count AS failure_count,
        dc(src) AS distinct_src,
        values(src) AS src_list
    BY user, sap_system, sap_client, _time
| eval risk_score=case(
    failure_count >= 20 AND distinct_src <= 1, 90,
    failure_count >= 10 AND distinct_src <= 1, 70,
    failure_count >= 5  AND distinct_src <= 1, 50,
    failure_count >= 20 AND distinct_src > 1,  80,
    failure_count >= 10 AND distinct_src > 1,  60,
    true(), 30)
| eval alert_type=case(
    distinct_src > 5,           "CREDENTIAL_STUFFING",
    distinct_src = 1
        AND failure_count > 10, "BRUTE_FORCE",
    true(),                     "FAILED_LOGIN_ANOMALY")
| where risk_score >= 50
| lookup known_batch_users.csv user OUTPUT is_batch
| where is_batch != "YES"
| table _time, user, sap_system, sap_client,
        failure_count, distinct_src,
        alert_type, risk_score
| sort - risk_score
```

Risk skoru 90 ve üzeri → anlık alarm; 70-89 → 1 saat içinde değerlendirme; 50-69 → günlük özet rapora ekle.

---

## Use-Case 10 — Servis Hesabı İnteraktif Logon 🟠

Bu use-case Add-on'un hazır olarak sunduğu ama lookup tablosunun kuruma özel doldurulması gereken kuraldır.

```spl
index=sap_audit sourcetype="sap:audit"
    action="success"
    authentication_method="Dialog"
    sap_client IN ("100","200")
    earliest=-1h latest=now
| lookup system_service_accounts.csv user OUTPUT is_service_account,
          account_purpose, expected_logon_type
| where is_service_account="YES"
      AND expected_logon_type IN ("RFC","Background","None")
| eval risk_note="Service account used interactively — " . account_purpose
| eval is_offhours=if(
    (tonumber(strftime(_time,"%H")) < 7 OR
     tonumber(strftime(_time,"%H")) > 20),
    "YES","NO")
| table _time, user, src, sap_system, sap_client,
        account_purpose, expected_logon_type,
        is_offhours, risk_note
| sort - is_offhours
```

`system_service_accounts.csv` lookup tablosunu oluşturmak için SAP'ta SU01 üzerinden "S" (System) ve "C" (Communication) tipindeki tüm kullanıcıları çıkarmak iyi bir başlangıç noktasıdır.

---

## Kurallar Arası Korelasyon: Risk Skoru Birikimi

Yukarıdaki on use-case tek tek çalıştırıldığında bile değerlidir. Ama bunları bir araya getiren — aynı kullanıcı için birden fazla kuralın kısa sürede tetiklendiğinde risk puanını biriktiren — bir üst katman, özellikle insider threat senaryolarında çok daha güçlü bir tespit sağlar.

```spl
-- Zaman penceresi: son 24 saat
-- Her use-case'in adını ve risk skorunu takip eden birleşik sorgu

| union
[ search index=sap_audit sourcetype="sap:audit"
  signature_id="AU1"
  sap_client IN ("100","200")
  (message="*SAP_ALL*" OR message="*SAP_NEW*")
  earliest=-24h
  | eval rule="SAP_ALL_ASSIGNED", score=90
  | table _time, user, sap_system, sap_client, rule, score ]

[ search index=sap_audit sourcetype="sap:audit"
  action="failure" signature_id IN ("AU3","AUW")
  sap_client IN ("100","200") earliest=-24h
  | stats count AS fc BY user, sap_system, sap_client
  | where fc >= 10
  | eval rule="REPEATED_FAILED_LOGIN", score=50
  | table user, sap_system, sap_client, rule, score ]

[ search index=sap_audit sourcetype="sap:audit"
  (message="*DEBUG*" AND message="*REPLACE*")
  sap_client IN ("100","200") earliest=-24h
  | eval rule="DEBUG_REPLACE", score=80
  | table _time, user, sap_system, sap_client, rule, score ]

| stats sum(score) AS total_risk_score,
        values(rule) AS triggered_rules,
        count AS rule_count
    BY user, sap_system, sap_client
| where total_risk_score >= 100
| eval risk_level=case(
    total_risk_score >= 200, "CRITICAL",
    total_risk_score >= 150, "HIGH",
    true(), "ELEVATED")
| table user, sap_system, sap_client,
        total_risk_score, risk_level,
        rule_count, triggered_rules
| sort - total_risk_score
```

Bu "birleşik risk skoru" sorgusu günlük özet rapor olarak ve 200+ puan için anlık alarm olarak yapılandırıldığında, tek bir kuralın üretemeyeceği düşük profilli çok adımlı iç tehdit örüntülerini yüzeye çıkarır.

---

## Genel False Positive Yönetimi

Bölüm 7'de (Olay Müdahalesi) false positive'lerin nasıl kapatılacağını ve bu kararların nasıl sonraki kuralları iyileştireceğini detaylı işleyeceğiz. Ama detection kurallarıyla birlikte düşünülmesi gereken üç temel ilkeyi burada belirtelim:

**İlke 1 — Whitelist değil, baseline:** "Bu kullanıcıyı kuralın dışında tut" (whitelist) yerine, "bu kullanıcının normali şu" (baseline) yaklaşımını tercih edin. Whitelist zamanla genişler ve kör noktaya dönüşür; baseline ise davranış değiştiğinde yeniden alarm üretir.

**İlke 2 — False positive kaydı:** Her false positive kararı, neden kapatıldığını ve kim tarafından kapatıldığını içeren bir kayıtla sonlanmalıdır. Aynı kullanıcı için aynı kural üç kez false positive üretirse, bu ya kural eşiğinin düzeltilmesi ya da o kullanıcı için özel bir baseline tanımlanması gerektiğinin sinyalidir.

**İlke 3 — Sessiz silme yok:** Bir alarm "gürültülü" diye kaldırıldığında, o kuralın yakaladığı senaryo artık görünmez hale gelir. Gürültülü alarm → eşik ayarı → daha az gürültü döngüsü, alarmı silmekten her zaman daha iyidir.

Bir sonraki bölümde operasyonel güvenliğe geçiyoruz: SAP Security Notes ve patch yönetimi, transport onay süreçlerinin SOC'a entegrasyonu, SoD matrisinin canlı tutulması ve RFC/trust ilişkilerinin periyodik envanteri. Bu konuların tamamı, bu bölümdeki kuralların sinyalini doğru yorumlamak için gereken operasyonel bağlamı sağlıyor.
