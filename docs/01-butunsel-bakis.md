---
layout: default
title: "Bölüm 1: SAP Güvenliğine Bütünsel Bakış"
nav_order: 1
parent: SAP Güvenliği Yazı Dizisi
permalink: /docs/01-butunsel-bakis/
---


## Bu Seri Neden Var

SAP, çoğu kurumda finans, satın alma, üretim, insan kaynakları gibi en kritik süreçlerin üzerinde çalıştığı sistemdir. Aynı zamanda çoğu SOC'un (Security Operations Center) en az görünür olduğu, en az anladığı sistemdir. Bu iki gerçek yan yana durduğunda ortaya ciddi bir kör nokta çıkar: kurumun en değerli verisi, en az izlenen platformda durur.

Bu durum soyut bir risk değil. Finansal tabloya doğrudan SQL ile yazılan bir kayıt, denetim izi bırakmadan bir ödemeyi değiştirebilir. Geçici olarak atanan ve geri alınmayan bir SAP_ALL yetkisi, aylarca fark edilmeden kurum içinde dolaşabilir. Bu senaryoların hiçbiri "exotic" bir saldırı tekniği gerektirmez — sistemin normal işleyişinin bir parçası gibi görünen, ama gözetimsiz kaldığında ciddi risk taşıyan operasyonlardır.

Bu yazı dizisi, bu kör noktayı kapatmayı hedefliyor. Dokuz bölüm boyunca SAP loglama politikalarından başlayıp, logların merkezi SIEM'e (Splunk öncelikli, kritik noktalarda QRadar karşılaştırmalı) aktarılmasına, detection kurallarının yazılmasına, operasyonel güvenliğe, olay müdahalesine ve raporlamaya kadar uçtan uca bir yol izleyeceğiz.

Hedef kitle SAP Basis ve güvenlik ekipleri. Çünkü bu işin merkezinde onlar var — SOC, SAP'ı anlamadan etkili bir detection stratejisi kuramaz; Basis ekibi de SOC'un nasıl çalıştığını bilmeden kendi sistemini bütünsel olarak savunamaz. Bu seri, iki dünya arasındaki köprüyü kurmaya çalışıyor.

## SAP'ın Mimarisi Neden "Farklı" Bir Güvenlik Sorunu

Klasik bir SOC, network trafiği, endpoint telemetrisi, Windows/Linux event logları, firewall ve proxy kayıtları üzerine kuruludur. Bu dünyada bir saldırı zinciri genellikle tanıdık adımlardan geçer: phishing, lateral movement, privilege escalation, exfiltration. Bu adımların her biri için olgunlaşmış detection mantığı, MITRE ATT&CK gibi ortak bir dil ve yıllar içinde biriken threat intelligence vardır.

SAP bu modele tam uymaz. Aşağıdaki basitleştirilmiş katman şeması, bir SOC analistinin önünde duran "kara kutu"yu açmaya yardımcı olur:

```
┌─────────────────────────────────────────────────┐
│  Sunum Katmanı (SAP GUI, Fiori, RFC istemcileri) │
├─────────────────────────────────────────────────┤
│  ABAP Application Server                         │
│  - Yetkilendirme (roller, profiller, auth obj.)  │
│  - İş mantığı, transaction'lar (T-code)           │
├─────────────────────────────────────────────────┤
│  Gateway / RFC Katmanı                            │
│  - Sistemler arası iletişim, trust ilişkileri     │
├─────────────────────────────────────────────────┤
│  Veritabanı Katmanı (HANA / RDBMS)                │
│  - Doğrudan tablo erişimi (uygulama katmanını     │
│    bypass edebilir)                               │
├─────────────────────────────────────────────────┤
│  Transport Sistemi (TMS)                          │
│  - Kod/yapılandırma değişikliklerinin taşınması   │
└─────────────────────────────────────────────────┘
        ↑ Tüm katmanlar, client (mandant) bazında
          ayrı mantıksal ortamlar barındırabilir
```

Bu katmanların her birini biraz daha açalım, çünkü her biri kendine özgü bir risk yüzeyi ve kendine özgü bir log dili taşır.

### ABAP Application Server ve Yetkilendirme Modeli

SAP'ın yetki modeli, klasik IAM (Identity and Access Management) araçlarının alışık olduğu rol tabanlı erişim kontrolünden çok daha granüler ve çok daha az şeffaftır. Bir kullanıcıya atanan her şey **authorization object** denilen yapılarla kontrol edilir; bunlar profiller ve roller içinde toplanır.

Birkaç kritik authorization object örneği, SOC'un neden bu modeli anlamadan risk değerlendirmesi yapamadığını gösterir:

- **S_TCODE** — Kullanıcının hangi transaction'lara (T-code) erişebileceğini kontrol eder. SE16/SE16N (tablo görüntüleme), SU01 (kullanıcı yönetimi), SE38/SE80 (ABAP geliştirme) gibi T-code'lara erişim, doğrudan risk seviyesini belirler.
- **S_TABU_DIS** — Tablo gruplarına (table authorization group) erişimi kontrol eder. Bir kullanıcının SE16N ile hangi tablo grubuna erişebileceği bu obje üzerinden belirlenir; finansal veya HR tablo gruplarına geniş erişim kritik bir bulgudur.
- **S_RFC** — RFC fonksiyon gruplarına erişimi kontrol eder. Geniş S_RFC yetkisi, bir kullanıcının sistemler arası fonksiyon çağırma kapasitesini büyük ölçüde artırır.
- **S_DEVELOP** — ABAP geliştirme ortamına erişimi kontrol eder. Production sistemde bu yetkiye sahip olmak, kod enjeksiyonu veya debug-replace gibi tekniklerin önünü açar.
- **S_USER_GRP / S_USER_PRO** — Kullanıcı yönetimi yetkilerini kontrol eder. Bu objelere sahip biri, başka kullanıcılara yetki atayabilir — yani kendi kendine privilege escalation yapabilir.

**SAP_ALL** ise bu objelerin tamamını kapsayan, pratikte "sistemde her şeyi yapabilme" anlamına gelen bir profildir. Bir Windows ortamında "Domain Admin" yetkisinin atanması genellikle dikkatle izlenen bir olaydır; SAP dünyasında SAP_ALL ataması çoğu zaman bir change ticket'ı içinde, "acil bir sorunu çözmek için geçici" gerekçesiyle, kimsenin fark etmediği bir şekilde gerçekleşir.

### Veritabanı Katmanı: Uygulama Mantığını Bypass Etmek

SAP'ın iş mantığı (onay akışları, validasyonlar, denetim izleri) ABAP katmanında çalışır. Ancak SE16/SE16N gibi araçlarla veya doğrudan veritabanı erişimiyle bir tabloya yazıldığında, bu iş mantığı tamamen devre dışı kalabilir. Bir muhasebe kaydının onay akışından geçmeden doğrudan tabloya yazılması, klasik bir "approval bypass" senaryosudur ve network güvenlik araçlarının hiçbir şekilde göremeyeceği bir katmanda gerçekleşir.

### Gateway ve RFC: Sistemler Arası Görünmez Köprüler

SAP sistemleri birbirleriyle ve üçüncü taraf sistemlerle RFC (Remote Function Call) üzerinden konuşur. Bu iletişim, **trust ilişkileri** (RFC destinations, trusted systems) üzerinden yetkilendirilir. Yanlış yapılandırılmış bir trust ilişkisi — örneğin bir geliştirme sisteminin production sisteme trusted olarak tanımlanması — saldırganın daha az korunan bir sistem üzerinden production'a sıçramasına izin verebilir. Bu, network seviyesinde tamamen "normal" trafik gibi görünür; çünkü teknik olarak iki SAP sistemi arasındaki beklenen bir iletişimdir.

### Transport Sistemi: Production'a Giden Resmi Yol

Kod ve yapılandırma değişiklikleri, geliştirme sisteminden test'e, test'ten production'a **transport** denilen paketler halinde taşınır. Bu süreç SAP'ın kendi onay mekanizmasıyla (TMS — Transport Management System) yönetilir ve klasik bir CI/CD pipeline güvenlik kontrolü buraya doğrudan uygulanamaz. Onaysız veya yanlış zamanlanmış bir transport, production'a beklenmeyen bir kod değişikliği taşıyabilir.

### Client (Mandant) Yapısı: Bağlamı Olmayan Log, Yanlış Yorumlanan Log

Aynı SAP sistemi içinde birden fazla client (mandant) barınabilir — örneğin 100 production, 110 test, 800 sandbox gibi. Bir log kaydının hangi client'tan geldiğini bilmeden olayı doğru yorumlamak mümkün değildir; test client'ında SAP_ALL ataması ile production client'ında aynı atama tamamen farklı risk seviyelerine işaret eder. Bu bağlamı taşımayan ya da normalize etmeyen bir SIEM kuralı, ya gürültü üretir ya da gerçek riski kaçırır.

## Somut Senaryolar: Yedi Vaka Üzerinden SAP Riskini Görmek

Teoriyi biraz somutlaştıralım. Aşağıdaki yedi senaryo, gerçek olaylardan damıtılmış, tipik örüntülerdir — her birinde "neden klasik SOC bunu kaçırır" ve "Basis ekibi neyi bilmesi gerekir" sorularını birlikte cevaplıyoruz. İlk üçü yetki ataması ve sistem mimarisi etrafında, sonraki üçü kimlik yönetimi, görev ayrılığı (SoD) ve veri taşınması etrafında, son senaryo ise doğrudan iç tehdit (insider threat) ve iş akışı bütünlüğü etrafında şekilleniyor — yani tek bir risk kategorisine sıkışmadan SAP'ın farklı risk yüzeylerini gösteriyor.

### Senaryo 1 — Unutulan SAP_ALL

Production'da kritik bir batch job hata veriyor. Basis ekibinden biri, sorunu hızlı çözmek için ilgili teknik kullanıcıya geçici olarak SAP_ALL profilini atar, sorunu çözer ve "sonra geri alırım" der. Change ticket'ı açılmıştır ama geri alma adımı unutulur. Üç ay sonra bu teknik kullanıcının kimlik bilgileri (credential) bir başka sistemdeki zafiyet üzerinden ele geçirilir ve artık saldırganın elinde production SAP'ta sınırsız yetki vardır.

**Neden SOC bunu göremez:** Yetki ataması SU01 üzerinden yapılmış bir SAP-içi işlemdir; network trafiğinde, endpoint'te veya AD'de hiçbir iz bırakmaz. Klasik bir "privileged access" izleme aracı bu olayı kapsamına dahi almaz, çünkü SAP'ın kendi yetki modelini izlemiyordur.

**Basis ekibinin bilmesi gereken:** Her SAP_ALL/SAP_NEW ataması, ne kadar "geçici" olsa da, bir kritik olay olarak ele alınmalı ve otomatik bir takip/hatırlatma mekanizmasına bağlanmalıdır. Bölüm 5'te bu durumu yakalayan SPL kuralını işleyeceğiz.

### Senaryo 2 — Debug & Replace ile Onay Akışının Bypass Edilmesi

SAP'ın "debug and replace" (Debug & Değiştir) özelliği, geliştiricilerin çalışma zamanında bir değişkenin değerini değiştirmesine izin verir. Yasal kullanım alanları vardır (sorun teşhisi), ama kötüye kullanıldığında bir onay akışındaki kontrol değişkenini ("approved = false") çalışma anında "approved = true" olarak değiştirip, sistemin normal akışını hiç kırmadan bir onayı bypass etmek mümkündür.

**Neden SOC bunu göremez:** Bu işlem ABAP debugger içinde gerçekleşir; sonuç olarak ortaya çıkan kayıt (örneğin onaylanmış bir ödeme) tamamen "normal" görünür. Tabloya yazılan veri, normal bir onay sürecinden geçmiş gibi görünür.

**Basis ekibinin bilmesi gereken:** Debug & Replace yetkisi (S_DEVELOP içinde özel bir authorization field ile kontrol edilir) production'da son derece kısıtlı tutulmalı ve bu yetkiye sahip kullanıcıların debug oturumları ayrıca loglanmalıdır. Bu olay sınıfı Security Audit Log'da özel olarak filtrelenebilir bir kategoridir.

### Senaryo 3 — RFC Trust İlişkisinin Kötüye Kullanılması

Bir saldırgan, görece daha az korunan bir geliştirme veya test SAP sistemine erişim sağlar (örneğin zayıf bir parola veya eski bir zafiyet üzerinden). Bu sistemden production sisteme tanımlı bir trusted RFC destination bulur ve bu ilişkiyi kullanarak production'a kimlik doğrulamasını büyük ölçüde bypass ederek erişir.

**Neden SOC bunu göremez:** Network seviyesinde bu, iki bilinen SAP sistemi arasındaki beklenen bir trafik gibi görünür; firewall ve IDS/IPS kuralları bu iletişimi zaten "izinli" olarak işaretlemiştir. Asıl anomali, trust ilişkisinin *kullanım örüntüsünde* gizlidir.

**Basis ekibinin bilmesi gereken:** Trust ilişkileri düzenli olarak envanterlenmeli, gereksiz olanlar kaldırılmalı ve geliştirme/test sistemlerinin production'a trusted olarak tanımlanması prensip olarak yasaklanmalıdır. Bölüm 6'da operasyonel güvenlik bağlamında bu konuyu derinleştireceğiz.

### Senaryo 4 — Yetkisiz Şifre Sıfırlama ile Hesap Devralma

Helpdesk fonksiyonunu üstlenen bir kullanıcı, SU01 üzerinde gereğinden geniş bir yetkiye sahiptir ve teoride yardım etmesi gereken kullanıcı grubunun çok dışındaki hesapların şifresini de sıfırlayabilmektedir. Bu kullanıcı, finansal onay yetkisi olan bir hesabın şifresini sıfırlar, o hesaba geçici olarak girer ve bekleyen yüksek tutarlı bir ödemeyi onaylar. Hesap sahibi ertesi gün şifresinin değiştiğini fark eder ama o sırada ödeme zaten gerçekleşmiştir.

**Neden SOC bunu göremez:** Şifre sıfırlama, helpdesk'in günlük rutin operasyonlarından biridir; SAP içinde meşru bir işlem olarak loglanır ve tek başına hiçbir alarm tetiklemez. Active Directory tabanlı bir "password reset" izleme aracı, SAP'ın kendi kullanıcı deposunu (user store) hiç görmez.

**Basis ekibinin bilmesi gereken:** Hangi kullanıcı gruplarının hangi diğer gruplara şifre sıfırlayabileceği S_USER_GRP authorization object'i ile sınırlandırılmalı; özellikle finansal onay yetkisi taşıyan "kritik kullanıcı" tipleri için şifre sıfırlama olayı ayrıca loglanmalı ve mümkünse anlık bildirime bağlanmalıdır.

### Senaryo 5 — Görev Ayrılığı (SoD) İhlali: Tedarikçi Oluşturma + Ödeme Onayı

Bir kullanıcı, organizasyonel değişiklikler sonucu zamanla hem yeni tedarikçi kaydı oluşturma (XK01/XK02) hem de ödeme onaylama yetkisine sahip olur — her iki yetki de ayrı ayrı dönemlerde, ayrı gerekçelerle, meşru şekilde atanmıştır. Kullanıcı bu kombinasyonu kullanarak sahte bir tedarikçi kaydı oluşturur ve kendi oluşturduğu faturaya kendi onayını verir.

**Neden SOC bunu göremez:** Her işlem tek başına tamamen meşru görünür — tedarikçi oluşturmak da ödeme onaylamak da günlük operasyonun parçasıdır. Risk, bu iki yetkinin *aynı kişide birleşmesinde* ortaya çıkar; bu, klasik bir zaman bazlı korelasyon kuralıyla değil, statik yetki kombinasyonu analiziyle yakalanabilecek bir örüntüdür ve SIEM'in varsayılan "olay bazlı" kural mantığına doğrudan uymaz.

**Basis ekibinin bilmesi gereken:** SoD matrislerinin (GRC Access Control veya manuel bir matris üzerinden) düzenli olarak taranması ve tespit edilen çakışmaların SIEM'e ayrı bir besleme olarak aktarılması gerekir. Bu konuyu Bölüm 6'da operasyonel güvenlik bağlamında ayrıca işleyeceğiz.

### Senaryo 6 — Client Copy Üzerinden Veri Sızması

Basis ekibi, test ortamını güncellemek amacıyla rutin bir **client copy** işlemiyle production client'ını test sistemine kopyalar. İşlem teknik olarak başarılı ve onaylıdır. Ancak production verisi maskelenmeden (data scrambling uygulanmadan) kopyalandığı için, test ortamına artık gerçek müşteri ve finansal veriler taşınmış olur. Test ortamına production kadar sıkı erişim kontrolleri uygulanmadığından, bu ortama erişimi olan biri verileri kolayca export eder.

**Neden SOC bunu göremez:** Client copy, planlı ve onaylı bir Basis operasyonudur; SOC'un izleme kapsamında genelde "bakım faaliyeti" olarak değerlendirilir. Asıl risk, kopyalama *sırasında* değil, sonrasında test ortamındaki gevşek erişim kontrolleriyle birleştiğinde ortaya çıkar — iki ayrı, kendi içinde "normal" olayın kesişimi.

**Basis ekibinin bilmesi gereken:** Client copy süreçlerinde hassas veri maskeleme politikası standart bir adım olmalı; test ortamları da en azından erişim ve loglama açısından production'a yakın bir seviyede tutulmalıdır.

### Senaryo 7 — İç Tehdit: Workflow Vekalet Suistimali ile Yetkisiz Onay

SAP Business Workflow, bir onaycı izinli veya seyahatteyken onay görevlerinin başka bir kullanıcıya yönlendirilmesine izin veren bir **vekalet (substitution)** mekanizması sunar. Yüksek onay limitine sahip bir yönetici, izne çıkmadan önce vekalet ayarını yapar; ancak bu ayar normalde çok daha düşük bir onay limitine sahip, daha kıdemsiz bir çalışana tanımlanır. Vekil çalışan, izin süresi boyunca kendi normal yetki seviyesinin çok üzerinde tutarlı satın alma siparişlerini veya fatura ödemelerini onaylar — bazıları gerçek iş ihtiyacından, bazıları kötüye kullanım veya bir tedarikçiyle iş birliğinden kaynaklanır. Sonuç, hem finansal kayıp hem de onay hiyerarşisinin fiilen devre dışı kalmasıdır.

**Neden SOC bunu göremez:** Vekalet ataması ve onay işlemi, workflow motorunun tamamen standart, kendi içinde tutarlı bir kullanımıdır; her onay kaydı "bir kullanıcı bir belgeyi onayladı" şeklinde normal görünür. Onaylayan kişinin normalde bu tutarda bir onay yetkisine sahip olmaması bilgisi, log kaydının içinde değil, SAP'ın yetki/limit yapılandırmasında saklıdır — ve bu ikisini birlikte değerlendirmeyen bir kural bu örüntüyü kaçırır.

**Basis ekibinin bilmesi gereken:** Workflow agent determination ve vekalet (substitution) atamaları düzenli gözden geçirilmeli; bir vekilin, asıl onaycının onay limitine veya yetki seviyesine sahip olmadığı durumlar özel olarak işaretlenmeli. Ayrıca release strategy'nin manuel olarak bypass edildiği veya "workflow dışı" onay yapıldığı durumlar (örn. ME29N üzerinde manuel release) ayrıca loglanmalı ve izlenmelidir. Bu, hem bir görev ayrılığı/yetki sorunu hem de doğrudan bir iç tehdit göstergesidir; finansal kayıp veya iş akışının bütünlüğünün bozulması ihtimali en yüksek senaryolardan biridir.

Bu yedi senaryonun ortak noktası şudur: hiçbiri klasik bir "exploit" veya malware içermiyor. Hepsi SAP'ın kendi normal mekanizmalarının — yetki ataması, şifre yönetimi, debug araçları, sistemler arası güven ilişkileri, görev tanımları, bakım operasyonları, workflow vekalet sistemi — gözetimsiz veya yanlış yapılandırılmış kullanımı. Bu da SAP güvenliğinin neden "patch yönetimi" kadar "yapılandırma ve davranış izleme" meselesi olduğunu gösteriyor; özellikle Senaryo 7, dış saldırgan olmadan, tamamen yetkili bir iç kullanıcı tarafından, sistemin kendi onay mekanizması kullanılarak nasıl ciddi finansal kayıp veya operasyonel kesinti yaratılabileceğini gösteriyor.

## Neden Generic IT Güvenlik Araçları SAP'ı "Göremiyor"

Yukarıdaki senaryolar ışığında, generic araçların SAP'ı kaçırma sebeplerini daha somut sıralayabiliriz:

**Log formatı ve terminoloji uyumsuzluğu.** SAP Security Audit Log'daki bir "AU3" olayı (RFC/CPIC login başarısız) ile bir Windows event log'daki başarısız login olayı aynı SIEM kuralıyla yakalanamaz. SAP'ın kendi olay sınıfları (AU1, AU3, AU5, AUW vb.), kendi T-code terminolojisi ve kendi authorization object yapısı vardır. Bu yapıyı tanımayan bir parser, logu ya hiç anlamlı şekilde işleyemez ya da yanlış normalize eder.

**Varsayılan loglama kapalı veya yetersiz.** Çoğu SAP sisteminde Security Audit Log default olarak ya kapalıdır ya da çok dar bir filtre setiyle çalışır. SOC'a "neden SAP'tan log gelmiyor" sorusunun cevabı çoğu zaman çok basittir: SAP tarafında o log hiç üretilmiyor. Bunu Bölüm 2'de detaylı işleyeceğiz.

**Yetki modelinin karmaşıklığı.** Bir kullanıcının SAP_ALL'a sahip olması, AD'de "Domain Admin" olmasından çok daha sık ve çoğu zaman fark edilmeden gerçekleşir — çünkü rol/profil atamaları SAP'a özgü bir süreçle yönetilir ve bu süreç genellikle SOC'un görüş alanı dışındadır.

**Baseline (normal davranış) tanımının eksikliği.** Bir kullanıcının hangi T-code'ları, hangi tabloları, hangi saatlerde kullanmasının "normal" olduğu bilgisi SAP'a özgüdür ve genelde sadece Basis/iş birimleri bilir. Bu baseline SOC'a aktarılmadan kurulan herhangi bir anomali kuralı, ya aşırı gürültülü ya da anlamsız kalır.

**Multi-client ve zaman damgası karmaşıklığı.** Aynı sistem içinde birden fazla client'ın, farklı zaman dilimlerinde çalışan sunucuların ve bazen birden fazla dilde üretilen log mesajlarının normalize edilmesi, generic bir log toplama aracının default yapılandırmasıyla doğru yapılamaz.

Sonuç: SAP, kurumun en kritik verisini taşırken, SOC'un en az "instrumente edilmiş" sistemi olarak kalır.

## Basis Ekibinin SOC İçin Neden Kritik Olduğu

Bir SOC analisti, bir Windows alarmını triage ederken Sysmon, Event Viewer, Active Directory yapısına dair yeterli bilgiye genelde sahiptir. Aynı analist bir SAP alarmı gördüğünde — örneğin "kullanıcı X, T-code SE16'da MARA tablosuna doğrudan erişti" — bu olayın ne kadar normal ya da ne kadar kritik olduğunu Basis ekibinin bilgisi olmadan değerlendiremez.

Bu işbirliğini somutlaştırmak için basit bir sorumluluk dağılımı (RACI) faydalı olur:

| Aktivite | Basis Ekibi | SOC | Güvenlik/GRC | Yönetim |
|---|---|---|---|---|
| Loglama politikasının belirlenmesi (hangi olaylar açılacak) | Sorumlu (R) | Danışılan (C) | Onaylayan (A) | Bilgilendirilen (I) |
| SIEM entegrasyonu ve parsing | Danışılan (C) | Sorumlu (R) | Bilgilendirilen (I) | — |
| Kritik use-case tanımı (hangi davranış anomali sayılır) | Sorumlu (R) | Danışılan (C) | Onaylayan (A) | — |
| Detection kuralının yazılması (SPL/AQL) | Danışılan (C) | Sorumlu (R) | Bilgilendirilen (I) | — |
| Kritik yetki atamalarının onayı (SAP_ALL, S_DEVELOP vb.) | Sorumlu (R) | Bilgilendirilen (I) | Onaylayan (A) | — |
| Şifre sıfırlama / hesap kurtarma politikası | Sorumlu (R) | Danışılan (C) | Onaylayan (A) | — |
| SoD matris taraması ve GRC entegrasyonu | Danışılan (C) | Bilgilendirilen (I) | Sorumlu (R) | Bilgilendirilen (I) |
| Client copy / sistem yenileme onayı ve veri maskeleme | Sorumlu (R) | Bilgilendirilen (I) | Danışılan (C) | — |
| RFC trust ilişkilerinin envanteri ve gözden geçirilmesi | Sorumlu (R) | Danışılan (C) | Onaylayan (A) | — |
| Workflow vekalet (substitution) atamalarının gözden geçirilmesi | Sorumlu (R) | Bilgilendirilen (I) | Onaylayan (A) | — |
| Alarm triage (ilk değerlendirme) | Danışılan (C) | Sorumlu (R) | — | — |
| SAP'a özgü doğrulama (gerçek mi, false positive mi) | Sorumlu (R) | Danışılan (C) | — | — |
| Olay kapatma ve kök neden analizi | Sorumlu (R) | Sorumlu (R) | Bilgilendirilen (I) | Bilgilendirilen (I) |
| Patch yönetimi (SAP Security Notes) | Sorumlu (R) | Bilgilendirilen (I) | Danışılan (C) | — |
| Yönetim raporlaması | Danışılan (C) | Sorumlu (R) | Onaylayan (A) | Bilgilendirilen (I) |

Bu tablonun gösterdiği temel prensip şu: SOC, tespit ve ilk triage'ın sahibidir; Basis, SAP'a özgü bağlamın ve doğrulamanın sahibidir. İkisi de "Sorumlu" olduğu adımlarda diğerini "Danışılan" konumunda tutar — yani süreç tek taraflı işlemez.

Bir alarmın pratikte nasıl aktığını basit bir akışla gösterelim:

```
SAP Log Üretimi (SM19/SM20, DBTABLOG, Gateway log)
        │
        ▼
SIEM'e Aktarım ve Parsing (Add-on / DSM)
        │
        ▼
Detection Kuralı Tetiklenir (SPL/AQL)
        │
        ▼
SOC İlk Triage: Bağlam toplama (kullanıcı, T-code, client, zaman)
        │
        ├── Açıkça benign ise → Kapat, kural ayarını iyileştir
        │
        ▼
Basis Ekibine Eskalasyon: "Bu kullanıcı/işlem normal mi?"
        │
        ├── Basis: Evet, bilinen bir operasyon → False positive olarak kapat,
        │            kural/whitelist güncellenir
        │
        └── Basis: Hayır, beklenmeyen → Ortak olay müdahalesi başlar
                    (Bölüm 7'de detaylandırılacak)
```

Bu üçlü yapı olmadan ortaya çıkan iki tipik başarısızlık modeli vardır: SOC'un SAP'ı "kara kutu" olarak görüp izlemeyi tamamen Basis ekibine bırakması (ki bu genellikle reaktif ve tutarsız bir güvenlik duruşu üretir), veya SOC'un SAP'a generic kurallar uygulayıp anlamlı sinyal yerine gürültü üretmesi — bu da zamanla Basis ekibinin SOC alarmlarını ciddiye almamasına, "yine SAP'tan yanlış alarm" yorgunluğuna yol açar.

## Serinin Yol Haritası

Önümüzdeki sekiz bölümde şu sırayla ilerleyeceğiz:

**Bölüm 2 — SAP Loglama Politikaları:** Hangi olayların loglanması gerektiği, SM19/SM20 yapılandırması, performans ve disk etkisiyle dengeleme, yaygın yanlış yapılandırmalar.

**Bölüm 3 — Logların Merkezi SIEM'e Aktarılması ve Parsing:** SAP Add-on for Splunk mimarisi, QRadar entegrasyon yaklaşımı, normalizasyon sorunları, hacim planlaması.

**Bölüm 4 — Splunk CIM Modeli ve Add-on Hazır Use-Case'leri:** CIM data model mantığının SAP'a uyarlanışı, Add-on'un hazır gelen saved search'leri, bunların sınırları.

**Bölüm 5 — Kritik Detection Use-Case'leri:** SPL ile yazılmış somut kurallar (bu bölümde tanıttığımız yedi senaryonun detection mantığı dahil), kritik noktalarda QRadar AQL karşılaştırması.

**Bölüm 6 — Operasyonel Güvenlik:** Patch yönetimi, transport süreçleri, SoD izleme, RFC/trust yönetimi.

**Bölüm 7 — Olay Müdahalesi:** SAP'a özgü triage adımları, SOC-Basis çalışma akışının detaylandırılması, false positive yönetimi.

**Bölüm 8 — Güvenlik Raporlama:** Yönetim ve operasyonel raporlar, uyumluluk raporlaması.

**Bölüm 9 — Olgunluk Modeli ve Yol Haritası:** Detection coverage ölçümü, SAP ETD ile SIEM ilişkisi, sürekli iyileştirme.

Bir sonraki bölümde işin temeline iniyoruz: loglama açık değilse, geri kalan her şey teoride kalır. SAP'ta hangi olay sınıflarının açılması gerektiğini, bunun performansa etkisini ve en sık yapılan yapılandırma hatalarını detaylı işleyeceğiz.
