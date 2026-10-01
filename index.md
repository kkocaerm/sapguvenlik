---
layout: default
title: SAP Güvenliği Yazı Dizisi
nav_order: 1
description: "SAP Güvenliği: Loglama, SIEM Entegrasyonu, Detection Kuralları ve Operasyonel Güvenlik"
permalink: /
---

# SAP Güvenliği Yazı Dizisi
{: .no_toc }

SAP ortamlarını bütünsel bir güvenlik yaklaşımıyla ele alan bu seri; loglama politikalarından SIEM entegrasyonuna, Splunk SPL detection kurallarından operasyonel güvenliğe, olay müdahalesinden raporlamaya kadar uçtan uca bir yol haritası sunmaktadır.

**Hedef Kitle:** SAP Basis ve güvenlik ekipleri  
**SIEM:** Splunk (SAP Add-on / CIM) — kritik noktalarda IBM QRadar AQL karşılaştırması  
**Düzenleyici Çerçeve:** BDDK, KVKK, SOX  
{: .fs-5 .fw-300 }

---

## Bölüm Durumu
{: .no_toc }

| # | Bölüm | Durum |
|---|---|---|
| 1 | [SAP Güvenliğine Bütünsel Bakış]({% link docs/01-butunsel-bakis.md %}) | ✅ Yayında |
| 2 | [Loglama Politikaları]({% link docs/02-loglama-politikalari.md %}) | ✅ Yayında |
| 3 | [Logların SIEM'e Aktarılması ve Parsing]({% link docs/03-siem-aktarim-parsing.md %}) | ✅ Yayında |
| 4 | [Splunk CIM Modeli ve Add-on Use-Case'leri]({% link docs/04-splunk-cim-addon.md %}) | ✅ Yayında |
| 5 | [Kritik Detection Use-Case'leri]({% link docs/05-detection-usecases.md %}) | ✅ Yayında |
| 6 | [Operasyonel Güvenlik]({% link docs/06-operasyonel-guvenlik.md %}) | ✅ Yayında |
| 7 | [Olay Müdahalesi: Triage ve Forensics]({% link docs/07-olay-mudahalesi.md %}) | ✅ Yayında |
| 8 | [Güvenlik Raporlama]({% link docs/08-guvenlik-raporlama.md %}) | ✅ Yayında |
| 9 | [Olgunluk Modeli ve Yol Haritası]({% link docs/09-olgunluk-modeli.md %}) | ✅ Yayında |

---

## Bu Seri Neden Var

SAP, çoğu kurumda finans, satın alma, üretim ve insan kaynakları gibi en kritik süreçlerin üzerinde çalıştığı sistemdir. Aynı zamanda çoğu SOC'un en az görünür olduğu, en az anladığı sistemdir. Bu iki gerçek yan yana durduğunda ciddi bir kör nokta oluşur: kurumun en değerli verisi, en az izlenen platformda durur.

Bu seri, **SAP Basis ve güvenlik ekiplerini** buluşturmak için hazırlanmıştır. Her bölüm, iki ekibin birlikte yapması gereken işi somut teknik adımlarla, gerçek dünyadan damıtılmış senaryolarla ve çalışır durumda Splunk SPL kurallarıyla anlatmaktadır.

## Serinin Kapsamı

```
Bölüm 1  ──→  Bölüm 2  ──→  Bölüm 3  ──→  Bölüm 4
Mimari &       Loglama        SIEM           CIM Modeli &
Risk Bağlamı   Politikası     Aktarımı       Hazır Use-Case

     ──→  Bölüm 5  ──→  Bölüm 6  ──→  Bölüm 7  ──→  Bölüm 8  ──→  Bölüm 9
          Detection      Operasyonel    Olay           Raporlama      Olgunluk &
          SPL Kuralları  Güvenlik       Müdahalesi                    Yol Haritası
```
