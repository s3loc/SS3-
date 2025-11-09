# SS3 — Security & OSINT Intelligence Framework
---

<img width="1024" height="1024" alt="SS3" src="https://github.com/user-attachments/assets/e886dfaf-8b2a-4830-903e-f1c1bc571f5f" />




Modüler OSINT ve güvenlik istihbaratı çerçevesi. Pasif/aktif keşif, veri arşivleme, ağ ilişkileri analizi, ölçülebilir risk skoru ve **eyleme dönük** öneriler üretir.

> ⚠️ yalnızca eğitim, araştırma ve yetkilendirilmiş sızma testleri için sağlanır. Bu yazılımın izinsiz sistemlere, ağlara veya veriye karşı kullanımı kesinlikle yasaktır ve hukuka aykırı olabilir. Kullanımınızdan doğan tüm risk ve sorumluluk size aittir.

YAZILIM “OLDUĞU GİBİ” SUNULUR; AÇIK VEYA ZIMNİ HER TÜRLÜ GARANTİ REDDEDİLİR. [YAZAR/KURUM_ADI] hiçbir koşulda doğrudan, dolaylı, arızi, özel veya sonuçsal zararlardan sorumlu tutulamaz.

Bu proje MIT Lisansı ile lisanslanmıştır; lisans koşulları ile bu sorumluluk reddi birlikte uygulanır. Ayrıntılı sürüm için `LEGAL_DISCLAIMER.md` dosyasına bakınız.

---

## Özellikler

- **Sentinel Node:** WHOIS, DNS, alt alanlar, HTTP güvenlik başlıkları, SSL durumu; ek olarak **asenkron port tarama + banner grabbing + CVE eşleştirme**.
- **Council Mesh:** NetworkX tabanlı ilişki grafı, merkezilik/yoğunluk analizleri, port ve teknoloji düğümleriyle zengin bağlam.
- **Archivum Core:** Sıkıştırma + şifreleme (Fernet), çoklu hash (MD5/SHA-1/SHA-256/SHA-512/BLAKE2b) ve disk arşivleme.
- **Ledger:** RSA imzalı, “quantum-hardened” hash zinciri ve SQLite kalıcılık; bütünlük ve doğrulama kayıtları.
- **Grand Node:** Executive summary, risk skoru/level, bulgu sayıları ve **otomatik düzeltme önerileri** (WAF, port kısıtlama, DMARC, SSL, header vb.).
- **Dashboard:** Flask tabanlı API + HTML rapor üretimi; “Önerilen Güvenlik Önlemleri” bölümünü görsel kartlar halinde sunar.

## Mimari

```

SS3_Main.py
├─ Sentinel_Node.py        # OSINT + aktif tarama/CVE
├─ Archivum_Core.py        # Arşivleme / şifreleme / hash
├─ Council_Mesh.py         # Ağ grafı ve ilişkisel analiz
├─ Ledger.py               # İmza, zincir ve veritabanı
├─ Grand_Node.py           # Özet, skor, öneriler
└─ SS3_Dashboard.py        # Flask API + HTML rapor

```

## Kurulum

```

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -U pip wheel

# Çekirdek gereksinimler (örnek)

pip install flask requests dnspython python-whois ipwhois beautifulsoup4 
aiohttp networkx plotly pandas cryptography

# Opsiyonel: shodan (API anahtarı varsa)

pip install shodan

```

İsteğe bağlı ortam değişkenleri:
```

export SHODAN_API_KEY="..."   # varsa Sentinel kullanır

```

## Hızlı Başlangıç

### 1) Komut satırından analiz
```

python SS3_Main.py

# İstendiğinde hedefi gir: example.com

```

### 2) Dashboard (API + HTML rapor)
Geliştirme modunda çalıştır:
```

export FLASK_APP=SS3_Dashboard.py
flask run --host 0.0.0.0 --port 5000

```

İstek:
```

POST /run
Content-Type: application/json
{"target": "example.com"}

```

Oluşan HTML rapor: `reports/SS3_Report_YYYYMMDD_HHMMSS_example.com.html`

## Çıktılar

- **Risk skoru:** 0.0–1.0 arası normalize değer.
- **Özet:** kritik/yüksek/orta/düşük bulgu sayıları.
- **Öneriler:** WAF etkinleştirme, port kısıtlama (22/445/3389), DMARC politikası, SSL yenileme, güvenlik başlıkları (CSP, HSTS, X-Frame-Options) vb.
- **Aktif Tarama:** açık port listesi, servis/sürüm ve **potansiyel CVE’ler**.

## Güvenlik ve Uyum

- Aktif tarama sadece **izinli** hedeflerde çalıştırın.
- Her analiz için denetim kaydı (audit) tutmanız önerilir (kullanıcı, zaman, hedef, modüller).
- API anahtarlarını `.env` dosyasında saklayın; repoya dahil etmeyin.

## Dağıtım (öneri)

- Production: Gunicorn + Nginx (SSL) arkası:
```

gunicorn SS3_Dashboard:app -w 4 -b 0.0.0.0:8080

```
- Logs: `journalctl` veya dosya tabanlı log rotasyonu.

## Katkı

PR’lar memnuniyetle karşılanır. Lütfen yeni modüllerde:
- Giriş doğrulaması ve zaman aşımı ekleyin.
- Ağ trafiği üreten işlemlerde **kullanım uyarısı** gösterin.
- Raporlama sözleşmesini (JSON alan adları) koruyun.

## Lisans

MIT License. Ayrıntılar için `LICENSE` dosyasına bakın.

---

### Sorumluluk Reddi

Bu proje yalnızca izinli güvenlik testleri, kurumsal güvenlik değerlendirmeleri ve eğitim amaçlıdır. Yazarlar, yetkisiz kullanımdan doğabilecek **her türlü** zarardan sorumlu değildir.  

![giphy](https://github.com/user-attachments/assets/1d9f104b-ca94-4d14-9ab6-e9d87b7a04ce)





