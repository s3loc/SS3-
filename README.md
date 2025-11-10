<img width="1024" height="1024" alt="SS3" src="https://github.com/user-attachments/assets/2372e816-66c7-41a5-a1ec-1689a361c397" />

```markdown
# 🔍 SS3 — Security & OSINT Intelligence Framework




Modüler OSINT ve güvenlik istihbaratı çerçevesi. Pasif/aktif keşif, veri arşivleme, ağ ilişkileri analizi, ölçülebilir risk skoru ve **eyleme dönüştürülebilir** güvenlik önerileri sunar.

---

## ⚠️ Sorumluluk Reddi ve Uyarı

Bu yazılım **yalnızca** aşağıdaki amaçlarla kullanılabilir:
- Eğitim ve akademik araştırmalar
- Yetkilendirilmiş sızma testleri
- Kurumsal güvenlik değerlendirmeleri

**Yasaklı Kullanım:**  
İzinsiz sistemlere, ağlara veya verilere karşı kullanımı kesinlikle yasaktır ve yasal ihlal oluşturabilir. Kullanıcı, kendi eylemlerinden doğacak tüm risk ve sorumlulukları kabul eder.

**Yazılım "OLDUĞU GİBİ" sunulmaktadır.** Açık veya zımni hiçbir garanti verilmemektedir. Geliştiriciler, doğrudan veya dolaylı zararlardan sorumlu tutulamaz.

Detaylı hükümler için [`LEGAL_DISCLAIMER.md`](LEGAL_DISCLAIMER.md) dosyasına bakınız.

---

## ✨ Temel Özellikler

| Modül | Açıklama |
|-------|----------|
| **🛡️ Sentinel Node** | WHOIS, DNS, alt alan tarama, HTTP güvenlik başlıkları, SSL durumu. **Asenkron port tarama + banner grabbing + CVE eşleştirme** |
| **🕸️ Council Mesh** | NetworkX tabanlı ilişki grafları, merkezilik/yoğunluk analizleri, port ve teknoloji düğümleri |
| **💾 Archivum Core** | Sıkıştırma + şifreleme (Fernet), çoklu hash (MD5/SHA-1/SHA-256/SHA-512/BLAKE2b), disk arşivleme |
| **📒 Ledger** | RSA imzalı "quantum-hardened" hash zinciri, SQLite kalıcılık, bütünlük ve doğrulama kayıtları |
| **🎯 Grand Node** | Executive summary, risk skoru/seviyesi, bulgu sayıları ve **otomatik düzeltme önerileri** |
| **📊 Dashboard** | Flask tabanlı API + HTML rapor üretimi, görsel kartlarla güvenlik önerileri |

---

## 🏗️ Mimari Yapı

```
SS3_Main.py
├─ Sentinel_Node.py        # OSINT + aktif tarama/CVE
├─ Archivum_Core.py        # Arşivleme / şifreleme / hash
├─ Council_Mesh.py         # Ağ grafı ve ilişkisel analiz
├─ Ledger.py               # İmza, zincir ve veritabanı
├─ Grand_Node.py           # Özet, skor, öneriler
└─ SS3_Dashboard.py        # Flask API + HTML rapor
```

---

## 🚀 Kurulum

### Temel Gereksinimler
- Python 3.8+
- pip (en son sürüm)

### Adım Adım Kurulum

1. **Sanal ortam oluştur ve etkinleştir:**
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

2. **Gereksinimleri yükle:**
```bash
pip install -U pip wheel
pip install flask requests dnspython python-whois ipwhois beautifulsoup4 aiohttp networkx plotly pandas cryptography
```

3. **Opsiyonel: Shodan entegrasyonu (API anahtarı gerektirir):**
```bash
pip install shodan
```

### Ortam Değişkenleri
```bash
export SHODAN_API_KEY="your_api_key_here"  # Shodan entegrasyonu için
export FLASK_ENV="development"             # Geliştirme modu
```

---

## 🎮 Kullanım

### 1. Komut Satırı Arayüzü
```bash
python SS3_Main.py
# İstendiğinde hedef domain/IP girin: example.com
```

### 2. Web Dashboard
```bash
export FLASK_APP=SS3_Dashboard.py
flask run --host 0.0.0.0 --port 5000
```

**API Kullanımı:**
```bash
curl -X POST http://localhost:5000/run \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'
```

**Çıktı:** `reports/SS3_Report_YYYYMMDD_HHMMSS_example.com.html`

---

## 📈 Çıktılar ve Raporlama

### Risk Metrikleri
- **Risk Skoru:** 0.0-1.0 arası normalize değer
- **Bulgu Seviyeleri:** Kritik/Yüksek/Orta/Düşük sınıflandırması
- **Özet Dashboard:** Görsel ve istatistiksel özet

### Güvenlik Önerileri
- WAF konfigürasyon önerileri
- Port güvenliği (22/445/3389 kısıtlama)
- DMARC/DKIM/SPF politikaları
- SSL/TLS iyileştirmeleri
- HTTP güvenlik başlıkları (CSP, HSTS, X-Frame-Options)

### Aktif Tarama Sonuçları
- Açık port listesi ve servis bilgileri
- Banner bilgileri ve sürüm tespiti
- Potansiyel CVE eşleştirmeleri

---

## 🔒 Güvenlik ve Uyum

### Best Practices
- Aktif taramaları yalnızca **yetkilendirilmiş** hedeflerde çalıştırın
- Tüm analizler için denetim kaydı (audit log) tutun
- API anahtarlarını `.env` dosyasında saklayın
- Production ortamında SSL/TLS kullanın

### Denetim Kaydı
Her analiz için aşağıdaki bilgileri kaydedin:
- Kullanıcı ve zaman damgası
- Hedef domain/IP
- Çalıştırılan modüller
- Risk skoru ve bulgu özeti

---

## 🌐 Production Dağıtımı

### Gunicorn + Nginx
```bash
gunicorn SS3_Dashboard:app -w 4 -b 0.0.0.0:8080
```

### Log Yönetimi
```bash
# Systemd servisi ile
journalctl -u ss3-service

# Dosya tabanlı log
logrotate /etc/logrotate.d/ss3
```

---

## 🤝 Katkıda Bulunma

Katkılarınızı memnuniyetle karşılıyoruz! Yeni modül geliştirirken:

- Giriş doğrulama ve zaman aşımı ekleyin
- Ağ işlemlerinde **kullanım uyarısı** gösterin
- Mevcut raporlama JSON formatını koruyun
- Test coverage'i artırın

### Katkı Süreci
1. Fork edin ve feature branch oluşturun
2. Değişikliklerinizi test edin
3. PR açın ve değişiklikleri detaylandırın

---

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [`LICENSE`](LICENSE) dosyasına bakınız.

---

## 🆘 Destek ve İletişim

- **Hata Raporları:** GitHub Issues
- **Güvenlik Açıkları:** Özel mesaj yoluyla
- **Dokümantasyon:** [`docs/`](docs/) klasörü

  
![giphy](https://github.com/user-attachments/assets/837ee5e3-be71-459d-9409-cc82db863dec)

---


```
*"Bilgi güçtür, ancak sorumlulukla kullanıldığında değer kazanır."*
