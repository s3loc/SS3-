# SS3_Dashboard.py
from flask import Flask, render_template, jsonify, request, send_file
from SS3_Main import SS3
from datetime import datetime
import os
import logging
import re
import json
import time
import sys

# Logging konfigürasyonu
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ASCII Sanat ve Animasyon
WELCOME_ASCII = """
/$$    /$$  /$$$$$$  /$$$$$$$  /$$   /$$ /$$   /$$
| $$   | $$ /$$__  $$| $$__  $$| $$  | $$| $$  / $$
| $$   | $$| $$  \ $$| $$  \ $$| $$  | $$|  $$/ $$/
|  $$ / $$/| $$$$$$$$| $$$$$$$/| $$  | $$ \  $$$$/ 
 \  $$ $$/ | $$__  $$| $$__  $$| $$  | $$  >$$  $$ 
  \  $$$/  | $$  | $$| $$  \ $$| $$  | $$ /$$/\  $$
   \  $/   | $$  | $$| $$  | $$|  $$$$$$/| $$  \ $$
    \_/    |__/  |__/|__/  |__/ \______/ |__/  |__/                         
"""

def animate_ascii():
    """ASCII animasyonu göster"""
    frames = [
        """
    🛡️  SS3 Intelligence Dashboard 🛡️
    ═══════════════════════════════════
    """,
        """
    🚀 Güvenlik Analiz Sistemine Hoş Geldiniz 🚀
    ════════════════════════════════════════════
    """,
        """
    📊 OSINT • Ağ Analizi • Risk Değerlendirmesi 📊
    ═══════════════════════════════════════════════
    """
    ]
    
    for frame in frames:
        print("\033[H\033[J")  # Ekranı temizle
        print(WELCOME_ASCII)
        print(frame)
        time.sleep(1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run', methods=['POST'])
def run_analysis():
    try:
        target = request.json.get('target')
        
        if not target:
            return jsonify({"error": "Hedef belirtilmedi"}), 400

        logger.info(f"Analiz başlatılıyor: {target}")
        
        # SS3 instance'ını oluştur (modüller otomatik başlatılır)
        ss3 = SS3()
        
        # Analizi çalıştır
        print(f"\n🎯 Hedef analiz ediliyor: {target}")
        start_time = time.time()
        results = ss3.run_analysis(target)
        processing_time = time.time() - start_time
        
        # DEBUG: Sonuçları kontrol et
        print(f"\n🔍 Analiz tamamlandı. İşlem süresi: {processing_time:.2f}s")
        print(f"📊 Sonuç anahtarları: {list(results.keys())}")
        
        # Grand Node verisini al ve kontrol et
        grand_data = results.get("grand", {})
        if not grand_data:
            print("⚠️  Grand Node verisi boş, fallback kullanılıyor")
            summary = create_fallback_summary(results, target)
            recommendations = []
        else:
            print(f"✅ Grand Node verisi alındı: {grand_data.keys()}")
            
            # Executive dashboard kontrolü
            if 'executive_dashboard' not in grand_data:
                print("⚠️  Executive dashboard eksik, fallback kullanılıyor")
                summary = create_fallback_summary(results, target)
                recommendations = []
            else:
                executive_dashboard = grand_data['executive_dashboard']
                summary = executive_dashboard.get("executive_summary", {})
                recommendations = executive_dashboard.get("recommendations", [])
                if not summary:
                    print("⚠️  Executive summary boş, fallback kullanılıyor")
                    summary = create_fallback_summary(results, target)
                else:
                    print("✅ Executive summary başarıyla alındı")
        
        print(f"📊 Summary verisi: {summary}")
        print(f"📋 Öneri sayısı: {len(recommendations)}")
        
        # Response mesajını oluştur
        message = create_response_message(target, summary, processing_time)
        
        # HTML Raporu oluştur ve kaydet
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_dir = "reports"
            os.makedirs(report_dir, exist_ok=True)
            safe_target = re.sub(r'[^a-zA-Z0-9_.-]', '_', target)
            report_path = os.path.join(report_dir, f"SS3_Report_{timestamp}_{safe_target}.html")
            
            # HTML rapor içeriği
            html_report = create_html_report(target, summary, results, timestamp, processing_time, recommendations)
            
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            
            logger.info(f"HTML rapor kaydedildi: {report_path}")
            message += f"\n\n📄 HTML Rapor oluşturuldu: {report_path}"
            
        except Exception as e:
            logger.error(f"Rapor kaydetme hatası: {e}")
            message += f"\n\n⚠️  Rapor kaydedilemedi: {e}"

        return jsonify({
            "message": message, 
            "report_path": report_path,
            "summary": summary,
            "processing_time": processing_time,
            "recommendations_count": len(recommendations)
        })

    except Exception as e:
        logger.error(f"Analiz hatası: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": f"Analiz sırasında hata oluştu: {str(e)}"
        }), 500

def create_fallback_summary(results, target):
    """Grand Node çalışmazsa temel bir summary oluştur"""
    print("🔄 Fallback summary oluşturuluyor...")
    
    sentinel_data = results.get('sentinel', {})
    council_data = results.get('council', {})
    
    # Temel bilgileri topla
    total_findings = 0
    
    # Sentinel verilerinden bulgular
    try:
        if sentinel_data:
            # DNS kayıtları
            dns_data = sentinel_data.get('dns', {})
            if isinstance(dns_data, dict):
                for record_type, records in dns_data.items():
                    if isinstance(records, list):
                        total_findings += len(records)
            
            # Subdomainler
            subdomains = sentinel_data.get('subdomains', {}).get('subdomains', [])
            if isinstance(subdomains, list):
                total_findings += len(subdomains)
            
            # Sosyal medya hesapları
            social_media = sentinel_data.get('social_media', {})
            if isinstance(social_media, dict):
                for platform, accounts in social_media.items():
                    if isinstance(accounts, list):
                        total_findings += len(accounts)
    except Exception as e:
        print(f"⚠️  Sentinel verisi işlenirken hata: {e}")
    
    # Council verilerinden bulgular
    try:
        if council_data:
            graph_info = council_data.get('graph_info', {})
            if graph_info:
                total_nodes = graph_info.get('graph_summary', {}).get('total_nodes', 0)
                total_findings += total_nodes
    except Exception as e:
        print(f"⚠️  Council verisi işlenirken hata: {e}")
    
    # Risk hesaplama (basit)
    if total_findings > 50:
        risk_level = "YÜKSEK"
        risk_score = 0.8
        critical_issues = total_findings // 4
        high_risk_issues = total_findings // 2
        low_risk_issues = total_findings - critical_issues - high_risk_issues
    elif total_findings > 20:
        risk_level = "ORTA"
        risk_score = 0.5
        critical_issues = total_findings // 6
        high_risk_issues = total_findings // 3
        low_risk_issues = total_findings - critical_issues - high_risk_issues
    else:
        risk_level = "DÜŞÜK"
        risk_score = 0.2
        critical_issues = 0
        high_risk_issues = total_findings // 4
        low_risk_issues = total_findings - high_risk_issues
    
    return {
        'risk_score': round(risk_score, 2),
        'risk_level': risk_level,
        'total_findings': total_findings,
        'critical_issues': critical_issues,
        'high_risk_issues': high_risk_issues,
        'low_risk_issues': low_risk_issues,
        'recommendation_count': max(1, total_findings // 5),
        'timestamp': datetime.now().isoformat(),
        'analysis_version': '2.0',
        'fallback_used': True
    }

def create_response_message(target, summary, processing_time):
    """Yanıt mesajını oluştur"""
    risk_emoji = {
        'DÜŞÜK': '🟢',
        'ORTA': '🟡', 
        'YÜKSEK': '🟠',
        'KRİTİK': '🔴'
    }.get(summary.get('risk_level', 'Bilinmiyor'), '⚪')
    
    return (
        f"{risk_emoji} SS3 Analizi Tamamlandı {risk_emoji}\n"
        f"════════════════════════════════════════\n"
        f"🎯 Hedef: {target}\n"
        f"⚠️  Risk Düzeyi: {summary.get('risk_level', 'Bilinmiyor')}\n"
        f"📊 Risk Skoru: {summary.get('risk_score', 'N/A')}\n"
        f"📈 Toplam Bulgular: {summary.get('total_findings', 'N/A')}\n"
        f"🔴 Kritik Bulgular: {summary.get('critical_issues', 'N/A')}\n"
        f"🟠 Yüksek Risk: {summary.get('high_risk_issues', 'N/A')}\n"
        f"🟢 Düşük Risk: {summary.get('low_risk_issues', 'N/A')}\n"
        f"📋 Öneri Sayısı: {summary.get('recommendation_count', 'N/A')}\n"
        f"⏱️  İşlem Süresi: {processing_time:.2f}s\n"
        f"{'🔄 FALLBACK MOD' if summary.get('fallback_used') else '✅ NORMAL MOD'}\n"
        f"════════════════════════════════════════\n"
        f"⏰ Zaman: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )

def safe_serialize(obj):
    """Güvenli JSON serialization"""
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as e:
        return f"Serialization hatası: {str(e)}"

def create_html_report(target, summary, results, timestamp, processing_time, recommendations):
    """HTML formatında profesyonel rapor oluştur"""
    
    # Risk seviyesine göre renk
    risk_level = summary.get('risk_level', 'Bilinmiyor')
    risk_color = {
        'DÜŞÜK': '#00ff00',
        'ORTA': '#ffff00', 
        'YÜKSEK': '#ff9900',
        'KRİTİK': '#ff0000'
    }.get(risk_level.upper(), '#cccccc')
    
    # Değerleri güvenle al
    risk_score = summary.get('risk_score', 'N/A')
    total_findings = summary.get('total_findings', 'N/A')
    critical_issues = summary.get('critical_issues', 'N/A')
    high_risk_issues = summary.get('high_risk_issues', 'N/A')
    low_risk_issues = summary.get('low_risk_issues', 'N/A')
    
    # Düşük risk hesaplaması
    if all(isinstance(x, (int, float)) for x in [total_findings, critical_issues, high_risk_issues]):
        calculated_low_risk = total_findings - critical_issues - high_risk_issues
    else:
        calculated_low_risk = low_risk_issues
    
    # Detaylı sonuçları formatla
    detailed_results = safe_serialize(results)
    
    # Önerileri formatla
    recommendations_html = format_recommendations_html(recommendations)

    html_content = f'''
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SS3 Intelligence Raporu - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(25, 25, 35, 0.95);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            overflow: hidden;
            border: 1px solid #333;
        }}
        
        .header {{
            background: linear-gradient(135deg, #00ffcc 0%, #00ccff 100%);
            color: #0a0a0a;
            padding: 30px;
            text-align: center;
            position: relative;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .target-info {{
            background: rgba(0, 255, 204, 0.1);
            padding: 20px;
            border-left: 5px solid #00ffcc;
            margin: 20px;
            border-radius: 8px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 20px;
        }}
        
        .summary-card {{
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid #333;
            transition: transform 0.3s ease;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            border-color: #00ffcc;
        }}
        
        .risk-card {{
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border: 2px solid {risk_color};
            box-shadow: 0 0 20px {risk_color}40;
        }}
        
        .card-value {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .risk-value {{
            color: {risk_color};
            font-size: 2.5em;
        }}
        
        .card-label {{
            color: #888;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .details-section {{
            padding: 20px;
            margin: 20px;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 10px;
            border: 1px solid #333;
        }}
        
        .details-content {{
            background: #1a1a1a;
            padding: 20px;
            border-radius: 8px;
            margin-top: 15px;
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            border: 1px solid #333;
        }}
        
        .recommendations-section {{
            padding: 20px;
            margin: 20px;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 10px;
            border: 1px solid #333;
        }}
        
        .recommendations {{
            display: flex;
            flex-direction: column;
            gap: 15px;
            margin-top: 20px;
        }}
        
        .rec-item {{
            background: rgba(255, 255, 255, 0.05);
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #00ffcc;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .rec-item:hover {{
            transform: translateX(5px);
            border-left-color: #00ffff;
            box-shadow: 0 5px 15px rgba(0, 255, 255, 0.2);
        }}
        
        .rec-item.critical {{
            border-left-color: #ff4444;
            background: rgba(255, 68, 68, 0.1);
        }}
        
        .rec-item.critical:hover {{
            border-left-color: #ff0000;
            box-shadow: 0 5px 15px rgba(255, 0, 0, 0.3);
        }}
        
        .rec-item.high {{
            border-left-color: #ff9900;
            background: rgba(255, 153, 0, 0.1);
        }}
        
        .rec-item.high:hover {{
            border-left-color: #ff7700;
            box-shadow: 0 5px 15px rgba(255, 119, 0, 0.3);
        }}
        
        .rec-item.medium {{
            border-left-color: #ffff00;
            background: rgba(255, 255, 0, 0.1);
        }}
        
        .rec-item.medium:hover {{
            border-left-color: #ffcc00;
            box-shadow: 0 5px 15px rgba(255, 204, 0, 0.3);
        }}
        
        .rec-item.low {{
            border-left-color: #00ff00;
            background: rgba(0, 255, 0, 0.1);
        }}
        
        .rec-item.low:hover {{
            border-left-color: #00cc00;
            box-shadow: 0 5px 15px rgba(0, 204, 0, 0.3);
        }}
        
        .rec-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .rec-priority {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .priority-critical {{
            background: #ff4444;
            color: white;
        }}
        
        .priority-high {{
            background: #ff9900;
            color: black;
        }}
        
        .priority-medium {{
            background: #ffff00;
            color: black;
        }}
        
        .priority-low {{
            background: #00ff00;
            color: black;
        }}
        
        .rec-category {{
            font-weight: bold;
            font-size: 1.1em;
            color: #00ffcc;
        }}
        
        .rec-action {{
            margin: 10px 0;
            padding: 10px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 5px;
            border-left: 3px solid #00ffcc;
            font-weight: bold;
        }}
        
        .rec-impact {{
            color: #888;
            font-style: italic;
            margin: 5px 0;
        }}
        
        .rec-timeline {{
            text-align: right;
            color: #00ffcc;
            font-weight: bold;
            margin-top: 10px;
        }}
        
        .timestamp {{
            text-align: center;
            padding: 20px;
            color: #888;
            font-style: italic;
        }}
        
        .signature {{
            text-align: center;
            padding: 30px;
            background: rgba(0, 0, 0, 0.3);
            margin-top: 20px;
        }}
        
        .varux-logo {{
            font-size: 2em;
            font-weight: bold;
            background: linear-gradient(135deg, #00ffcc 0%, #00ccff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        
        .tagline {{
            color: #888;
            font-style: italic;
        }}
        
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff9900; }}
        .medium {{ color: #ffff00; }}
        .low {{ color: #00ff00; }}
        
        .fallback-warning {{
            background: linear-gradient(135deg, #ff4444 0%, #ff9900 100%);
            color: white;
            padding: 15px;
            text-align: center;
            margin: 20px;
            border-radius: 8px;
            font-weight: bold;
        }}
        
        .no-recommendations {{
            text-align: center;
            padding: 40px;
            color: #888;
            font-style: italic;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 8px;
            border: 1px dashed #333;
        }}
        
        @media (max-width: 768px) {{
            .summary-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .rec-header {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .rec-timeline {{
                text-align: left;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SS3 INTELLIGENCE DASHBOARD</h1>
            <div class="subtitle">Güvenlik Analiz ve İstihbarat Raporu</div>
        </div>
        
        {"<div class='fallback-warning'>⚠️ FALLBACK MOD - Grand Node verisi kullanılamadı</div>" if summary.get('fallback_used') else ""}
        
        <div class="target-info">
            <h2>🎯 Analiz Edilen Hedef</h2>
            <p style="font-size: 1.3em; margin-top: 10px; font-weight: bold;">{target}</p>
            <p style="margin-top: 5px; color: #888;">İşlem Süresi: {processing_time:.2f}s</p>
        </div>
        
        <div class="summary-grid">
            <div class="risk-card">
                <div class="card-label">Risk Seviyesi</div>
                <div class="card-value risk-value">{risk_level}</div>
                <div class="card-label">Genel Güvenlik Durumu</div>
            </div>
            
            <div class="summary-card">
                <div class="card-label">Risk Skoru</div>
                <div class="card-value">{risk_score}</div>
                <div class="card-label">0-1 Arası</div>
            </div>
            
            <div class="summary-card">
                <div class="card-label">Toplam Bulgu</div>
                <div class="card-value">{total_findings}</div>
                <div class="card-label">Tespit Edilen</div>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <div class="card-label critical">🔴 Kritik Bulgular</div>
                <div class="card-value critical">{critical_issues}</div>
                <div class="card-label">Acil Müdahale Gerekli</div>
            </div>
            
            <div class="summary-card">
                <div class="card-label high">🟠 Yüksek Risk</div>
                <div class="card-value high">{high_risk_issues}</div>
                <div class="card-label">Öncelikli Çözüm</div>
            </div>
            
            <div class="summary-card">
                <div class="card-label low">🟢 Düşük Risk</div>
                <div class="card-value low">{calculated_low_risk}</div>
                <div class="card-label">İzleme Gerekli</div>
            </div>
        </div>
        
        <div class="details-section">
            <h2>📊 Detaylı Analiz Sonuçları</h2>
            <div class="details-content">
                <pre>{detailed_results}</pre>
            </div>
        </div>
        
        <div class="recommendations-section">
            <h2>🚧 Önerilen Güvenlik Önlemleri</h2>
            {recommendations_html}
        </div>
        
        <div class="timestamp">
            Rapor oluşturulma tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
        </div>
        
        <div class="signature">
            <div class="varux-logo">VARUX</div>
            <div class="tagline">Security Intelligence & Threat Analysis</div>
            <div style="margin-top: 15px; color: #666;">
                Bu rapor SS3 Intelligence Dashboard tarafından otomatik olarak oluşturulmuştur.<br>
                Gizli ve hassas bilgiler içerir - yetkisiz dağıtımı yasaktır.
            </div>
        </div>
    </div>
</body>
</html>
'''
    return html_content

def format_recommendations_html(recommendations):
    """Önerileri HTML formatına dönüştür"""
    if not recommendations:
        return '''
        <div class="no-recommendations">
            <h3>📭 Öneri Bulunamadı</h3>
            <p>Bu analiz için özel güvenlik önerisi üretilemedi.</p>
            <p>Temel güvenlik önlemleri için genel öneriler:</p>
            <ul style="text-align: left; margin-top: 15px;">
                <li>Düzenli güvenlik güncellemeleri uygula</li>
                <li>Güçlü parola politikaları kullan</li>
                <li>Çok faktörlü kimlik doğrulama etkinleştir</li>
                <li>Ağ trafiğini düzenli olarak izle</li>
                <li>Yedekleme ve kurtarma prosedürleri oluştur</li>
            </ul>
        </div>
        '''
    
    recommendations_html = '<div class="recommendations">'
    
    for rec in recommendations:
        priority = rec.get('priority', 'MEDIUM').upper()
        category = rec.get('category', 'Genel Güvenlik')
        action = rec.get('action', 'Belirtilmemiş')
        impact = rec.get('impact', 'Belirtilmemiş')
        timeline = rec.get('timeline', 'Belirtilmemiş')
        
        # Priority'e göre CSS sınıfı belirle
        priority_class = priority.lower()
        priority_display = {
            'CRITICAL': 'KRİTİK',
            'HIGH': 'YÜKSEK', 
            'MEDIUM': 'ORTA',
            'LOW': 'DÜŞÜK'
        }.get(priority, 'ORTA')
        
        recommendations_html += f'''
        <div class="rec-item {priority_class}">
            <div class="rec-header">
                <div class="rec-category">{category}</div>
                <div class="rec-priority priority-{priority_class}">[{priority_display}]</div>
            </div>
            <div class="rec-action">{action}</div>
            <div class="rec-impact">💡 Etki: {impact}</div>
            <div class="rec-timeline">⏱️ {timeline}</div>
        </div>
        '''
    
    recommendations_html += '</div>'
    return recommendations_html

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint bulunamadı"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Sunucu iç hatası"}), 500

@app.route('/reports')
def list_reports():
    """Mevcut raporları listele"""
    report_dir = "reports"
    if not os.path.exists(report_dir):
        return jsonify({"error": "Henüz rapor oluşturulmadı"}), 404
    
    try:
        files = sorted(
            [f for f in os.listdir(report_dir) if f.startswith("SS3_Report_") and f.endswith(".html")],
            reverse=True
        )
        
        if not files:
            return jsonify({"error": "Henüz rapor oluşturulmadı"}), 404
        
        reports_list = []
        for file in files:
            file_path = os.path.join(report_dir, file)
            file_time = os.path.getctime(file_path)
            formatted_time = datetime.fromtimestamp(file_time).strftime('%d.%m.%Y %H:%M')
            reports_list.append({
                "filename": file,
                "created_time": formatted_time,
                "download_url": f"/download/{file}",
                "view_url": f"/view/{file}"
            })
        
        return jsonify({"reports": reports_list})
    
    except Exception as e:
        logger.error(f"Rapor listeleme hatası: {e}")
        return jsonify({"error": f"Raporlar listelenirken hata oluştu: {str(e)}"}), 500

@app.route('/download/<filename>')
def download_report(filename):
    """Rapor dosyasını indir"""
    try:
        report_dir = "reports"
        file_path = os.path.join(report_dir, filename)
        
        # Güvenlik kontrolü - sadece HTML dosyalarına izin ver
        if not filename.endswith('.html') or '..' in filename or not os.path.exists(file_path):
            return jsonify({"error": "Geçersiz dosya"}), 400
            
        return send_file(file_path, as_attachment=True)
    
    except Exception as e:
        logger.error(f"İndirme hatası: {e}")
        return jsonify({"error": f"Dosya indirilirken hata oluştu: {str(e)}"}), 500

@app.route('/view/<filename>')
def view_report(filename):
    """Belirli bir raporu göster"""
    try:
        report_dir = "reports"
        file_path = os.path.join(report_dir, filename)
        
        # Güvenlik kontrolü
        if not filename.endswith('.html') or '..' in filename or not os.path.exists(file_path):
            return jsonify({"error": "Geçersiz dosya"}), 400
            
        return send_file(file_path)
    
    except Exception as e:
        logger.error(f"Rapor görüntüleme hatası: {e}")
        return jsonify({"error": f"Rapor görüntülenirken hata oluştu: {str(e)}"}), 500

@app.route('/latest')
def show_latest_report():
    """En son raporu göster"""
    report_dir = "reports"
    if not os.path.exists(report_dir):
        return jsonify({"error": "Henüz rapor oluşturulmadı"}), 404
    
    try:
        files = sorted(
            [f for f in os.listdir(report_dir) if f.startswith("SS3_Report_") and f.endswith(".html")],
            reverse=True
        )
        
        if not files:
            return jsonify({"error": "Henüz rapor oluşturulmadı"}), 404
        
        latest_report = files[0]
        return send_file(os.path.join(report_dir, latest_report))
    
    except Exception as e:
        logger.error(f"Son rapor görüntüleme hatası: {e}")
        return jsonify({"error": f"Son rapor görüntülenirken hata oluştu: {str(e)}"}), 500

def main():
    """Ana fonksiyon - ASCII animasyonu ve başlangıç"""
    print("\033[H\033[J")  # Ekranı temizle
    print(WELCOME_ASCII)
    
    print("🚀 SS3 Intelligence Dashboard Başlatılıyor...")
    time.sleep(1)
    
    print("\n" + "="*50)
    print("🛡️  SİSTEM BİLGİLERİ")
    print("="*50)
    print(f"📍 Web Arayüzü: http://localhost:5000")
    print(f"📊 Raporlar: http://localhost:5000/reports")
    print(f"📄 Son Rapor: http://localhost:5000/latest")
    print(f"⏰ Başlangıç Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)
    
    print("\n🎯 Kullanım:")
    print("1. Web tarayıcınızda http://localhost:5000 adresini açın")
    print("2. Hedef domain veya IP adresini girin")
    print("3. 'Analiz Başlat' butonuna tıklayın")
    print("4. Sonuçları bekleyin ve raporları inceleyin")
    
    print("\n" + "⚡".center(50))
    print("Sistem hazır! Flask sunucusu başlatılıyor...")
    print("⚡".center(50))
    
    # Flask uygulamasını başlat
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)

if __name__ == '__main__':
    main()