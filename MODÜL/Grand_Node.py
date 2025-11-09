# Grand_Node.py
from datetime import datetime
from typing import Dict, Any, List, Tuple
import json
import hashlib
import uuid
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    LOW = "DÜŞÜK"
    MEDIUM = "ORTA"
    HIGH = "YÜKSEK"
    CRITICAL = "KRİTİK"

class ThreatCategory(Enum):
    NETWORK_SECURITY = "network_security"
    INFORMATION_EXPOSURE = "information_exposure"
    SOCIAL_ENGINEERING = "social_engineering"
    INFRASTRUCTURE = "infrastructure"
    DATA_LEAKAGE = "data_leakage"
    COMPLIANCE = "compliance"

@dataclass
class SecurityFinding:
    id: str
    category: str
    severity: RiskLevel
    title: str
    description: str
    evidence: List[str]
    impact: str
    recommendation: str
    confidence: float
    timestamp: datetime

class AdvancedGrandNode:
    def __init__(self):
        self.name = "AdvancedGrandNode"
        self.version = "3.0"
        self.analysis_results = {}
        self.session_id = str(uuid.uuid4())
        self.security_findings = []
        self.threat_intelligence = {}
        self.start_time = datetime.now()
        
    def print_log(self, message: str, level: str = "INFO"):
        """Gelişmiş log sistemi"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{self.name}] [{level}] {message}"
        print(log_entry)
        
    def calculate_hash(self, data: Any) -> str:
        """Veri hash hesaplama"""
        try:
            data_str = json.dumps(data, sort_keys=True, default=str)
            return hashlib.sha256(data_str.encode()).hexdigest()
        except Exception as e:
            self.print_log(f"Hash hesaplama hatası: {e}", "ERROR")
            return hashlib.sha256(str(data).encode()).hexdigest()
        
    def validate_analysis_data(self, analysis_data: Dict[str, Any]) -> bool:
        """Analiz verilerini doğrula - SS3 PIPELINE ENTEGRE"""
        if not analysis_data:
            self.print_log("Analiz verisi boş", "ERROR")
            return False
            
        # Temel modül kontrolleri - SS3 PIPELINE UYUMLU
        required_modules = ['sentinel', 'council', 'archivum']
        available_modules = []
        
        for module in required_modules:
            if module in analysis_data:
                module_data = analysis_data[module]
                if module_data and isinstance(module_data, dict) and len(module_data) > 0:
                    available_modules.append(module)
                else:
                    self.print_log(f"Modül verisi boş veya geçersiz: {module}", "WARNING")
            else:
                self.print_log(f"Modül eksik: {module}", "WARNING")
                
        # Ledger modülü opsiyonel ama kontrol et
        if 'ledger' not in analysis_data:
            self.print_log("Ledger modülü eksik - fallback moda geçilebilir", "INFO")
        
        self.print_log(f"Mevcut modüller: {available_modules}")
        return len(available_modules) >= 2  # En az 2 modül olmalı
        
    def safe_get(self, data: Any, keys: List[str], default: Any = None) -> Any:
        """Güvenli iç içe veri erişimi"""
        try:
            current = data
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            return current if current is not None else default
        except Exception:
            return default
        
    def create_executive_summary(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gelişmiş executive özet oluştur"""
        self.print_log("Gelişmiş executive summary oluşturuluyor...")
        
        if not self.validate_analysis_data(analysis_data):
            return self.create_fallback_summary(analysis_data)
        
        summary = {
            'session_id': self.session_id,
            'total_data_sources': len(analysis_data),
            'analysis_timestamp': datetime.now().isoformat(),
            'risk_score': 0.0,
            'risk_level': RiskLevel.LOW.value,
            'total_findings': 0,
            'critical_issues': 0,
            'high_risk_issues': 0,
            'medium_risk_issues': 0,
            'low_risk_issues': 0,
            'recommendation_count': 0,
            'data_quality_score': 0.0,
            'threat_indicator_count': 0,
            'attack_surface_score': 0.0,
            'compliance_score': 0.0,
            'processing_time': 0,
            'fallback_used': False
        }
        
        try:
            # Gelişmiş veri analizi
            total_weight = 0
            weighted_score = 0
            
            # Sentinel analizi
            if 'sentinel' in analysis_data:
                sentinel_data = analysis_data['sentinel']
                
                # DNS kayıt analizi
                dns_records = self.safe_get(sentinel_data, ['dns'], {})
                dns_findings = 0
                for record_type, records in dns_records.items():
                    if isinstance(records, list):
                        dns_findings += len(records)
                        summary['total_findings'] += len(records)
                
                # Subdomain analizi
                subdomains = self.safe_get(sentinel_data, ['subdomains', 'subdomains'], [])
                subdomain_count = len(subdomains)
                summary['total_findings'] += subdomain_count
                
                # SSL sertifika analizi
                ssl_info = self.safe_get(sentinel_data, ['ssl_certificate'], {})
                ssl_risk = 0.0
                days_until_expiry = self.safe_get(ssl_info, ['days_until_expiry'], 365)
                if days_until_expiry < 30:
                    ssl_risk = 0.8
                elif days_until_expiry < 90:
                    ssl_risk = 0.4
                    
                # Güvenlik başlıkları analizi
                security_headers = self.safe_get(sentinel_data, ['security_headers'], {})
                header_score = 0.0
                score_str = self.safe_get(security_headers, ['security_score'], '0/0')
                try:
                    current, total = score_str.split('/')
                    header_score = int(current) / int(total) if int(total) > 0 else 0.0
                except:
                    header_score = 0.0
                    
                # Sosyal medya analizi
                social_media = self.safe_get(sentinel_data, ['social_media'], {})
                social_media_count = 0
                if isinstance(social_media, dict):
                    social_media_count = sum(len(accounts) for accounts in social_media.values() if isinstance(accounts, list))
                summary['total_findings'] += social_media_count
                
                # Risk hesaplamaları
                weighted_score += dns_findings * 0.3
                weighted_score += subdomain_count * 0.2
                weighted_score += (1 - header_score) * 0.3
                weighted_score += ssl_risk * 0.2
                total_weight += 1.0
                
            # Council Mesh analizi
            if 'council' in analysis_data:
                council_data = analysis_data['council']
                graph_info = self.safe_get(council_data, ['graph_info'], {})
                total_nodes = self.safe_get(graph_info, ['graph_summary', 'total_nodes'], 0)
                summary['total_findings'] += total_nodes
                
                # Ağ merkezilik analizi
                centrality = self.safe_get(council_data, ['centrality'], {})
                if centrality.get('top_nodes'):
                    central_node_risk = min(0.7, len(centrality['top_nodes']) * 0.1)
                    weighted_score += central_node_risk * 0.4
                    total_weight += 0.4
                    
            # Ek veri kaynakları için analiz
            additional_sources = ['threat_intel', 'vulnerability_scan', 'compliance_check']
            for source in additional_sources:
                if source in analysis_data:
                    source_data = analysis_data[source]
                    source_risk = self.analyze_additional_source(source, source_data)
                    weighted_score += source_risk * 0.2
                    total_weight += 0.2
                    summary['total_findings'] += len(str(source_data)) // 100
            
            # Nihai risk skoru
            if total_weight > 0:
                summary['risk_score'] = min(1.0, weighted_score / total_weight)
            else:
                summary['risk_score'] = 0.1
                
            # Risk seviyesi belirleme
            if summary['risk_score'] >= 0.8:
                summary['risk_level'] = RiskLevel.CRITICAL.value
            elif summary['risk_score'] >= 0.6:
                summary['risk_level'] = RiskLevel.HIGH.value
            elif summary['risk_score'] >= 0.4:
                summary['risk_level'] = RiskLevel.MEDIUM.value
            else:
                summary['risk_level'] = RiskLevel.LOW.value
                
            # Detaylı bulgu sayıları
            summary['critical_issues'] = max(1, int(summary['total_findings'] * summary['risk_score'] * 0.3))
            summary['high_risk_issues'] = max(2, int(summary['total_findings'] * summary['risk_score'] * 0.4))
            summary['medium_risk_issues'] = max(3, int(summary['total_findings'] * summary['risk_score'] * 0.2))
            summary['low_risk_issues'] = max(1, summary['total_findings'] - 
                                           summary['critical_issues'] - 
                                           summary['high_risk_issues'] - 
                                           summary['medium_risk_issues'])
            
            summary['recommendation_count'] = max(5, summary['total_findings'] // 5)
            summary['data_quality_score'] = min(1.0, summary['total_data_sources'] * 0.2)
            summary['threat_indicator_count'] = summary['critical_issues'] + summary['high_risk_issues']
            summary['attack_surface_score'] = min(1.0, summary['total_findings'] * 0.01)
            summary['compliance_score'] = max(0.0, 1.0 - summary['risk_score'])
            summary['processing_time'] = (datetime.now() - self.start_time).total_seconds()
            
        except Exception as e:
            self.print_log(f"Executive summary oluşturma hatası: {e}", "ERROR")
            return self.create_fallback_summary(analysis_data)
        
        return summary
        
    def create_fallback_summary(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback summary oluştur"""
        self.print_log("Fallback summary oluşturuluyor...", "WARNING")
        
        # Temel veri analizi
        total_findings = 0
        try:
            # Sentinel verilerinden bulgular
            if 'sentinel' in analysis_data:
                sentinel_data = analysis_data['sentinel']
                
                # DNS kayıtları
                dns_data = self.safe_get(sentinel_data, ['dns'], {})
                for record_type, records in dns_data.items():
                    if isinstance(records, list):
                        total_findings += len(records)
                
                # Subdomainler
                subdomains = self.safe_get(sentinel_data, ['subdomains', 'subdomains'], [])
                total_findings += len(subdomains)
                
                # Sosyal medya hesapları
                social_media = self.safe_get(sentinel_data, ['social_media'], {})
                if isinstance(social_media, dict):
                    for platform, accounts in social_media.items():
                        if isinstance(accounts, list):
                            total_findings += len(accounts)
            
            # Council verilerinden bulgular
            if 'council' in analysis_data:
                council_data = analysis_data['council']
                graph_info = self.safe_get(council_data, ['graph_info'], {})
                if graph_info:
                    total_nodes = self.safe_get(graph_info, ['graph_summary', 'total_nodes'], 0)
                    total_findings += total_nodes
        except Exception as e:
            self.print_log(f"Fallback veri analiz hatası: {e}", "ERROR")
            total_findings = 10  # Varsayılan değer

        # Risk hesaplama
        if total_findings > 50:
            risk_level = RiskLevel.HIGH.value
            risk_score = 0.8
            critical_issues = total_findings // 4
            high_risk_issues = total_findings // 2
            low_risk_issues = total_findings - critical_issues - high_risk_issues
        elif total_findings > 20:
            risk_level = RiskLevel.MEDIUM.value
            risk_score = 0.5
            critical_issues = total_findings // 6
            high_risk_issues = total_findings // 3
            low_risk_issues = total_findings - critical_issues - high_risk_issues
        else:
            risk_level = RiskLevel.LOW.value
            risk_score = 0.2
            critical_issues = 0
            high_risk_issues = total_findings // 4
            low_risk_issues = total_findings - high_risk_issues
        
        return {
            'session_id': self.session_id,
            'total_data_sources': len(analysis_data),
            'analysis_timestamp': datetime.now().isoformat(),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'total_findings': total_findings,
            'critical_issues': critical_issues,
            'high_risk_issues': high_risk_issues,
            'medium_risk_issues': 0,
            'low_risk_issues': low_risk_issues,
            'recommendation_count': max(5, total_findings // 5),
            'data_quality_score': 0.5,
            'threat_indicator_count': critical_issues + high_risk_issues,
            'attack_surface_score': min(1.0, total_findings * 0.01),
            'compliance_score': max(0.0, 1.0 - risk_score),
            'processing_time': (datetime.now() - self.start_time).total_seconds(),
            'fallback_used': True
        }
        
    def analyze_additional_source(self, source: str, data: Any) -> float:
        """Ek veri kaynakları için risk analizi"""
        try:
            if source == 'threat_intel':
                return min(1.0, len(str(data)) * 0.001)
            elif source == 'vulnerability_scan':
                return min(1.0, len(str(data)) * 0.002)
            elif source == 'compliance_check':
                return min(1.0, len(str(data)) * 0.0015)
            return 0.1
        except Exception:
            return 0.1
        
    def comprehensive_risk_assessment(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gelişmiş kapsamlı risk değerlendirmesi"""
        self.print_log("Gelişmiş risk değerlendirmesi yapılıyor...")
        
        risk_categories = {
            'network_security': {
                'score': 0.0,
                'level': RiskLevel.LOW.value,
                'factors': [],
                'weight': 0.25,
                'subcategories': {
                    'dns_security': {'score': 0.0, 'factors': []},
                    'ssl_tls': {'score': 0.0, 'factors': []},
                    'security_headers': {'score': 0.0, 'factors': []},
                    'subdomain_risk': {'score': 0.0, 'factors': []}
                }
            },
            'information_exposure': {
                'score': 0.0,
                'level': RiskLevel.LOW.value,
                'factors': [],
                'weight': 0.20,
                'subcategories': {
                    'data_leakage': {'score': 0.0, 'factors': []},
                    'config_exposure': {'score': 0.0, 'factors': []},
                    'sensitive_info': {'score': 0.0, 'factors': []}
                }
            },
            'social_engineering': {
                'score': 0.0,
                'level': RiskLevel.LOW.value,
                'factors': [],
                'weight': 0.15,
                'subcategories': {
                    'social_media_presence': {'score': 0.0, 'factors': []},
                    'employee_exposure': {'score': 0.0, 'factors': []},
                    'brand_impersonation': {'score': 0.0, 'factors': []}
                }
            },
            'infrastructure': {
                'score': 0.0,
                'level': RiskLevel.LOW.value,
                'factors': [],
                'weight': 0.20,
                'subcategories': {
                    'service_discovery': {'score': 0.0, 'factors': []},
                    'port_exposure': {'score': 0.0, 'factors': []},
                    'technology_stack': {'score': 0.0, 'factors': []}
                }
            },
            'data_leakage': {
                'score': 0.0,
                'level': RiskLevel.LOW.value,
                'factors': [],
                'weight': 0.10,
                'subcategories': {
                    'cloud_misconfig': {'score': 0.0, 'factors': []},
                    'api_exposure': {'score': 0.0, 'factors': []},
                    'credential_leak': {'score': 0.0, 'factors': []}
                }
            },
            'compliance': {
                'score': 0.0,
                'level': RiskLevel.LOW.value,
                'factors': [],
                'weight': 0.10,
                'subcategories': {
                    'privacy_violation': {'score': 0.0, 'factors': []},
                    'regulatory_issues': {'score': 0.0, 'factors': []},
                    'audit_failures': {'score': 0.0, 'factors': []}
                }
            }
        }
        
        try:
            # Gelişmiş Sentinel analizi
            if 'sentinel' in analysis_data:
                sentinel_data = analysis_data['sentinel']
                
                # DNS güvenlik analizi
                dns_records = self.safe_get(sentinel_data, ['dns'], {})
                if not dns_records.get('DMARC'):
                    risk_categories['network_security']['subcategories']['dns_security']['factors'].append(
                        'DMARC kaydı eksik - Email spoofing saldırılarına açık')
                    risk_categories['network_security']['subcategories']['dns_security']['score'] += 0.3
                    
                if not dns_records.get('SPF'):
                    risk_categories['network_security']['subcategories']['dns_security']['factors'].append(
                        'SPF kaydı eksik - Email sahteciliği riski')
                    risk_categories['network_security']['subcategories']['dns_security']['score'] += 0.2
                    
                if not dns_records.get('DKIM'):
                    risk_categories['network_security']['subcategories']['dns_security']['factors'].append(
                        'DKIM kaydı eksik - Email doğrulama zayıflığı')
                    risk_categories['network_security']['subcategories']['dns_security']['score'] += 0.2
                    
                # SSL/TLS analizi
                ssl_info = self.safe_get(sentinel_data, ['ssl_certificate'], {})
                days_until_expiry = self.safe_get(ssl_info, ['days_until_expiry'], 0)
                if days_until_expiry < 7:
                    risk_categories['network_security']['subcategories']['ssl_tls']['factors'].append(
                        f'SSL sertifikası {days_until_expiry} gün içinde sona erecek - Kritik risk')
                    risk_categories['network_security']['subcategories']['ssl_tls']['score'] += 0.8
                elif days_until_expiry < 30:
                    risk_categories['network_security']['subcategories']['ssl_tls']['factors'].append(
                        f'SSL sertifikası {days_until_expiry} gün içinde sona erecek - Yüksek risk')
                    risk_categories['network_security']['subcategories']['ssl_tls']['score'] += 0.5
                    
                # Güvenlik başlıkları analizi
                security_headers = self.safe_get(sentinel_data, ['security_headers'], {})
                missing_headers = self.safe_get(security_headers, ['missing_headers'], [])
                for header in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options']:
                    if header in missing_headers:
                        risk_categories['network_security']['subcategories']['security_headers']['factors'].append(
                            f'{header} başlığı eksik - Güvenlik zafiyeti')
                        risk_categories['network_security']['subcategories']['security_headers']['score'] += 0.2
                        
                # Subdomain risk analizi
                subdomains = self.safe_get(sentinel_data, ['subdomains', 'subdomains'], [])
                if len(subdomains) > 50:
                    risk_categories['network_security']['subcategories']['subdomain_risk']['factors'].append(
                        f'{len(subdomains)} subdomain tespit edildi - Geniş saldırı yüzeyi')
                    risk_categories['network_security']['subcategories']['subdomain_risk']['score'] += 0.4
                elif len(subdomains) > 20:
                    risk_categories['network_security']['subcategories']['subdomain_risk']['factors'].append(
                        f'{len(subdomains)} subdomain tespit edildi - Orta seviye saldırı yüzeyi')
                    risk_categories['network_security']['subcategories']['subdomain_risk']['score'] += 0.2
                    
                # Sosyal medya risk analizi
                social_media = self.safe_get(sentinel_data, ['social_media'], {})
                total_social_media = 0
                if isinstance(social_media, dict):
                    total_social_media = sum(len(accounts) for accounts in social_media.values() if isinstance(accounts, list))
                if total_social_media > 10:
                    risk_categories['social_engineering']['subcategories']['social_media_presence']['factors'].append(
                        f'{total_social_media} sosyal medya hesabı - Sosyal mühendislik riski yüksek')
                    risk_categories['social_engineering']['subcategories']['social_media_presence']['score'] += 0.4
                elif total_social_media > 5:
                    risk_categories['social_engineering']['subcategories']['social_media_presence']['factors'].append(
                        f'{total_social_media} sosyal medya hesabı - Orta seviye sosyal mühendislik riski')
                    risk_categories['social_engineering']['subcategories']['social_media_presence']['score'] += 0.2
                    
            # Council Mesh ağ analizi
            if 'council' in analysis_data:
                council_data = analysis_data['council']
                centrality = self.safe_get(council_data, ['centrality'], {})
                
                # Merkezi düğüm analizi
                if centrality.get('top_nodes'):
                    top_nodes_count = len(centrality['top_nodes'])
                    risk_categories['infrastructure']['subcategories']['service_discovery']['factors'].append(
                        f'{top_nodes_count} merkezi düğüm tespit edildi - Hedef saldırı riski')
                    risk_categories['infrastructure']['subcategories']['service_discovery']['score'] += min(0.6, top_nodes_count * 0.1)
                    
        except Exception as e:
            self.print_log(f"Risk değerlendirme hatası: {e}", "ERROR")
            # Hata durumunda minimum risk değerleri döndür
            for category in risk_categories.values():
                category['score'] = 0.1
                category['level'] = RiskLevel.LOW.value

        # Ana kategori skorlarını hesapla
        for category_name, category_data in risk_categories.items():
            try:
                total_sub_score = 0.0
                subcategory_count = len(category_data['subcategories'])
                
                for subcategory_name, subcategory_data in category_data['subcategories'].items():
                    total_sub_score += subcategory_data['score']
                    # Alt kategori faktörlerini ana kategoriye taşı
                    category_data['factors'].extend(subcategory_data['factors'])
                    
                if subcategory_count > 0:
                    category_data['score'] = min(1.0, total_sub_score / subcategory_count)
                else:
                    category_data['score'] = 0.0
                    
                # Risk seviyesini belirle
                score = category_data['score']
                if score > 0.8:
                    category_data['level'] = RiskLevel.CRITICAL.value
                elif score > 0.6:
                    category_data['level'] = RiskLevel.HIGH.value
                elif score > 0.4:
                    category_data['level'] = RiskLevel.MEDIUM.value
                else:
                    category_data['level'] = RiskLevel.LOW.value
            except Exception as e:
                self.print_log(f"Kategori skor hesaplama hatası ({category_name}): {e}", "ERROR")
                category_data['score'] = 0.1
                category_data['level'] = RiskLevel.LOW.value
                
        return risk_categories
        
    def generate_recommendations(self, analysis_data: Dict[str, Any], risk_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Gelişmiş öneri sistemi"""
        self.print_log("Gelişmiş öneriler oluşturuluyor...")
        
        recommendations = []
        priority_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        try:
            # DNS güvenliği önerileri
            dns_risk = risk_assessment['network_security']['subcategories']['dns_security']['score']
            if dns_risk > 0.3:
                recommendations.append({
                    'id': str(uuid.uuid4()),
                    'category': 'DNS Security',
                    'priority': 'HIGH' if dns_risk > 0.6 else 'MEDIUM',
                    'description': 'Eksik DNS güvenlik kayıtları tespit edildi',
                    'action': 'DMARC, SPF ve DKIM kayıtlarını acilen yapılandır',
                    'impact': 'Email spoofing ve phishing saldırılarını önler',
                    'effort': 'LOW',
                    'timeline': '1-2 gün',
                    'category_weight': priority_weights['HIGH' if dns_risk > 0.6 else 'MEDIUM']
                })
                
            # SSL/TLS önerileri
            ssl_risk = risk_assessment['network_security']['subcategories']['ssl_tls']['score']
            if ssl_risk > 0.3:
                recommendations.append({
                    'id': str(uuid.uuid4()),
                    'category': 'SSL/TLS Security',
                    'priority': 'CRITICAL' if ssl_risk > 0.7 else 'HIGH',
                    'description': 'SSL sertifika sorunları tespit edildi',
                    'action': 'SSL sertifikasını yenile ve otomatik yenileme ayarla',
                    'impact': 'Man-in-the-middle saldırılarını önler, güven iletişimi sağlar',
                    'effort': 'MEDIUM',
                    'timeline': '3-5 gün',
                    'category_weight': priority_weights['CRITICAL' if ssl_risk > 0.7 else 'HIGH']
                })
                
            # Güvenlik başlıkları önerileri
            headers_risk = risk_assessment['network_security']['subcategories']['security_headers']['score']
            if headers_risk > 0.2:
                recommendations.append({
                    'id': str(uuid.uuid4()),
                    'category': 'Web Security Headers',
                    'priority': 'HIGH' if headers_risk > 0.5 else 'MEDIUM',
                    'description': 'Eksik güvenlik başlıkları tespit edildi',
                    'action': 'Content-Security-Policy, HSTS, X-Frame-Options başlıklarını ekle',
                    'impact': 'XSS, clickjacking ve diğer web saldırılarını önler',
                    'effort': 'LOW',
                    'timeline': '2-3 gün',
                    'category_weight': priority_weights['HIGH' if headers_risk > 0.5 else 'MEDIUM']
                })
                
            # Subdomain yönetimi önerileri
            subdomain_risk = risk_assessment['network_security']['subcategories']['subdomain_risk']['score']
            if subdomain_risk > 0.3:
                recommendations.append({
                    'id': str(uuid.uuid4()),
                    'category': 'Attack Surface Management',
                    'priority': 'MEDIUM',
                    'description': 'Geniş subdomain yapısı saldırı yüzeyini artırıyor',
                    'action': 'Kullanılmayan subdomainleri kapat, wildcard DNS kaydı kullanma',
                    'impact': 'Saldırı yüzeyini daraltır, güvenlik duruşunu iyileştirir',
                    'effort': 'MEDIUM',
                    'timeline': '1-2 hafta',
                    'category_weight': priority_weights['MEDIUM']
                })
                
            # Sosyal medya güvenliği önerileri
            social_risk = risk_assessment['social_engineering']['subcategories']['social_media_presence']['score']
            if social_risk > 0.3:
                recommendations.append({
                    'id': str(uuid.uuid4()),
                    'category': 'Social Media Security',
                    'priority': 'MEDIUM',
                    'description': 'Sosyal medya varlığı sosyal mühendislik riski oluşturuyor',
                    'action': 'Marka taklitlerine karşı doğrulanmış hesap oluştur',
                    'impact': 'Sosyal mühendislik saldırılarını azaltır, marka itibarını korur',
                    'effort': 'LOW',
                    'timeline': '1 hafta',
                    'category_weight': priority_weights['MEDIUM']
                })
                
            # Ağ güvenliği önerileri
            infrastructure_risk = risk_assessment['infrastructure']['score']
            if infrastructure_risk > 0.4:
                recommendations.append({
                    'id': str(uuid.uuid4()),
                    'category': 'Network Infrastructure',
                    'priority': 'HIGH' if infrastructure_risk > 0.6 else 'MEDIUM',
                    'description': 'Ağ altyapısında güvenlik riskleri tespit edildi',
                    'action': 'Ağ segmentasyonu uygula, merkezi düğümleri koru',
                    'impact': 'Yatay hareket saldırılarını önler, ağ güvenliğini artırır',
                    'effort': 'HIGH',
                    'timeline': '2-4 hafta',
                    'category_weight': priority_weights['HIGH' if infrastructure_risk > 0.6 else 'MEDIUM']
                })
                
            # Kritik port kontrolleri
            if 'port_scan' in analysis_data:
                port_data = analysis_data['port_scan']
                open_ports = self.safe_get(port_data, ['open_ports'], [])
                critical_ports = [22, 445, 3389]
                open_critical_ports = [port for port in open_ports if port in critical_ports]
                
                if open_critical_ports:
                    recommendations.append({
                        'id': str(uuid.uuid4()),
                        'category': 'Network Security',
                        'priority': 'CRITICAL',
                        'description': f'Kritik portlar açık: {open_critical_ports}',
                        'action': 'Bu portları kapat ve yalnızca VPN erişimine izin ver',
                        'impact': 'Doğrudan saldırı vektörlerini kapatır',
                        'effort': 'MEDIUM',
                        'timeline': '1-2 gün',
                        'category_weight': priority_weights['CRITICAL']
                    })
                    
            # DMARC politikası önerisi
            if 'sentinel' in analysis_data:
                sentinel_data = analysis_data['sentinel']
                dns_records = self.safe_get(sentinel_data, ['dns'], {})
                if not dns_records.get('DMARC'):
                    recommendations.append({
                        'id': str(uuid.uuid4()),
                        'category': 'Email Security',
                        'priority': 'HIGH',
                        'description': 'DMARC kaydı eksik',
                        'action': 'DMARC politikası oluştur: v=DMARC1; p=reject; rua=mailto:security@domain.com',
                        'impact': 'Email spoofing ve phishing saldırılarını engeller',
                        'effort': 'LOW',
                        'timeline': '1 gün',
                        'category_weight': priority_weights['HIGH']
                    })
                    
            # Whois bilgi sızıntısı kontrolü
            if 'whois' in analysis_data:
                whois_data = analysis_data['whois']
                if isinstance(whois_data, dict) and any(key in whois_data for key in ['registrant_email', 'registrant_name', 'registrant_phone']):
                    recommendations.append({
                        'id': str(uuid.uuid4()),
                        'category': 'Information Protection',
                        'priority': 'MEDIUM',
                        'description': 'Whois kayıtlarında hassas bilgiler tespit edildi',
                        'action': 'Gizli alan bilgilerini kaldır, Whois anonimleştirme aktif et',
                        'impact': 'Hedef bilgi toplamayı zorlaştırır',
                        'effort': 'LOW',
                        'timeline': '1 hafta',
                        'category_weight': priority_weights['MEDIUM']
                    })
                    
            # Yüksek risk durumunda WAF önerisi
            executive_summary = self.create_executive_summary(analysis_data)
            if executive_summary['risk_level'] in [RiskLevel.CRITICAL.value, RiskLevel.HIGH.value]:
                recommendations.append({
                    'id': str(uuid.uuid4()),
                    'category': 'Web Application Security',
                    'priority': 'CRITICAL',
                    'description': 'Yüksek risk seviyesi tespit edildi',
                    'action': 'Web Application Firewall (WAF) aktif et ve IP rate limit uygula',
                    'impact': 'Uygulama katmanı saldırılarını engeller',
                    'effort': 'HIGH',
                    'timeline': '1-2 hafta',
                    'category_weight': priority_weights['CRITICAL']
                })
                
        except Exception as e:
            self.print_log(f"Öneri oluşturma hatası: {e}", "ERROR")
            # Hata durumunda genel öneriler ekle
            recommendations = []

        # Genel güvenlik önerileri (her zaman)
        try:
            general_recommendations = [
                {
                    'id': str(uuid.uuid4()),
                    'category': 'Security Monitoring',
                    'priority': 'MEDIUM',
                    'description': 'Sürekli güvenlik izleme eksikliği',
                    'action': 'SIEM sistemi kur ve güvenlik olaylarını merkezi olarak izle',
                    'impact': 'Gerçek zamanlı tehdit tespiti ve hızlı müdahale sağlar',
                    'effort': 'HIGH',
                    'timeline': '4-6 hafta',
                    'category_weight': priority_weights['MEDIUM']
                },
                {
                    'id': str(uuid.uuid4()),
                    'category': 'Vulnerability Management',
                    'priority': 'MEDIUM',
                    'description': 'Zafiyet yönetimi programı eksikliği',
                    'action': 'Düzenli güvenlik taramaları ve zafiyet yönetimi süreci oluştur',
                    'impact': 'Bilinen zafiyetleri proaktif olarak düzeltir',
                    'effort': 'MEDIUM',
                    'timeline': '2-3 hafta',
                    'category_weight': priority_weights['MEDIUM']
                }
            ]
            
            recommendations.extend(general_recommendations)
            
            # Önceliğe göre sırala
            recommendations.sort(key=lambda x: (x['category_weight'], x['priority']), reverse=True)
            
        except Exception as e:
            self.print_log(f"Genel öneri ekleme hatası: {e}", "ERROR")

        return recommendations[:15]  # En önemli 15 öneriyi döndür
        
    def create_security_findings(self, analysis_data: Dict[str, Any], risk_assessment: Dict[str, Any]) -> List[SecurityFinding]:
        """Güvenlik bulguları oluştur"""
        findings = []
        
        try:
            # DNS güvenlik bulguları
            if risk_assessment['network_security']['subcategories']['dns_security']['score'] > 0.3:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    category="DNS Security",
                    severity=RiskLevel.HIGH,
                    title="Eksik DNS Güvenlik Kayıtları",
                    description="DMARC, SPF veya DKIM kayıtları eksik veya yanlış yapılandırılmış",
                    evidence=["Email spoofing saldırılarına açık", "Phishing riski yüksek"],
                    impact="Marka itibar zedelenmesi, finansal kayıp",
                    recommendation="DMARC, SPF ve DKIM kayıtlarını acilen yapılandır",
                    confidence=0.85,
                    timestamp=datetime.now()
                ))
                
            # SSL/TLS bulguları
            if risk_assessment['network_security']['subcategories']['ssl_tls']['score'] > 0.3:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    category="SSL/TLS",
                    severity=RiskLevel.CRITICAL,
                    title="SSL Sertifika Sorunları",
                    description="SSL sertifikası süresi dolmak üzere veya geçersiz",
                    evidence=["Man-in-the-middle saldırı riski", "Güven iletişimi zafiyeti"],
                    impact="Veri gizliliği ihlali, güven kaybı",
                    recommendation="SSL sertifikasını yenile ve otomatik yenileme ayarla",
                    confidence=0.95,
                    timestamp=datetime.now()
                ))
                
            # Güvenlik başlıkları bulguları
            if risk_assessment['network_security']['subcategories']['security_headers']['score'] > 0.2:
                findings.append(SecurityFinding(
                    id=str(uuid.uuid4()),
                    category="Web Security",
                    severity=RiskLevel.MEDIUM,
                    title="Eksik Güvenlik Başlıkları",
                    description="Temel güvenlik başlıkları eksik veya yanlış yapılandırılmış",
                    evidence=["XSS saldırılarına açık", "Clickjacking riski"],
                    impact="Web uygulama güvenlik zafiyetleri",
                    recommendation="Content-Security-Policy, HSTS, X-Frame-Options başlıklarını ekle",
                    confidence=0.75,
                    timestamp=datetime.now()
                ))
                
            # Kritik port bulguları
            if 'port_scan' in analysis_data:
                port_data = analysis_data['port_scan']
                open_ports = self.safe_get(port_data, ['open_ports'], [])
                critical_ports = [22, 445, 3389]
                open_critical_ports = [port for port in open_ports if port in critical_ports]
                
                if open_critical_ports:
                    findings.append(SecurityFinding(
                        id=str(uuid.uuid4()),
                        category="Network Security",
                        severity=RiskLevel.CRITICAL,
                        title="Kritik Portlar Açık",
                        description=f"Kritik güvenlik portları açık: {open_critical_ports}",
                        evidence=["Doğrudan saldırı vektörü", "Brute-force saldırı riski"],
                        impact="Sistem ele geçirme, veri sızıntısı",
                        recommendation="Bu portları kapat ve yalnızca VPN erişimine izin ver",
                        confidence=0.90,
                        timestamp=datetime.now()
                    ))
                    
        except Exception as e:
            self.print_log(f"Güvenlik bulguları oluşturma hatası: {e}", "ERROR")
                
        return findings
        
    def create_raw_data_summary(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gelişmiş ham veri özeti"""
        summary = {}
        total_data_size = 0
        
        try:
            for module, data in analysis_data.items():
                try:
                    data_str = json.dumps(data, default=str)
                    data_size = len(data_str.encode('utf-8'))
                    total_data_size += data_size
                    
                    summary[module] = {
                        'data_points': len(data_str),
                        'data_size_bytes': data_size,
                        'data_hash': self.calculate_hash(data),
                        'timestamp': datetime.now().isoformat(),
                        'has_data': bool(data),
                        'data_quality': 'HIGH' if data_size > 1000 else 'MEDIUM' if data_size > 100 else 'LOW'
                    }
                except Exception as e:
                    self.print_log(f"Modül veri özeti hatası ({module}): {e}", "ERROR")
                    summary[module] = {
                        'data_points': 0,
                        'data_size_bytes': 0,
                        'data_hash': 'error',
                        'timestamp': datetime.now().isoformat(),
                        'has_data': False,
                        'data_quality': 'LOW'
                    }
                    
            summary['_metadata'] = {
                'total_modules': len(analysis_data),
                'total_data_size_bytes': total_data_size,
                'average_data_quality': self.calculate_average_data_quality(summary),
                'analysis_complete': True
            }
        except Exception as e:
            self.print_log(f"Ham veri özeti oluşturma hatası: {e}", "ERROR")
            summary['_metadata'] = {
                'total_modules': 0,
                'total_data_size_bytes': 0,
                'average_data_quality': 'LOW',
                'analysis_complete': False,
                'error': str(e)
            }
                
        return summary
        
    def calculate_average_data_quality(self, summary: Dict[str, Any]) -> str:
        """Ortalama veri kalitesini hesapla"""
        try:
            quality_scores = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
            total_score = 0
            count = 0
            
            for module, data in summary.items():
                if module != '_metadata':
                    total_score += quality_scores.get(data['data_quality'], 1)
                    count += 1
                    
            if count == 0:
                return 'LOW'
                
            average_score = total_score / count
            if average_score >= 2.5:
                return 'HIGH'
            elif average_score >= 1.5:
                return 'MEDIUM'
            else:
                return 'LOW'
        except Exception:
            return 'LOW'
        
    def run(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gelişmiş ana çalıştırma metodu"""
        self.print_log("Gelişmiş Grand Node analizi başlatıldı")
        self.start_time = datetime.now()
        
        try:
            # Executive Dashboard oluştur
            executive_summary = self.create_executive_summary(analysis_data)
            
            # Risk değerlendirmesi
            risk_assessment = self.comprehensive_risk_assessment(analysis_data)
            
            # Öneriler oluştur
            recommendations = self.generate_recommendations(analysis_data, risk_assessment)
            
            # Güvenlik bulguları oluştur
            security_findings = self.create_security_findings(analysis_data, risk_assessment)
            
            # Dashboard verisini birleştir
            dashboard = {
                'executive_summary': executive_summary,
                'risk_assessment': risk_assessment,
                'recommendations': recommendations,
                'security_findings': [finding.__dict__ for finding in security_findings],
                'analysis_timestamp': datetime.now().isoformat(),
                'data_sources': list(analysis_data.keys()),
                'session_metadata': {
                    'session_id': self.session_id,
                    'analysis_version': self.version,
                    'processing_time_ms': (datetime.now() - self.start_time).total_seconds() * 1000,
                    'total_operations': len(analysis_data) * 4
                }
            }
            
            self.analysis_results = {
                'executive_dashboard': dashboard,
                'raw_data_summary': self.create_raw_data_summary(analysis_data),
                'threat_intelligence': self.threat_intelligence
            }
            
            self.print_log("Grand Node analizi başarıyla tamamlandı")
            return self.analysis_results
            
        except Exception as e:
            self.print_log(f"Grand Node analiz hatası: {str(e)}", "ERROR")
            import traceback
            self.print_log(f"Traceback: {traceback.format_exc()}", "ERROR")
            
            # Hata durumunda fallback dashboard oluştur
            fallback_summary = self.create_fallback_summary(analysis_data)
            
            dashboard = {
                'executive_summary': fallback_summary,
                'risk_assessment': {},
                'recommendations': [],
                'security_findings': [],
                'analysis_timestamp': datetime.now().isoformat(),
                'data_sources': list(analysis_data.keys()) if analysis_data else [],
                'session_metadata': {
                    'session_id': self.session_id,
                    'analysis_version': self.version,
                    'processing_time_ms': (datetime.now() - self.start_time).total_seconds() * 1000,
                    'total_operations': 0,
                    'error_occurred': True,
                    'error_message': str(e)
                }
            }
            
            return {
                'executive_dashboard': dashboard,
                'raw_data_summary': self.create_raw_data_summary(analysis_data),
                'threat_intelligence': self.threat_intelligence,
                'error': str(e)
            }
        
    def report(self) -> str:
        """Gelişmiş detaylı rapor oluştur"""
        if not self.analysis_results:
            return "Henüz Grand Node analizi yapılmadı"
            
        try:
            executive = self.analysis_results['executive_dashboard']['executive_summary']
            risk_assessment = self.analysis_results['executive_dashboard']['risk_assessment']
            recommendations = self.analysis_results['executive_dashboard']['recommendations']
            security_findings = self.analysis_results['executive_dashboard'].get('security_findings', [])
            
            report = f"""
GELİŞMİŞ GRAND NODE GÜVENLİK RAPORU v{self.version}
==================================================
ANALİZ METADATASI
-----------------
Oturum ID: {executive['session_id']}
Analiz Tarihi: {executive['analysis_timestamp']}
Veri Kaynağı Sayısı: {executive['total_data_sources']}
Toplam Bulgu: {executive['total_findings']}
İşlem Süresi: {executive.get('processing_time', 0):.2f}s
{'⚠️  FALLBACK MOD KULLANILDI' if executive.get('fallback_used') else '✅ NORMAL MOD'}

EXECUTIVE SUMMARY
-----------------
Genel Risk Seviyesi: {executive['risk_level']}
Risk Skoru: {executive['risk_score']:.2f}
Kritik Sorunlar: {executive['critical_issues']}
Yüksek Riskli Sorunlar: {executive['high_risk_issues']}
Orta Riskli Sorunlar: {executive['medium_risk_issues']}
Düşük Riskli Sorunlar: {executive['low_risk_issues']}
Öneri Sayısı: {executive['recommendation_count']}
Saldırı Yüzeyi Skoru: {executive['attack_surface_score']:.2f}
Uyumluluk Skoru: {executive['compliance_score']:.2f}

DETAYLI RİSK DEĞERLENDİRMESİ
-----------------------------
"""
            for category, assessment in risk_assessment.items():
                report += f"\n{category.upper()}:\n"
                report += f"  Risk Seviyesi: {assessment['level']}\n"
                report += f"  Risk Skoru: {assessment['score']:.2f}\n"
                report += f"  Ağırlık: {assessment['weight']}\n"
                
                if assessment['factors']:
                    report += "  Risk Faktörleri:\n"
                    for factor in assessment['factors'][:5]:
                        report += f"    * {factor}\n"
                        
                for subcategory_name, subcategory_data in assessment['subcategories'].items():
                    if subcategory_data['score'] > 0.1:
                        report += f"  - {subcategory_name}: {subcategory_data['score']:.2f}\n"
                        for factor in subcategory_data['factors'][:2]:
                            report += f"      > {factor}\n"
                    
            report += "\nGÜVENLİK BULGULARI\n-----------------\n"
            for i, finding in enumerate(security_findings, 1):
                report += f"{i}. [{finding['severity']}] {finding['title']}\n"
                report += f"   Kategori: {finding['category']}\n"
                report += f"   Açıklama: {finding['description']}\n"
                report += f"   Etki: {finding['impact']}\n"
                report += f"   Güven Skoru: {finding['confidence']:.2f}\n"
                report += f"   Öneri: {finding['recommendation']}\n\n"
                    
            report += "\n🚧 ÖNERİLEN GÜVENLİK ÖNLEMLERİ\n-----------------------------\n"
            for i, rec in enumerate(recommendations, 1):
                report += f"{i}. [{rec['priority']}] {rec['category']}\n"
                report += f"   Açıklama: {rec['description']}\n"
                report += f"   Eylem: {rec['action']}\n"
                report += f"   Etki: {rec['impact']}\n"
                report += f"   Çaba: {rec['effort']} | Zaman: {rec['timeline']}\n\n"
                
            report += f"""
RAPOR METRİKLERİ
----------------
Toplam Veri Boyutu: {self.analysis_results['raw_data_summary']['_metadata']['total_data_size_bytes']} bayt
Ortalama Veri Kalitesi: {self.analysis_results['raw_data_summary']['_metadata']['average_data_quality']}
Analiz Modülü Sayısı: {self.analysis_results['raw_data_summary']['_metadata']['total_modules']}

---
Rapor Sonu - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Gelişmiş Grand Node Sistemi - Profesyonel Güvenlik Analizi
"""
                
            return report
        except Exception as e:
            return f"Rapor oluşturma hatası: {str(e)}"

# Legacy uyumluluk için orijinal sınıf
class GrandNode(AdvancedGrandNode):
    def __init__(self):
        super().__init__()
        self.name = "GrandNode"
        self.version = "2.0"

# Hızlı başlatma fonksiyonu
def create_grand_node() -> AdvancedGrandNode:
    """Grand Node örneği oluştur"""
    return AdvancedGrandNode()