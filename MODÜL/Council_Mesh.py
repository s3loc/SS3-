# Council_Mesh.py
import networkx as nx
import matplotlib.pyplot as plt
import json
from collections import defaultdict, Counter
import community.community_louvain as community_louvain

import numpy as np
from typing import Dict, List, Any, Optional, Tuple
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import seaborn as sns
import warnings
from datetime import datetime
import hashlib
import itertools
from scipy import stats
import plotly.figure_factory as ff
import matplotlib.cm as cm
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

warnings.filterwarnings('ignore')

class CouncilMesh:
    def __init__(self):
        self.name = "CouncilMesh"
        self.version = "3.0"
        self.graph = nx.Graph()
        self.analysis_results = {}
        self.visualization_data = {}
        self.security_level = "ELITE_RED"
        self.encryption_key = hashlib.sha256(b"REDHACK_ELITE_PROTECTION").hexdigest()
        self.performance_optimized = True
        self.advanced_metrics_enabled = True
        
    def print_log(self, message: str, level: str = "INFO"):
        """Geliştirilmiş güvenlik log sistemi"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        level_icons = {
            "INFO": "ℹ️",
            "WARNING": "⚠️", 
            "ERROR": "❌",
            "SUCCESS": "✅",
            "SECURITY": "🔒",
            "ANALYSIS": "🔍"
        }
        icon = level_icons.get(level, "🔹")
        print(f"[{timestamp}] [{self.name} v{self.version}] [{icon} {level}] {message}")
        
    def security_validation(self, data: Any) -> bool:
        """Gelişmiş güvenlik validasyonu"""
        try:
            if data is None:
                return False
                
            # Injection koruması
            dangerous_patterns = ["__class__", "__base__", "__subclasses__", "eval(", "exec(", "compile("]
            data_str = str(data).lower()
            
            for pattern in dangerous_patterns:
                if pattern in data_str:
                    self.print_log(f"Güvenlik ihlali tespit edildi: {pattern}", "SECURITY")
                    return False
                    
            # Boyut sınırlaması
            if len(str(data)) > 1000000:  # 1MB sınırı
                self.print_log("Veri boyutu sınırı aşıldı", "SECURITY")
                return False
                
            return True
        except Exception as e:
            self.print_log(f"Güvenlik validasyon hatası: {e}", "ERROR")
            return False

    def build_comprehensive_network_graph(self, osint_data: Dict[str, Any]) -> nx.Graph:
        """Gelişmiş kapsamlı ağ grafı oluşturma"""
        self.print_log("Gelişmiş ağ grafı oluşturuluyor...", "ANALYSIS")
        
        if not self.security_validation(osint_data):
            self.print_log("OSINT verisi güvenlik validasyonundan geçemedi", "ERROR")
            return self.graph

        # DNS kayıtlarından ilişkiler
        dns_records = osint_data.get('dns', {})
        domain = osint_data.get('domain', '')
        
        if not domain:
            self.print_log("Domain bilgisi bulunamadı", "WARNING")
            return self.graph

        # Ana domain düğümü - gelişmiş özellikler
        self.graph.add_node(domain, 
                          type='domain', 
                          size=300,
                          color='red',
                          importance=1.0,
                          security_level="HIGH",
                          creation_time=datetime.now().isoformat(),
                          node_id=hashlib.md5(domain.encode()).hexdigest())

        # IP adreslerini ekle - gelişmiş analiz
        ip_info = osint_data.get('ip_info', {})
        if ip_info.get('ip'):
            ip_node = ip_info['ip']
            geolocation = ip_info.get('geolocation', {})
            
            # IP risk analizi
            risk_score = self.calculate_ip_risk_score(ip_info)
            
            self.graph.add_node(ip_node, 
                              type='ip', 
                              size=200,
                              color='blue' if risk_score < 0.5 else 'darkred',
                              importance=0.8,
                              geolocation=geolocation,
                              risk_score=risk_score,
                              asn=ip_info.get('asn'),
                              organization=ip_info.get('org'),
                              node_id=hashlib.md5(ip_node.encode()).hexdigest())
            
            self.graph.add_edge(domain, ip_node, 
                              relationship='resolves_to',
                              weight=0.9,
                              label='IP Resolution',
                              security_level="MEDIUM",
                              edge_id=f"{domain}_{ip_node}_resolve")

        # Subdomainleri ekle - gelişmiş tespit
        subdomains_data = osint_data.get('subdomains', {})
        subdomains_list = subdomains_data.get('subdomains', [])
        
        if isinstance(subdomains_list, list):
            for subdomain_info in subdomains_list:
                subdomain = subdomain_info.get('subdomain', '')
                if subdomain and self.security_validation(subdomain):
                    # Subdomain risk analizi
                    subdomain_risk = self.analyze_subdomain_risk(subdomain, subdomain_info)
                    
                    self.graph.add_node(subdomain, 
                                      type='subdomain', 
                                      size=150,
                                      color='green' if subdomain_risk < 0.3 else 'orange',
                                      importance=0.6,
                                      ip=subdomain_info.get('ip'),
                                      ports=subdomain_info.get('open_ports', []),
                                      risk_score=subdomain_risk,
                                      technologies=subdomain_info.get('technologies', []),
                                      node_id=hashlib.md5(subdomain.encode()).hexdigest())
                    
                    self.graph.add_edge(domain, subdomain, 
                                      relationship='subdomain_of',
                                      weight=0.7,
                                      label='Subdomain',
                                      security_level="LOW",
                                      edge_id=f"{domain}_{subdomain}_subdomain")

        # DNS kayıt ilişkileri - gelişmiş analiz
        for record_type, records in dns_records.items():
            if isinstance(records, list):
                for record in records[:15]:  # İlk 15 kayıt
                    if record and len(str(record)) < 100 and self.security_validation(record):
                        record_node = f"{record_type}:{record[:50]}"
                        dns_risk = self.analyze_dns_record_risk(record_type, record)
                        
                        self.graph.add_node(record_node, 
                                          type=f'dns_{record_type}', 
                                          size=100,
                                          color='purple' if dns_risk < 0.4 else 'darkorange',
                                          importance=0.4,
                                          risk_score=dns_risk,
                                          full_record=record,
                                          node_id=hashlib.md5(record_node.encode()).hexdigest())
                        
                        self.graph.add_edge(domain, record_node, 
                                          relationship=record_type,
                                          weight=0.5,
                                          label=f'DNS {record_type}',
                                          security_level="LOW",
                                          edge_id=f"{domain}_{record_node}_dns")

        # Sosyal medya ilişkileri - gelişmiş OSINT
        social_media = osint_data.get('social_media', {})
        for platform, accounts in social_media.items():
            if isinstance(accounts, list):
                for account_info in accounts[:8]:  # İlk 8 hesap
                    if isinstance(account_info, dict) and self.security_validation(account_info):
                        account = account_info.get('username', '')
                        if account:
                            account_node = f"{platform}:{account}"
                            social_risk = self.analyze_social_media_risk(platform, account_info)
                            
                            self.graph.add_node(account_node, 
                                              type='social_media', 
                                              size=180,
                                              color='orange' if social_risk < 0.5 else 'crimson',
                                              importance=0.7,
                                              platform=platform,
                                              confidence=account_info.get('confidence'),
                                              risk_score=social_risk,
                                              followers=account_info.get('followers'),
                                              activity_level=account_info.get('activity'),
                                              node_id=hashlib.md5(account_node.encode()).hexdigest())
                            
                            self.graph.add_edge(domain, account_node, 
                                              relationship='social_media',
                                              weight=0.6,
                                              label=platform,
                                              security_level="MEDIUM",
                                              edge_id=f"{domain}_{account_node}_social")

        # WHOIS ilişkileri - gelişmiş analiz
        whois_data = osint_data.get('whois', {})
        self._process_whois_data(domain, whois_data)
        
        # SSL sertifikaları ilişkileri
        ssl_data = osint_data.get('ssl_certificates', {})
        self._process_ssl_data(domain, ssl_data)
        
        # Port tarama verileri
        port_scan_data = osint_data.get('port_scan', {})
        self._process_port_scan_data(domain, port_scan_data)
        
        # Web teknolojileri
        web_tech_data = osint_data.get('web_technologies', {})
        self._process_web_technologies(domain, web_tech_data)

        # Ağ yoğunluğu optimizasyonu
        self._optimize_network_density()
        
        self.print_log(f"Ağ grafı oluşturma tamamlandı: {self.graph.number_of_nodes()} düğüm, {self.graph.number_of_edges()} kenar", "SUCCESS")
        return self.graph

    def _process_whois_data(self, domain: str, whois_data: Dict[str, Any]):
        """WHOIS verilerini işle"""
        name_servers = whois_data.get('name_servers', [])
        if isinstance(name_servers, list):
            for ns in name_servers[:5]:  # İlk 5 nameserver
                if self.security_validation(ns):
                    ns_node = f"NS:{ns}"
                    self.graph.add_node(ns_node, 
                                      type='nameserver', 
                                      size=120,
                                      color='brown',
                                      importance=0.5,
                                      node_id=hashlib.md5(ns_node.encode()).hexdigest())
                    
                    self.graph.add_edge(domain, ns_node, 
                                      relationship='nameserver',
                                      weight=0.8,
                                      label='Name Server',
                                      security_level="MEDIUM",
                                      edge_id=f"{domain}_{ns_node}_ns")

        # Registrar bilgileri
        registrar = whois_data.get('registrar')
        if registrar and self.security_validation(registrar):
            registrar_node = f"Registrar:{registrar}"
            self.graph.add_node(registrar_node,
                              type='registrar',
                              size=110,
                              color='darkblue',
                              importance=0.4,
                              node_id=hashlib.md5(registrar_node.encode()).hexdigest())
            
            self.graph.add_edge(domain, registrar_node,
                              relationship='registered_by',
                              weight=0.6,
                              label='Registrar',
                              security_level="LOW",
                              edge_id=f"{domain}_{registrar_node}_registrar")

    def _process_ssl_data(self, domain: str, ssl_data: Dict[str, Any]):
        """SSL sertifika verilerini işle"""
        certificates = ssl_data.get('certificates', [])
        for cert in certificates[:3]:  # İlk 3 sertifika
            if isinstance(cert, dict) and self.security_validation(cert):
                issuer = cert.get('issuer', '')
                if issuer:
                    cert_node = f"SSL:{issuer[:30]}"
                    self.graph.add_node(cert_node,
                                      type='ssl_certificate',
                                      size=90,
                                      color='teal',
                                      importance=0.3,
                                      expiration=cert.get('expiration'),
                                      node_id=hashlib.md5(cert_node.encode()).hexdigest())
                    
                    self.graph.add_edge(domain, cert_node,
                                      relationship='ssl_certificate',
                                      weight=0.4,
                                      label='SSL Certificate',
                                      security_level="MEDIUM",
                                      edge_id=f"{domain}_{cert_node}_ssl")

    def _process_port_scan_data(self, domain: str, port_data: Dict[str, Any]):
        """Port tarama verilerini işle"""
        open_ports = port_data.get('open_ports', [])
        for port_info in open_ports[:10]:  # İlk 10 port
            if isinstance(port_info, dict) and self.security_validation(port_info):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                if port:
                    port_node = f"Port:{port}({service})"
                    risk_level = self.analyze_port_risk(port, service)
                    
                    self.graph.add_node(port_node,
                                      type='open_port',
                                      size=80,
                                      color='lightcoral' if risk_level > 0.7 else 'lightblue',
                                      importance=0.2,
                                      risk_score=risk_level,
                                      node_id=hashlib.md5(port_node.encode()).hexdigest())
                    
                    # Port'u ilgili IP'ye bağla
                    ip_address = port_data.get('ip_address')
                    if ip_address and ip_address in self.graph.nodes():
                        self.graph.add_edge(ip_address, port_node,
                                          relationship='has_port',
                                          weight=0.3,
                                          label=f'Port {port}',
                                          security_level="LOW",
                                          edge_id=f"{ip_address}_{port_node}_port")

    def _process_web_technologies(self, domain: str, web_tech_data: Dict[str, Any]):
        """Web teknolojilerini işle"""
        technologies = web_tech_data.get('technologies', [])
        for tech in technologies[:15]:  # İlk 15 teknoloji
            if isinstance(tech, dict) and self.security_validation(tech):
                tech_name = tech.get('name', '')
                tech_version = tech.get('version', '')
                if tech_name:
                    tech_node = f"Tech:{tech_name}"
                    self.graph.add_node(tech_node,
                                      type='web_technology',
                                      size=70,
                                      color='lightgreen',
                                      importance=0.1,
                                      version=tech_version,
                                      node_id=hashlib.md5(tech_node.encode()).hexdigest())
                    
                    self.graph.add_edge(domain, tech_node,
                                      relationship='uses_technology',
                                      weight=0.2,
                                      label=tech_name,
                                      security_level="LOW",
                                      edge_id=f"{domain}_{tech_node}_tech")

    def _optimize_network_density(self):
        """Ağ yoğunluğunu optimize et"""
        if self.graph.number_of_nodes() > 1000:
            self.print_log("Büyük ağ için optimizasyon yapılıyor...", "ANALYSIS")
            # Önemsiz düğümleri filtrele
            nodes_to_remove = []
            for node, data in self.graph.nodes(data=True):
                if data.get('importance', 0) < 0.1:
                    nodes_to_remove.append(node)
            
            for node in nodes_to_remove:
                self.graph.remove_node(node)
                
            self.print_log(f"Optimizasyon tamamlandı: {len(nodes_to_remove)} düğüm kaldırıldı", "SUCCESS")

    def calculate_ip_risk_score(self, ip_info: Dict[str, Any]) -> float:
        """IP risk skoru hesapla"""
        risk_score = 0.0
        
        # ASN riski
        asn = ip_info.get('asn', '')
        if asn and any(risky_asn in asn for risky_asn in ['TOR', 'PROXY', 'VPN']):
            risk_score += 0.6
            
        # Organizasyon riski
        org = ip_info.get('org', '').lower()
        risky_orgs = ['hosting', 'cloud', 'vps', 'proxy', 'vpn']
        if any(risky in org for risky in risky_orgs):
            risk_score += 0.4
            
        # Coğrafi risk
        country = ip_info.get('geolocation', {}).get('country', '')
        risky_countries = ['RU', 'CN', 'KP', 'IR']  # Riskli ülkeler
        if country in risky_countries:
            risk_score += 0.3
            
        return min(risk_score, 1.0)

    def analyze_subdomain_risk(self, subdomain: str, subdomain_info: Dict[str, Any]) -> float:
        """Subdomain risk analizi"""
        risk_score = 0.0
        
        # Şüpheli subdomain patternleri
        suspicious_patterns = ['admin', 'test', 'dev', 'staging', 'backup', 'api']
        if any(pattern in subdomain.lower() for pattern in suspicious_patterns):
            risk_score += 0.3
            
        # Port riski
        open_ports = subdomain_info.get('open_ports', [])
        risky_ports = [21, 22, 23, 135, 445, 1433, 3306, 3389]
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port = port_info.get('port', 0)
                if port in risky_ports:
                    risk_score += 0.2
                    
        return min(risk_score, 1.0)

    def analyze_dns_record_risk(self, record_type: str, record: str) -> float:
        """DNS kaydı risk analizi"""
        risk_score = 0.0
        
        if record_type.upper() in ['TXT', 'CNAME']:
            suspicious_terms = ['phishing', 'malware', 'suspicious', 'spam']
            if any(term in record.lower() for term in suspicious_terms):
                risk_score += 0.5
                
        return min(risk_score, 1.0)

    def analyze_social_media_risk(self, platform: str, account_info: Dict[str, Any]) -> float:
        """Sosyal medya risk analizi"""
        risk_score = 0.0
        
        # Aktivite seviyesi
        activity = account_info.get('activity', 'low')
        if activity == 'high':
            risk_score += 0.2
        elif activity == 'suspicious':
            risk_score += 0.5
            
        return min(risk_score, 1.0)

    def analyze_port_risk(self, port: int, service: str) -> float:
        """Port risk analizi"""
        high_risk_ports = {
            21: 0.8,    # FTP
            22: 0.7,    # SSH
            23: 0.9,    # Telnet
            135: 0.8,   # RPC
            139: 0.7,   # NetBIOS
            445: 0.9,   # SMB
            1433: 0.8,  # MSSQL
            3306: 0.6,  # MySQL
            3389: 0.9   # RDP
        }
        
        return high_risk_ports.get(port, 0.3)

    def enhanced_network_centrality_analysis(self) -> Dict[str, Any]:
        """Gelişmiş ağ merkezilik analizi"""
        self.print_log("Gelişmiş merkezilik analizi yapılıyor...", "ANALYSIS")
        
        centrality_measures = {}
        
        try:
            if len(self.graph.nodes) > 0:
                centrality_measures['degree_centrality'] = nx.degree_centrality(self.graph)
            else:
                centrality_measures['degree_centrality'] = {}
        except Exception as e:
            self.print_log(f"Derece merkezilik hatası: {e}", "ERROR")
            centrality_measures['degree_centrality'] = {}
            
        try:
            if len(self.graph.nodes) > 0:
                # Betweenness centrality için optimize edilmiş hesaplama
                if len(self.graph.nodes) > 50:
                    centrality_measures['betweenness_centrality'] = nx.betweenness_centrality(
                        self.graph, k=min(50, len(self.graph.nodes)//2))
                else:
                    centrality_measures['betweenness_centrality'] = nx.betweenness_centrality(self.graph)
            else:
                centrality_measures['betweenness_centrality'] = {}
        except Exception as e:
            self.print_log(f"Aradalık merkezilik hatası: {e}", "ERROR")
            centrality_measures['betweenness_centrality'] = {}
            
        try:
            if len(self.graph.nodes) > 0:
                centrality_measures['eigenvector_centrality'] = nx.eigenvector_centrality(
                    self.graph, max_iter=2000, tol=1e-8)
            else:
                centrality_measures['eigenvector_centrality'] = {}
        except Exception as e:
            self.print_log(f"Özvektör merkezilik hatası: {e}", "ERROR")
            centrality_measures['eigenvector_centrality'] = {}
            
        try:
            if len(self.graph.nodes) > 0:
                centrality_measures['closeness_centrality'] = nx.closeness_centrality(self.graph)
            else:
                centrality_measures['closeness_centrality'] = {}
        except Exception as e:
            self.print_log(f"Yakınlık merkezilik hatası: {e}", "ERROR")
            centrality_measures['closeness_centrality'] = {}
            
        try:
            if len(self.graph.nodes) > 0:
                centrality_measures['pagerank'] = nx.pagerank(self.graph, alpha=0.85, max_iter=200)
            else:
                centrality_measures['pagerank'] = {}
        except Exception as e:
            self.print_log(f"PageRank hatası: {e}", "ERROR")
            centrality_measures['pagerank'] = {}
            
        try:
            if len(self.graph.nodes) > 0:
                centrality_measures['harmonic_centrality'] = nx.harmonic_centrality(self.graph)
            else:
                centrality_measures['harmonic_centrality'] = {}
        except Exception as e:
            self.print_log(f"Harmonik merkezilik hatası: {e}", "ERROR")
            centrality_measures['harmonic_centrality'] = {}
            
        try:
            if len(self.graph.nodes) > 0:
                centrality_measures['katz_centrality'] = nx.katz_centrality(self.graph, max_iter=1000)
            else:
                centrality_measures['katz_centrality'] = {}
        except Exception as e:
            self.print_log(f"Katz merkezilik hatası: {e}", "ERROR")
            centrality_measures['katz_centrality'] = {}

        # Gelişmiş merkezilik analizi
        try:
            if len(self.graph.nodes) > 0:
                # Load Centrality
                centrality_measures['load_centrality'] = nx.load_centrality(self.graph)
                
                # Subgraph Centrality
                centrality_measures['subgraph_centrality'] = nx.subgraph_centrality(self.graph)
            else:
                centrality_measures['load_centrality'] = {}
                centrality_measures['subgraph_centrality'] = {}
        except Exception as e:
            self.print_log(f"Gelişmiş merkezilik hatası: {e}", "ERROR")
            centrality_measures['load_centrality'] = {}
            centrality_measures['subgraph_centrality'] = {}
        
        # Top merkezilik düğümlerini bul
        top_nodes = {}
        for measure_name, measure_dict in centrality_measures.items():
            if measure_dict and len(measure_dict) > 0:
                sorted_nodes = sorted(measure_dict.items(), key=lambda x: x[1], reverse=True)[:10]  # İlk 10
                top_nodes[measure_name] = [
                    {
                        'node': node, 
                        'score': round(score, 6), 
                        'type': self.graph.nodes[node].get('type', 'unknown'),
                        'risk_score': self.graph.nodes[node].get('risk_score', 0),
                        'importance': self.graph.nodes[node].get('importance', 0)
                    }
                    for node, score in sorted_nodes
                ]
                
        centrality_measures['top_nodes'] = top_nodes
        
        # Merkezilik korelasyon analizi
        centrality_measures['correlation_analysis'] = self._analyze_centrality_correlations(centrality_measures)
        
        return centrality_measures
        
    def _analyze_centrality_correlations(self, centrality_measures: Dict[str, Any]) -> Dict[str, Any]:
        """Merkezilik ölçütleri arası korelasyon analizi"""
        correlations = {}
        
        try:
            # Ortak düğümler üzerinden korelasyon hesapla
            common_nodes = set()
            valid_measures = {}
            
            for measure_name, measure_dict in centrality_measures.items():
                if isinstance(measure_dict, dict) and measure_dict and measure_name not in ['top_nodes', 'correlation_analysis']:
                    valid_measures[measure_name] = measure_dict
                    if not common_nodes:
                        common_nodes = set(measure_dict.keys())
                    else:
                        common_nodes = common_nodes.intersection(set(measure_dict.keys()))
            
            if len(common_nodes) > 2:
                # Korelasyon matrisi oluştur
                measure_names = list(valid_measures.keys())
                corr_matrix = np.zeros((len(measure_names), len(measure_names)))
                
                for i, measure1 in enumerate(measure_names):
                    for j, measure2 in enumerate(measure_names):
                        if i <= j:
                            values1 = [valid_measures[measure1][node] for node in common_nodes]
                            values2 = [valid_measures[measure2][node] for node in common_nodes]
                            
                            if len(values1) > 1 and len(values2) > 1:
                                correlation, p_value = stats.pearsonr(values1, values2)
                                corr_matrix[i, j] = correlation
                                corr_matrix[j, i] = correlation
                
                correlations['matrix'] = corr_matrix.tolist()
                correlations['measures'] = measure_names
                correlations['common_nodes_count'] = len(common_nodes)
                
        except Exception as e:
            self.print_log(f"Korelasyon analiz hatası: {e}", "ERROR")
            
        return correlations

    def advanced_community_detection(self) -> Dict[str, Any]:
        """Gelişmiş topluluk tespiti"""
        if len(self.graph.nodes) == 0:
            return {}
            
        community_results = {}
        
        try:
            # Louvain algoritması
            partition = community_louvain.best_partition(self.graph)
            communities = defaultdict(list)
            
            for node, community_id in partition.items():
                node_data = {
                    'node': node,
                    'type': self.graph.nodes[node].get('type', 'unknown'),
                    'centrality': self.graph.nodes[node].get('importance', 0),
                    'risk_score': self.graph.nodes[node].get('risk_score', 0)
                }
                communities[community_id].append(node_data)
                
            # Topluluk istatistikleri
            community_stats = {}
            for comm_id, nodes in communities.items():
                node_types = [node['type'] for node in nodes]
                type_counts = Counter(node_types)
                
                risk_scores = [node['risk_score'] for node in nodes]
                centrality_scores = [node['centrality'] for node in nodes]
                
                community_stats[comm_id] = {
                    'size': len(nodes),
                    'node_types': dict(type_counts),
                    'avg_centrality': np.mean(centrality_scores) if nodes else 0,
                    'avg_risk_score': np.mean(risk_scores) if nodes else 0,
                    'risk_std': np.std(risk_scores) if nodes else 0,
                    'main_type': max(type_counts, key=type_counts.get) if type_counts else 'unknown',
                    'most_central_node': max(nodes, key=lambda x: x['centrality']) if nodes else None,
                    'highest_risk_node': max(nodes, key=lambda x: x['risk_score']) if nodes else None
                }
                
            community_results['louvain'] = {
                'communities': dict(communities),
                'statistics': community_stats,
                'total_communities': len(communities),
                'modularity': community_louvain.modularity(partition, self.graph)
            }
            
            # Girvan-Newman topluluk tespiti (küçük ağlar için)
            if len(self.graph.nodes) < 1000:
                try:
                    comp = nx.algorithms.community.girvan_newman(self.graph)
                    limited_communities = []
                    for communities in itertools.islice(comp, 3):  # İlk 3 seviye
                        comm_list = [list(community) for community in communities]
                        limited_communities.append(comm_list)
                    
                    community_results['girvan_newman'] = {
                        'hierarchical_communities': limited_communities
                    }
                except Exception as e:
                    self.print_log(f"Girvan-Newman hatası: {e}", "WARNING")
                    
            # Label Propagation
            try:
                label_prop_communities = list(nx.algorithms.community.label_propagation_communities(self.graph))
                community_results['label_propagation'] = {
                    'communities': [list(community) for community in label_prop_communities],
                    'total_communities': len(label_prop_communities)
                }
            except Exception as e:
                self.print_log(f"Label Propagation hatası: {e}", "WARNING")
                
        except Exception as e:
            self.print_log(f"Topluluk tespit hatası: {e}", "ERROR")
            
        return community_results

    def calculate_comprehensive_network_metrics(self) -> Dict[str, Any]:
        """Kapsamlı ağ metrikleri hesaplama"""
        metrics = {
            'basic_metrics': {
                'number_of_nodes': self.graph.number_of_nodes(),
                'number_of_edges': self.graph.number_of_edges(),
                'density': nx.density(self.graph) if self.graph.number_of_nodes() > 0 else 0,
                'average_degree': 0,
                'degree_assortativity': 0,
                'degree_pearson_correlation': 0
            },
            'connectivity_metrics': {},
            'centrality_metrics': {},
            'clustering_metrics': {},
            'advanced_metrics': {},
            'security_metrics': {}
        }
        
        # Temel metrikler
        if metrics['basic_metrics']['number_of_nodes'] > 0:
            degrees = dict(self.graph.degree())
            metrics['basic_metrics']['average_degree'] = sum(degrees.values()) / metrics['basic_metrics']['number_of_nodes']
            metrics['basic_metrics']['max_degree'] = max(degrees.values()) if degrees else 0
            metrics['basic_metrics']['min_degree'] = min(degrees.values()) if degrees else 0
            metrics['basic_metrics']['degree_variance'] = np.var(list(degrees.values())) if degrees else 0
            
            try:
                metrics['basic_metrics']['degree_assortativity'] = nx.degree_assortativity_coefficient(self.graph)
                metrics['basic_metrics']['degree_pearson_correlation'] = nx.degree_pearson_correlation_coefficient(self.graph)
            except Exception as e:
                self.print_log(f"Degree assortativity hatası: {e}", "WARNING")
            
        # Bağlantı metrikleri
        try:
            if self.graph.number_of_nodes() > 0:
                if nx.is_connected(self.graph):
                    metrics['connectivity_metrics']['diameter'] = nx.diameter(self.graph)
                    metrics['connectivity_metrics']['average_shortest_path'] = nx.average_shortest_path_length(self.graph)
                    metrics['connectivity_metrics']['is_connected'] = True
                else:
                    connected_components = list(nx.connected_components(self.graph))
                    metrics['connectivity_metrics']['connected_components'] = len(connected_components)
                    if connected_components:
                        largest_cc = max(connected_components, key=len)
                        metrics['connectivity_metrics']['largest_component_size'] = len(largest_cc)
                        metrics['connectivity_metrics']['largest_component_ratio'] = len(largest_cc) / metrics['basic_metrics']['number_of_nodes']
                    else:
                        metrics['connectivity_metrics']['largest_component_size'] = 0
                        metrics['connectivity_metrics']['largest_component_ratio'] = 0
                    metrics['connectivity_metrics']['is_connected'] = False
                    
                metrics['connectivity_metrics']['node_connectivity'] = nx.node_connectivity(self.graph) if self.graph.number_of_nodes() > 1 else 0
                metrics['connectivity_metrics']['edge_connectivity'] = nx.edge_connectivity(self.graph) if self.graph.number_of_nodes() > 1 else 0
                metrics['connectivity_metrics']['average_node_connectivity'] = nx.average_node_connectivity(self.graph) if self.graph.number_of_nodes() > 1 else 0
                
            else:
                metrics['connectivity_metrics']['is_connected'] = False
                metrics['connectivity_metrics']['connected_components'] = 0
                metrics['connectivity_metrics']['largest_component_size'] = 0
                metrics['connectivity_metrics']['node_connectivity'] = 0
                metrics['connectivity_metrics']['edge_connectivity'] = 0
                
        except Exception as e:
            self.print_log(f"Bağlantı metrikleri hatası: {e}", "ERROR")
            metrics['connectivity_metrics']['error'] = str(e)
            
        # Kümeleme metrikleri
        try:
            if self.graph.number_of_nodes() > 0:
                metrics['clustering_metrics']['average_clustering'] = nx.average_clustering(self.graph)
                metrics['clustering_metrics']['transitivity'] = nx.transitivity(self.graph)
                metrics['clustering_metrics']['square_clustering'] = nx.square_clustering(self.graph)
                
                # Düğüm tipine göre kümeleme katsayıları
                clustering_coeffs = nx.clustering(self.graph)
                type_clustering = defaultdict(list)
                for node, coeff in clustering_coeffs.items():
                    node_type = self.graph.nodes[node].get('type', 'unknown')
                    type_clustering[node_type].append(coeff)
                    
                metrics['clustering_metrics']['type_based_clustering'] = {
                    node_type: {
                        'average': np.mean(coeffs) if coeffs else 0,
                        'std': np.std(coeffs) if coeffs else 0,
                        'min': min(coeffs) if coeffs else 0,
                        'max': max(coeffs) if coeffs else 0,
                        'count': len(coeffs)
                    }
                    for node_type, coeffs in type_clustering.items()
                }
            else:
                metrics['clustering_metrics']['average_clustering'] = 0
                metrics['clustering_metrics']['transitivity'] = 0
                metrics['clustering_metrics']['square_clustering'] = 0
                metrics['clustering_metrics']['type_based_clustering'] = {}
                
        except Exception as e:
            self.print_log(f"Kümeleme metrikleri hatası: {e}", "ERROR")
            metrics['clustering_metrics']['error'] = str(e)
            
        # Gelişmiş metrikler
        try:
            if self.graph.number_of_nodes() > 0:
                # Eğrilik (Curvature) metrikleri
                metrics['advanced_metrics']['rich_club_coefficient'] = nx.rich_club_coefficient(self.graph, normalized=True)
                
                # Spectral metrikler
                try:
                    laplacian_spectrum = nx.laplacian_spectrum(self.graph)
                    metrics['advanced_metrics']['algebraic_connectivity'] = sorted(laplacian_spectrum)[1] if len(laplacian_spectrum) > 1 else 0
                    metrics['advanced_metrics']['spectral_radius'] = max(laplacian_spectrum) if laplacian_spectrum else 0
                except Exception as e:
                    self.print_log(f"Spectral metrik hatası: {e}", "WARNING")
                    
                # Efficiency metrikleri
                try:
                    metrics['advanced_metrics']['global_efficiency'] = nx.global_efficiency(self.graph)
                    metrics['advanced_metrics']['local_efficiency'] = nx.local_efficiency(self.graph)
                except Exception as e:
                    self.print_log(f"Efficiency metrik hatası: {e}", "WARNING")
                    
        except Exception as e:
            self.print_log(f"Gelişmiş metrikler hatası: {e}", "ERROR")
            metrics['advanced_metrics']['error'] = str(e)
            
        # Güvenlik metrikleri
        try:
            risk_scores = [data.get('risk_score', 0) for _, data in self.graph.nodes(data=True)]
            security_metrics = {
                'average_risk_score': np.mean(risk_scores) if risk_scores else 0,
                'max_risk_score': max(risk_scores) if risk_scores else 0,
                'high_risk_nodes': len([score for score in risk_scores if score > 0.7]),
                'medium_risk_nodes': len([score for score in risk_scores if 0.3 <= score <= 0.7]),
                'low_risk_nodes': len([score for score in risk_scores if score < 0.3]),
                'risk_distribution': dict(Counter([round(score, 1) for score in risk_scores]))
            }
            
            # Risk korelasyonu
            if len(risk_scores) > 1:
                degrees = [deg for _, deg in self.graph.degree()]
                if len(degrees) == len(risk_scores):
                    risk_degree_corr = np.corrcoef(risk_scores, degrees)[0, 1] if not np.isnan(np.corrcoef(risk_scores, degrees)[0, 1]) else 0
                    security_metrics['risk_degree_correlation'] = risk_degree_corr
                    
            metrics['security_metrics'] = security_metrics
            
        except Exception as e:
            self.print_log(f"Güvenlik metrikleri hatası: {e}", "ERROR")
            metrics['security_metrics']['error'] = str(e)
            
        return metrics

    def calculate_advanced_metrics(self):
        """Gelişmiş metrikleri hesapla - DÜZELTİLMİŞ VERSİYON"""
        try:
            # HATA ÇÖZÜMÜ: Daha düşük swap değerleri kullan
            if len(self.graph.nodes) > 0:
                # Community detection için daha küçük parametreler
                communities = nx.algorithms.community.greedy_modularity_communities(
                    self.graph, resolution=1.0, best_n=min(10, len(self.graph.nodes))
                )
                
                # Betweenness centrality için sample kullan
                if len(self.graph.nodes) > 50:
                    centrality = nx.betweenness_centrality(self.graph, k=min(50, len(self.graph.nodes)//2))
                else:
                    centrality = nx.betweenness_centrality(self.graph)
                    
        except Exception as e:
            self.print_log(f"Gelişmiş metrikler hatası: {e}", "ERROR")
            # Fallback metrikler
            return self.calculate_basic_metrics()

    def create_interactive_network_visualization(self, filename: str = 'interactive_network.html') -> str:
        """Gelişmiş etkileşimli ağ görselleştirme"""
        try:
            if len(self.graph.nodes) == 0:
                self.print_log("Görselleştirme için düğüm bulunamadı", "WARNING")
                return None

            # Gelişmiş düğüm pozisyonları
            pos = nx.spring_layout(self.graph, k=2, iterations=100, seed=42)
            
            # Düğüm özellikleri
            node_x = []
            node_y = []
            node_text = []
            node_size = []
            node_color = []
            node_types = []
            node_risk = []
            node_centrality = []
            custom_data = []
            
            for node in self.graph.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                
                node_data = self.graph.nodes[node]
                node_type = node_data.get('type', 'unknown')
                risk_score = node_data.get('risk_score', 0)
                importance = node_data.get('importance', 0)
                
                # Detaylı tooltip
                tooltip_text = f"""
                <b>{node}</b><br>
                Type: {node_type}<br>
                Risk Score: {risk_score:.3f}<br>
                Importance: {importance:.3f}<br>
                Degree: {self.graph.degree[node]}
                """
                
                if 'geolocation' in node_data:
                    geo = node_data['geolocation']
                    tooltip_text += f"<br>Location: {geo.get('city', '')}, {geo.get('country', '')}"
                    
                node_text.append(tooltip_text)
                node_size.append(max(5, node_data.get('size', 100) / 2))
                
                # Risk skoruna göre renk
                if risk_score > 0.7:
                    node_color.append('red')
                elif risk_score > 0.4:
                    node_color.append('orange')
                elif risk_score > 0.1:
                    node_color.append('yellow')
                else:
                    # Tip bazlı renkler
                    color_map = {
                        'domain': 'red',
                        'ip': 'blue', 
                        'subdomain': 'green',
                        'social_media': 'orange',
                        'dns_a': 'purple',
                        'dns_mx': 'purple',
                        'dns_txt': 'purple',
                        'dns_ns': 'purple',
                        'nameserver': 'brown',
                        'ssl_certificate': 'teal',
                        'open_port': 'lightcoral',
                        'web_technology': 'lightgreen',
                        'registrar': 'darkblue'
                    }
                    node_color.append(color_map.get(node_type, 'gray'))
                
                node_types.append(node_type)
                node_risk.append(risk_score)
                node_centrality.append(importance)
                custom_data.append([node_type, risk_score, importance])
            
            # Kenar özellikleri
            edge_x = []
            edge_y = []
            edge_text = []
            edge_width = []
            edge_color = []
            
            for edge in self.graph.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                
                edge_data = self.graph.edges[edge]
                relationship = edge_data.get('relationship', 'unknown')
                weight = edge_data.get('weight', 0.5)
                
                edge_text.append(f"{edge[0]} → {edge[1]}<br>Relationship: {relationship}<br>Weight: {weight:.3f}")
                edge_width.append(max(0.5, weight * 3))
                
                # İlişki tipine göre renk
                rel_color_map = {
                    'resolves_to': 'blue',
                    'subdomain_of': 'green',
                    'social_media': 'orange',
                    'nameserver': 'brown',
                    'registered_by': 'darkblue',
                    'ssl_certificate': 'teal',
                    'has_port': 'lightcoral',
                    'uses_technology': 'lightgreen'
                }
                edge_color.append(rel_color_map.get(relationship, 'gray'))
            
            # Etkileşimli grafik oluştur
            fig = go.Figure()
            
            # Kenarları ekle
            fig.add_trace(go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=edge_width, color=edge_color),
                hoverinfo='text',
                text=edge_text,
                mode='lines',
                name='Connections',
                opacity=0.7
            ))
            
            # Düğümleri ekle
            fig.add_trace(go.Scatter(
                x=node_x, y=node_y,
                mode='markers+text',
                hoverinfo='text',
                text=[node[:20] + '...' if len(node) > 20 else node for node in self.graph.nodes()],
                textposition="middle center",
                hovertext=node_text,
                marker=dict(
                    size=node_size,
                    color=node_color,
                    line=dict(width=2, color='darkblue'),
                    opacity=0.9
                ),
                customdata=custom_data,
                hovertemplate='<b>%{hovertext}</b><extra></extra>',
                name='Nodes'
            ))
            
            # Layout ayarları
            fig.update_layout(
                title=dict(
                    text=f'Council Mesh v{self.version} - Gelişmiş Ağ İlişkileri Haritası<br><sub>Toplam {len(node_x)} düğüm, {len(self.graph.edges())} kenar</sub>',
                    font=dict(size=20, color='white')
                ),
                showlegend=True,
                hovermode='closest',
                margin=dict(b=20, l=5, r=5, t=80),
                paper_bgcolor='rgba(0,0,0,0.9)',
                plot_bgcolor='rgba(0,0,0,0.9)',
                font=dict(color='white'),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                width=1400,
                height=900,
                annotations=[dict(
                    text="REDHACK ELITE NETWORK ANALYSIS",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.5, y=-0.05,
                    font=dict(size=12, color='red')
                )]
            )
            
            # HTML olarak kaydet
            fig.write_html(filename, config={'responsive': True})
            self.print_log(f"Gelişmiş interaktif ağ grafiği kaydedildi: {filename}", "SUCCESS")
            
            return filename

        except Exception as e:
            self.print_log(f"İnteraktif görselleştirme hatası: {e}", "ERROR")
            return None

    def create_advanced_visualization(self):
        """Gelişmiş görselleştirme - DÜZELTİLMİŞ"""
        try:
            # HATA ÇÖZÜMÜ: Renk formatını düzelt
            if hasattr(self, 'node_colors') and self.node_colors:
                # Liste yerine tek renk kullan veya doğru formata çevir
                valid_colors = []
                for color in self.node_colors:
                    if color in ['blue', 'red', 'green', 'yellow', 'purple', 'orange', 'brown']:
                        valid_colors.append(color)
                    else:
                        valid_colors.append('gray')  # Varsayılan renk
                        
                # Plotly için doğru renk formatı
                line_color = valid_colors[0] if valid_colors else 'blue'
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=[0, 1, 2],  # Örnek koordinatlar
                    y=[0, 1, 2],
                    mode='markers+text',
                    marker=dict(
                        size=[10, 15, 20],  # Örnek boyutlar
                        color=valid_colors,  # Marker rengi liste olabilir
                        line=dict(width=2, color=line_color)  # Line rengi tek değer
                    )
                ))
                
        except Exception as e:
            self.print_log(f"Görselleştirme hatası: {e}", "ERROR")
            return self.create_basic_visualization()
            
    def create_analytical_dashboards(self) -> Dict[str, str]:
        """Gelişmiş analitik dashboard'lar oluştur"""
        dashboards = {}
        
        try:
            # 1. Merkezilik Dağılımı Dashboard
            centrality_data = self.analysis_results.get('centrality', {})
            if centrality_data.get('degree_centrality'):
                self._create_centrality_dashboard(centrality_data, dashboards)
                
            # 2. Topluluk Analizi Dashboard
            communities_data = self.analysis_results.get('communities', {})
            if communities_data:
                self._create_community_dashboard(communities_data, dashboards)
                
            # 3. Güvenlik Risk Dashboard
            security_metrics = self.analysis_results.get('metrics', {}).get('security_metrics', {})
            if security_metrics:
                self._create_security_dashboard(security_metrics, dashboards)
                
            # 4. Ağ Metrikleri Dashboard
            network_metrics = self.analysis_results.get('metrics', {})
            if network_metrics:
                self._create_network_metrics_dashboard(network_metrics, dashboards)
                
            # 5. Korelasyon Analizi Dashboard
            if centrality_data.get('correlation_analysis'):
                self._create_correlation_dashboard(centrality_data['correlation_analysis'], dashboards)
                
        except Exception as e:
            self.print_log(f"Dashboard oluşturma hatası: {e}", "ERROR")
            
        return dashboards

    def _create_centrality_dashboard(self, centrality_data: Dict[str, Any], dashboards: Dict[str, str]):
        """Merkezilik dashboard'ı oluştur"""
        try:
            # Merkezilik dağılım histogramları
            fig = make_subplots(
                rows=2, cols=3,
                subplot_titles=['Degree Centrality', 'Betweenness Centrality', 'Closeness Centrality',
                              'Eigenvector Centrality', 'PageRank', 'Harmonic Centrality'],
                specs=[[{"secondary_y": False}, {"secondary_y": False}, {"secondary_y": False}],
                       [{"secondary_y": False}, {"secondary_y": False}, {"secondary_y": False}]]
            )
            
            centrality_types = ['degree_centrality', 'betweenness_centrality', 'closeness_centrality',
                              'eigenvector_centrality', 'pagerank', 'harmonic_centrality']
            
            for i, cent_type in enumerate(centrality_types):
                if cent_type in centrality_data and centrality_data[cent_type]:
                    values = list(centrality_data[cent_type].values())
                    row = i // 3 + 1
                    col = i % 3 + 1
                    
                    fig.add_trace(
                        go.Histogram(x=values, name=cent_type.replace('_', ' ').title(),
                                   nbinsx=30, opacity=0.7),
                        row=row, col=col
                    )
            
            fig.update_layout(height=800, title_text="Merkezilik Ölçütleri Dağılımı", showlegend=False)
            dashboards['centrality_distribution'] = 'centrality_distribution.html'
            fig.write_html(dashboards['centrality_distribution'])
            
        except Exception as e:
            self.print_log(f"Merkezilik dashboard hatası: {e}", "ERROR")

    def _create_community_dashboard(self, communities_data: Dict[str, Any], dashboards: Dict[str, str]):
        """Topluluk analizi dashboard'ı oluştur"""
        try:
            louvain_data = communities_data.get('louvain', {})
            if louvain_data and louvain_data.get('statistics'):
                stats = louvain_data['statistics']
                
                # Topluluk boyutları
                comm_sizes = [comm_stats['size'] for comm_stats in stats.values()]
                comm_ids = list(stats.keys())
                
                fig = make_subplots(
                    rows=2, cols=2,
                    subplot_titles=['Topluluk Boyutları', 'Ortalama Risk Dağılımı',
                                  'Düğüm Tipi Dağılımı', 'Merkezilik-Risk İlişkisi'],
                    specs=[[{"type": "bar"}, {"type": "histogram"}],
                           [{"type": "pie"}, {"type": "scatter"}]]
                )
                
                # Topluluk boyutları
                fig.add_trace(
                    go.Bar(x=comm_ids, y=comm_sizes, name='Topluluk Boyutu'),
                    row=1, col=1
                )
                
                # Risk dağılımı
                risk_scores = [comm_stats['avg_risk_score'] for comm_stats in stats.values()]
                fig.add_trace(
                    go.Histogram(x=risk_scores, name='Risk Dağılımı', nbinsx=20),
                    row=1, col=2
                )
                
                # Düğüm tipi dağılımı (ilk topluluk için)
                if stats:
                    first_comm = list(stats.values())[0]
                    node_types = first_comm.get('node_types', {})
                    fig.add_trace(
                        go.Pie(labels=list(node_types.keys()), values=list(node_types.values()),
                             name='Düğüm Tipleri'),
                        row=2, col=1
                    )
                
                # Merkezilik-Risk scatter plot
                centrality_scores = [comm_stats['avg_centrality'] for comm_stats in stats.values()]
                fig.add_trace(
                    go.Scatter(x=centrality_scores, y=risk_scores, mode='markers',
                             marker=dict(size=comm_sizes, sizemode='area', sizeref=2.*max(comm_sizes)/(40.**2),
                                       sizemin=4), name='Topluluklar'),
                    row=2, col=2
                )
                
                fig.update_layout(height=800, title_text="Topluluk Analizi Dashboard")
                dashboards['community_analysis'] = 'community_analysis.html'
                fig.write_html(dashboards['community_analysis'])
                
        except Exception as e:
            self.print_log(f"Topluluk dashboard hatası: {e}", "ERROR")

    def _create_security_dashboard(self, security_metrics: Dict[str, Any], dashboards: Dict[str, str]):
        """Güvenlik risk dashboard'ı oluştur"""
        try:
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=['Risk Dağılımı', 'Risk Seviyeleri', 'Risk-Korelasyon', 'Zaman Serisi Analizi'],
                specs=[[{"type": "histogram"}, {"type": "pie"}],
                       [{"type": "bar"}, {"type": "scatter"}]]
            )
            
            # Risk dağılımı
            risk_dist = security_metrics.get('risk_distribution', {})
            if risk_dist:
                fig.add_trace(
                    go.Histogram(x=list(risk_dist.keys()), y=list(risk_dist.values()),
                               name='Risk Dağılımı'),
                    row=1, col=1
                )
            
            # Risk seviyeleri
            risk_levels = ['Yüksek Risk', 'Orta Risk', 'Düşük Risk']
            risk_counts = [
                security_metrics.get('high_risk_nodes', 0),
                security_metrics.get('medium_risk_nodes', 0),
                security_metrics.get('low_risk_nodes', 0)
            ]
            
            fig.add_trace(
                go.Pie(labels=risk_levels, values=risk_counts, name='Risk Seviyeleri'),
                row=1, col=2
            )
            
            # Risk metrikleri
            risk_metrics = {
                'Ortalama Risk': security_metrics.get('average_risk_score', 0),
                'Maksimum Risk': security_metrics.get('max_risk_score', 0),
                'Risk-Derece Korelasyon': security_metrics.get('risk_degree_correlation', 0)
            }
            
            fig.add_trace(
                go.Bar(x=list(risk_metrics.keys()), y=list(risk_metrics.values()),
                     name='Risk Metrikleri'),
                row=2, col=1
            )
            
            fig.update_layout(height=800, title_text="Güvenlik Risk Dashboard")
            dashboards['security_analysis'] = 'security_analysis.html'
            fig.write_html(dashboards['security_analysis'])
            
        except Exception as e:
            self.print_log(f"Güvenlik dashboard hatası: {e}", "ERROR")

    def _create_network_metrics_dashboard(self, network_metrics: Dict[str, Any], dashboards: Dict[str, str]):
        """Ağ metrikleri dashboard'ı oluştur"""
        try:
            basic_metrics = network_metrics.get('basic_metrics', {})
            connectivity_metrics = network_metrics.get('connectivity_metrics', {})
            clustering_metrics = network_metrics.get('clustering_metrics', {})
            
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=['Temel Metrikler', 'Bağlantı Metrikleri', 
                              'Kümeleme Metrikleri', 'Gelişmiş Metrikler'],
                specs=[[{"type": "bar"}, {"type": "bar"}],
                       [{"type": "bar"}, {"type": "bar"}]]
            )
            
            # Temel metrikler
            basic_data = {
                'Düğüm Sayısı': basic_metrics.get('number_of_nodes', 0),
                'Kenar Sayısı': basic_metrics.get('number_of_edges', 0),
                'Ortalama Derece': round(basic_metrics.get('average_degree', 0), 2),
                'Ağ Yoğunluğu': round(basic_metrics.get('density', 0), 4)
            }
            
            fig.add_trace(
                go.Bar(x=list(basic_data.keys()), y=list(basic_data.values()),
                     name='Temel Metrikler'),
                row=1, col=1
            )
            
            # Bağlantı metrikleri
            connectivity_data = {
                'Bağlı Bileşen': connectivity_metrics.get('connected_components', 0),
                'En Büyük Bileşen': connectivity_metrics.get('largest_component_size', 0),
                'Düğüm Bağlantısı': connectivity_metrics.get('node_connectivity', 0),
                'Kenar Bağlantısı': connectivity_metrics.get('edge_connectivity', 0)
            }
            
            fig.add_trace(
                go.Bar(x=list(connectivity_data.keys()), y=list(connectivity_data.values()),
                     name='Bağlantı Metrikleri'),
                row=1, col=2
            )
            
            # Kümeleme metrikleri
            clustering_data = {
                'Ort. Kümeleme': round(clustering_metrics.get('average_clustering', 0), 4),
                'Transitivity': round(clustering_metrics.get('transitivity', 0), 4),
                'Kare Kümeleme': round(clustering_metrics.get('square_clustering', 0), 4)
            }
            
            fig.add_trace(
                go.Bar(x=list(clustering_data.keys()), y=list(clustering_data.values()),
                     name='Kümeleme Metrikleri'),
                row=2, col=1
            )
            
            fig.update_layout(height=800, title_text="Ağ Metrikleri Dashboard")
            dashboards['network_metrics'] = 'network_metrics.html'
            fig.write_html(dashboards['network_metrics'])
            
        except Exception as e:
            self.print_log(f"Ağ metrikleri dashboard hatası: {e}", "ERROR")

    def _create_correlation_dashboard(self, correlation_data: Dict[str, Any], dashboards: Dict[str, str]):
        """Korelasyon analizi dashboard'ı oluştur"""
        try:
            if correlation_data.get('matrix') and correlation_data.get('measures'):
                corr_matrix = np.array(correlation_data['matrix'])
                measures = correlation_data['measures']
                
                fig = go.Figure(data=go.Heatmap(
                    z=corr_matrix,
                    x=measures,
                    y=measures,
                    hoverongaps=False,
                    colorscale='RdBu_r',
                    zmin=-1,
                    zmax=1
                ))
                
                fig.update_layout(
                    title='Merkezilik Ölçütleri Korelasyon Matrisi',
                    height=600
                )
                
                dashboards['correlation_analysis'] = 'correlation_analysis.html'
                fig.write_html(dashboards['correlation_analysis'])
                
        except Exception as e:
            self.print_log(f"Korelasyon dashboard hatası: {e}", "ERROR")
            
    def run_parallel_analysis(self, osint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Paralel analiz çalıştırma"""
        self.print_log("Paralel ağ analizi başlatıldı", "ANALYSIS")
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Paralel görevler
            future_graph = executor.submit(self.build_comprehensive_network_graph, osint_data)
            future_centrality = executor.submit(self.enhanced_network_centrality_analysis)
            future_communities = executor.submit(self.advanced_community_detection)
            future_metrics = executor.submit(self.calculate_comprehensive_network_metrics)
            
            # Sonuçları bekle
            graph_result = future_graph.result()
            centrality_result = future_centrality.result()
            communities_result = future_communities.result()
            metrics_result = future_metrics.result()
            
        # Görselleştirmeleri seri olarak çalıştır
        visualization_result = self.create_interactive_network_visualization()
        dashboards_result = self.create_analytical_dashboards()
        
        self.analysis_results = {
            'graph_info': {
                'nodes': list(self.graph.nodes(data=True)),
                'edges': list(self.graph.edges(data=True)),
                'graph_summary': {
                    'total_nodes': self.graph.number_of_nodes(),
                    'total_edges': self.graph.number_of_edges(),
                    'node_types': Counter([data.get('type', 'unknown') for _, data in self.graph.nodes(data=True)]),
                    'risk_profile': {
                        'high_risk_nodes': len([data for _, data in self.graph.nodes(data=True) if data.get('risk_score', 0) > 0.7]),
                        'critical_nodes': [node for node, data in self.graph.nodes(data=True) if data.get('importance', 0) > 0.8 and data.get('risk_score', 0) > 0.5]
                    }
                }
            },
            'centrality': centrality_result,
            'communities': communities_result,
            'metrics': metrics_result,
            'visualization': {
                'interactive': visualization_result,
                'dashboards': dashboards_result
            },
            'security_assessment': self._perform_security_assessment(),
            'performance_metrics': {
                'analysis_time': datetime.now().isoformat(),
                'graph_complexity': self._calculate_graph_complexity(),
                'processing_efficiency': self._calculate_processing_efficiency()
            }
        }
        
        return self.analysis_results

    def _perform_security_assessment(self) -> Dict[str, Any]:
        """Güvenlik değerlendirmesi yap"""
        assessment = {
            'threat_level': 'LOW',
            'critical_vulnerabilities': [],
            'security_recommendations': [],
            'risk_indicators': {}
        }
        
        try:
            # Yüksek riskli düğümleri tespit et
            high_risk_nodes = []
            for node, data in self.graph.nodes(data=True):
                risk_score = data.get('risk_score', 0)
                importance = data.get('importance', 0)
                
                if risk_score > 0.7 and importance > 0.5:
                    high_risk_nodes.append({
                        'node': node,
                        'type': data.get('type', 'unknown'),
                        'risk_score': risk_score,
                        'importance': importance,
                        'threat_level': 'CRITICAL' if risk_score > 0.9 else 'HIGH'
                    })
            
            assessment['critical_vulnerabilities'] = high_risk_nodes
            
            # Tehdit seviyesini belirle
            if high_risk_nodes:
                critical_count = len([node for node in high_risk_nodes if node['threat_level'] == 'CRITICAL'])
                if critical_count > 0:
                    assessment['threat_level'] = 'CRITICAL'
                else:
                    assessment['threat_level'] = 'HIGH'
            else:
                # Orta riskli düğümleri kontrol et
                medium_risk_nodes = len([data for _, data in self.graph.nodes(data=True) if 0.4 <= data.get('risk_score', 0) <= 0.7])
                if medium_risk_nodes > 5:
                    assessment['threat_level'] = 'MEDIUM'
            
            # Güvenlik önerileri
            if assessment['threat_level'] in ['HIGH', 'CRITICAL']:
                assessment['security_recommendations'].extend([
                    "Yüksek riskli düğümler derinlemesine incelenmeli",
                    "Şüpheli IP adresleri için bloklama uygulanmalı",
                    "Güvenlik duvarı kuralları gözden geçirilmeli"
                ])
            elif assessment['threat_level'] == 'MEDIUM':
                assessment['security_recommendations'].extend([
                    "Orta riskli servisler izlenmeli",
                    "Port taramaları düzenli yapılmalı",
                    "Log analizi artırılmalı"
                ])
                
        except Exception as e:
            self.print_log(f"Güvenlik değerlendirme hatası: {e}", "ERROR")
            
        return assessment

    def _calculate_graph_complexity(self) -> Dict[str, float]:
        """Graf karmaşıklığını hesapla"""
        complexity = {}
        
        try:
            n = self.graph.number_of_nodes()
            m = self.graph.number_of_edges()
            
            if n > 0:
                complexity['density'] = nx.density(self.graph)
                complexity['average_degree'] = 2 * m / n
                complexity['degree_heterogeneity'] = np.std([d for n, d in self.graph.degree()]) if n > 0 else 0
                complexity['clustering_coefficient'] = nx.average_clustering(self.graph)
                complexity['assortativity'] = nx.degree_assortativity_coefficient(self.graph)
                
                # Karmaşıklık skoru
                complexity_score = (complexity['density'] * 0.2 + 
                                  complexity['average_degree'] * 0.3 + 
                                  complexity['degree_heterogeneity'] * 0.2 +
                                  complexity['clustering_coefficient'] * 0.2 +
                                  abs(complexity['assortativity']) * 0.1)
                complexity['overall_complexity'] = complexity_score
                
        except Exception as e:
            self.print_log(f"Karmaşıklık hesaplama hatası: {e}", "ERROR")
            
        return complexity

    def _calculate_processing_efficiency(self) -> Dict[str, Any]:
        """İşlem verimliliğini hesapla"""
        efficiency = {
            'nodes_processed': self.graph.number_of_nodes(),
            'edges_processed': self.graph.number_of_edges(),
            'analysis_depth': 'DEEP' if self.graph.number_of_nodes() > 100 else 'STANDARD',
            'optimization_level': 'HIGH' if self.performance_optimized else 'STANDARD'
        }
        
        return efficiency
            
    def run(self, osint_data: Dict[str, Any], parallel: bool = True) -> Dict[str, Any]:
        """Ana çalıştırma metodu"""
        self.print_log(f"Gelişmiş ağ analizi başlatıldı (v{self.version})", "ANALYSIS")
        
        start_time = datetime.now()
        
        try:
            if parallel and self.graph.number_of_nodes() > 50:
                results = self.run_parallel_analysis(osint_data)
            else:
                # Seri analiz
                self.build_comprehensive_network_graph(osint_data)
                
                self.analysis_results = {
                    'graph_info': {
                        'nodes': list(self.graph.nodes(data=True)),
                        'edges': list(self.graph.edges(data=True)),
                        'graph_summary': {
                            'total_nodes': self.graph.number_of_nodes(),
                            'total_edges': self.graph.number_of_edges(),
                            'node_types': Counter([data.get('type', 'unknown') for _, data in self.graph.nodes(data=True)]),
                            'risk_profile': {
                                'high_risk_nodes': len([data for _, data in self.graph.nodes(data=True) if data.get('risk_score', 0) > 0.7]),
                                'critical_nodes': [node for node, data in self.graph.nodes(data=True) if data.get('importance', 0) > 0.8 and data.get('risk_score', 0) > 0.5]
                            }
                        }
                    },
                    'centrality': self.enhanced_network_centrality_analysis(),
                    'communities': self.advanced_community_detection(),
                    'metrics': self.calculate_comprehensive_network_metrics(),
                    'visualization': {
                        'interactive': self.create_interactive_network_visualization(),
                        'dashboards': self.create_analytical_dashboards()
                    },
                    'security_assessment': self._perform_security_assessment(),
                    'performance_metrics': {
                        'analysis_time': datetime.now().isoformat(),
                        'graph_complexity': self._calculate_graph_complexity(),
                        'processing_efficiency': self._calculate_processing_efficiency()
                    }
                }
                results = self.analysis_results
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self.print_log(f"Ağ analizi tamamlandı: {duration:.2f} saniye", "SUCCESS")
            self.print_log(f"İşlenen düğüm: {self.graph.number_of_nodes()}, kenar: {self.graph.number_of_edges()}", "INFO")
            
            return results
            
        except Exception as e:
            self.print_log(f"Analiz çalıştırma hatası: {e}", "ERROR")
            return {}
        
    def generate_comprehensive_report(self) -> str:
        """Kapsamlı rapor oluştur"""
        if not self.analysis_results:
            return "Henüz ağ analizi yapılmadı"
            
        metrics = self.analysis_results.get('metrics', {})
        basic_metrics = metrics.get('basic_metrics', {})
        centrality = self.analysis_results.get('centrality', {})
        communities = self.analysis_results.get('communities', {})
        security = self.analysis_results.get('security_assessment', {})
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    COUNCIL MESH ELITE RAPORU v{self.version}                    ║
║                     REDHACK GELİŞMİŞ AĞ ANALİZ SİSTEMİ                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  AĞ TOPOLOJİSİ VE GÜVENLİK ANALİZİ                                          ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣

TEMEL METRİKLER:
────────────────
• Düğüm Sayısı: {basic_metrics.get('number_of_nodes', 0):,}
• Kenar Sayısı: {basic_metrics.get('number_of_edges', 0):,}
• Ağ Yoğunluğu: {basic_metrics.get('density', 0):.4f}
• Ortalama Derece: {basic_metrics.get('average_degree', 0):.2f}
• Maksimum Derece: {basic_metrics.get('max_degree', 0)}
• Derece Varyansı: {basic_metrics.get('degree_variance', 0):.2f}

GÜVENLİK DURUMU:
────────────────
• Tehdit Seviyesi: {security.get('threat_level', 'UNKNOWN')}
• Kritik Açıklıklar: {len(security.get('critical_vulnerabilities', []))}
• Yüksek Risk Düğümleri: {metrics.get('security_metrics', {}).get('high_risk_nodes', 0)}
• Ortalama Risk Skoru: {metrics.get('security_metrics', {}).get('average_risk_score', 0):.3f}

MERKEZİLİK ANALİZİ:
───────────────────"""

        if centrality.get('top_nodes'):
            degree_top = centrality['top_nodes'].get('degree_centrality', [])
            if degree_top:
                report += "\n• En Merkezi Düğümler (Degree):"
                for i, node_info in enumerate(degree_top[:3], 1):
                    report += f"\n  {i}. {node_info['node'][:40]}... ({node_info['type']}): {node_info['score']:.4f}"
                    
            betweenness_top = centrality['top_nodes'].get('betweenness_centrality', [])
            if betweenness_top:
                report += "\n\n• En Aradalığı Yüksek Düğümler:"
                for i, node_info in enumerate(betweenness_top[:3], 1):
                    report += f"\n  {i}. {node_info['node'][:40]}... ({node_info['type']}): {node_info['score']:.4f}"
                    
            pagerank_top = centrality['top_nodes'].get('pagerank', [])
            if pagerank_top:
                report += "\n\n• PageRank Değeri Yüksek Düğümler:"
                for i, node_info in enumerate(pagerank_top[:3], 1):
                    report += f"\n  {i}. {node_info['node'][:40]}... ({node_info['type']}): {node_info['score']:.4f}"

        louvain_data = communities.get('louvain', {})
        report += f"\n\nTOPLULUK YAPISI:"
        report += f"\n────────────────"
        report += f"\n• Tespit Edilen Topluluk Sayısı: {louvain_data.get('total_communities', 0)}"
        report += f"\n• Modularity Skoru: {louvain_data.get('modularity', 0):.4f}"
        
        if louvain_data.get('statistics'):
            comm_stats = louvain_data['statistics']
            if comm_stats:
                largest_comm = max(comm_stats.items(), key=lambda x: x[1]['size']) 
                report += f"\n• En Büyük Topluluk: {largest_comm[1]['size']} düğüm"
                report += f"\n• Ortalama Topluluk Riski: {np.mean([stats['avg_risk_score'] for stats in comm_stats.values()]):.3f}"

        # Bağlantı metrikleri
        conn_metrics = metrics.get('connectivity_metrics', {})
        report += f"\n\nBAĞLANTI ANALİZİ:"
        report += f"\n────────────────"
        if conn_metrics.get('is_connected'):
            report += f"\n• Ağ Bağlantısı: Tamamen Bağlı"
            report += f"\n• Çap (Diameter): {conn_metrics.get('diameter', 'N/A')}"
            report += f"\n• Ortalama Kısa Yol: {conn_metrics.get('average_shortest_path', 0):.3f}"
        else:
            report += f"\n• Ağ Bağlantısı: Parçalı ({conn_metrics.get('connected_components', 0)} bileşen)"
            report += f"\n• En Büyük Bileşen: {conn_metrics.get('largest_component_size', 0)} düğüm"
            report += f"\n• Bileşen Oranı: {conn_metrics.get('largest_component_ratio', 0):.1%}"

        # Kümeleme metrikleri
        clustering_metrics = metrics.get('clustering_metrics', {})
        report += f"\n\nKÜMELEME ANALİZİ:"
        report += f"\n────────────────"
        report += f"\n• Ortalama Kümeleme Katsayısı: {clustering_metrics.get('average_clustering', 0):.4f}"
        report += f"\n• Transitivity: {clustering_metrics.get('transitivity', 0):.4f}"

        # Kritik güvenlik uyarıları
        critical_vulns = security.get('critical_vulnerabilities', [])
        if critical_vulns:
            report += f"\n\n🚨 KRİTİK GÜVENLİK UYARILARI:"
            report += f"\n────────────────────────────"
            for i, vuln in enumerate(critical_vulns[:5], 1):
                report += f"\n{i}. {vuln['node'][:50]}... - Risk: {vuln['risk_score']:.3f} - Seviye: {vuln['threat_level']}"

        # Performans metrikleri
        perf_metrics = self.analysis_results.get('performance_metrics', {})
        report += f"\n\nPERFORMANS METRİKLERİ:"
        report += f"\n─────────────────────"
        report += f"\n• Analiz Derinliği: {perf_metrics.get('processing_efficiency', {}).get('analysis_depth', 'UNKNOWN')}"
        report += f"\n• Optimizasyon Seviyesi: {perf_metrics.get('processing_efficiency', {}).get('optimization_level', 'UNKNOWN')}"
        
        complexity = perf_metrics.get('graph_complexity', {})
        if complexity:
            report += f"\n• Ağ Karmaşıklık Skoru: {complexity.get('overall_complexity', 0):.3f}"

        report += f"\n\n╔══════════════════════════════════════════════════════════════════════════════╗"
        report += f"\n║                         RAPOR SONU - {datetime.now().strftime('%Y-%m-%d %H:%M')}                       ║"
        report += f"\n╚══════════════════════════════════════════════════════════════════════════════╝"
            
        return report

    def report(self) -> str:
        """Rapor oluşturma için alias"""
        return self.generate_comprehensive_report()

    def export_analysis_data(self, format: str = 'json') -> str:
        """Analiz verilerini dışa aktar"""
        try:
            if format.lower() == 'json':
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"council_mesh_analysis_{timestamp}.json"
                
                export_data = {
                    'metadata': {
                        'version': self.version,
                        'export_time': datetime.now().isoformat(),
                        'security_level': self.security_level,
                        'total_nodes': self.graph.number_of_nodes(),
                        'total_edges': self.graph.number_of_edges()
                    },
                    'analysis_results': self.analysis_results
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                    
                self.print_log(f"Analiz verileri dışa aktarıldı: {filename}", "SUCCESS")
                return filename
                
            else:
                self.print_log(f"Desteklenmeyen format: {format}", "WARNING")
                return ""
                
        except Exception as e:
            self.print_log(f"Dışa aktarma hatası: {e}", "ERROR")
            return ""

# Gelişmiş test ve demo fonksiyonu
def demonstrate_council_mesh():
    """Council Mesh demo fonksiyonu"""
    print("🔍 Council Mesh v3.0 - Gelişmiş Ağ Analiz Sistemi")
    print("=" * 60)
    
    # Örnek OSINT verisi
    sample_osint = {
        'domain': 'example.com',
        'ip_info': {
            'ip': '192.168.1.1',
            'geolocation': {'city': 'Istanbul', 'country': 'TR'},
            'asn': 'AS12345',
            'org': 'Example Hosting'
        },
        'subdomains': {
            'subdomains': [
                {'subdomain': 'api.example.com', 'ip': '192.168.1.2', 'open_ports': [80, 443]},
                {'subdomain': 'admin.example.com', 'ip': '192.168.1.3', 'open_ports': [22, 3389]}
            ]
        },
        'dns': {
            'A': ['192.168.1.1', '192.168.1.2'],
            'MX': ['mail.example.com'],
            'TXT': ['v=spf1 include:_spf.example.com ~all']
        },
        'social_media': {
            'twitter': [
                {'username': 'example_ceo', 'confidence': 0.8, 'followers': 1500, 'activity': 'high'}
            ]
        },
        'whois': {
            'name_servers': ['ns1.example.com', 'ns2.example.com'],
            'registrar': 'Example Registrar Inc.'
        }
    }
    
    # Council Mesh örneği oluştur
    mesh = CouncilMesh()
    
    # Analiz çalıştır
    print("🚀 Analiz başlatılıyor...")
    results = mesh.run(sample_osint, parallel=True)
    
    # Rapor oluştur
    print("📊 Rapor oluşturuluyor...")
    report = mesh.report()
    print(report)
    
    # Dışa aktar
    print("💾 Veriler dışa aktarılıyor...")
    export_file = mesh.export_analysis_data('json')
    if export_file:
        print(f"✅ Analiz verileri kaydedildi: {export_file}")
    
    print("🎉 Council Mesh demo tamamlandı!")

if __name__ == "__main__":
    demonstrate_council_mesh()