import whois
import socket
import requests
import dns.resolver
import json
from urllib.parse import urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time
import ssl
import http.client
import urllib3
from bs4 import BeautifulSoup
import re
import dns.reversename
import ipwhois
import shodan
import warnings
import asyncio
import aiohttp
from typing import Dict, Any, List

warnings.filterwarnings('ignore')

# SSL uyarılarını kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SentinelNode:
    def __init__(self, shodan_api_key: str = None):
        self.name = "SentinelNode"
        self.version = "2.0"
        self.results = {}
        self.timeout = 10
        self.max_workers = 15
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # API anahtarları
        self.shodan_api_key = shodan_api_key
        if shodan_api_key:
            try:
                self.shodan_client = shodan.Shodan(shodan_api_key)
            except:
                self.shodan_client = None
        else:
            self.shodan_client = None
            
        self.social_media_patterns = {
            'twitter': [r'twitter\.com/([a-zA-Z0-9_]+)', r'x\.com/([a-zA-Z0-9_]+)'],
            'facebook': [r'facebook\.com/([a-zA-Z0-9\.]+)', r'fb\.com/([a-zA-Z0-9\.]+)'],
            'linkedin': [r'linkedin\.com/(in|company)/([a-zA-Z0-9\-]+)'],
            'instagram': [r'instagram\.com/([a-zA-Z0-9\._]+)'],
            'github': [r'github\.com/([a-zA-Z0-9\-]+)'],
            'youtube': [r'youtube\.com/(user|channel)/([a-zA-Z0-9\-]+)'],
            'reddit': [r'reddit\.com/user/([a-zA-Z0-9_]+)']
        }
        
        # CVE Database - Genişletilmiş Yerel CVE Eşleştirmeleri
        self.cve_database = {
            'nginx': {
                'patterns': [r'nginx/(\d+\.\d+\.\d+)', r'nginx/(\d+\.\d+)'],
                'cves': {
                    '1.18.0': ['CVE-2021-23017', 'CVE-2020-12400'],
                    '1.16.0': ['CVE-2019-20372', 'CVE-2018-16843'],
                    '1.14.0': ['CVE-2018-16844', 'CVE-2018-16845'],
                    'default': ['CVE-2021-23017', 'CVE-2018-16845']
                }
            },
            'apache': {
                'patterns': [r'Apache/(\d+\.\d+\.\d+)', r'Apache/(\d+\.\d+)', r'httpd/(\d+\.\d+\.\d+)'],
                'cves': {
                    '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                    '2.4.50': ['CVE-2021-42013'],
                    '2.4.46': ['CVE-2020-11984', 'CVE-2020-11993'],
                    'default': ['CVE-2021-41773', 'CVE-2021-42013']
                }
            },
            'ssh': {
                'patterns': [r'SSH-2.0-OpenSSH_(\d+\.\d+)', r'OpenSSH_(\d+\.\d+)'],
                'cves': {
                    '8.0': ['CVE-2021-28041'],
                    '7.9': ['CVE-2020-15778'],
                    '7.7': ['CVE-2019-6111'],
                    'default': ['CVE-2020-15778', 'CVE-2019-6111']
                }
            },
            'ftp': {
                'patterns': [r'220.*vsFTPd (\d+\.\d+\.\d+)', r'220.*ProFTPD (\d+\.\d+\.\d+)'],
                'cves': {
                    'vsftpd': ['CVE-2011-0762'],
                    'proftpd': ['CVE-2015-0296'],
                    'default': ['CVE-2011-0762']
                }
            },
            'mysql': {
                'patterns': [r'(\d+\.\d+\.\d+)-MySQL', r'mysql.*(\d+\.\d+\.\d+)'],
                'cves': {
                    '8.0.0': ['CVE-2021-22946'],
                    '5.7.0': ['CVE-2020-14812'],
                    'default': ['CVE-2021-22946']
                }
            },
            'iis': {
                'patterns': [r'Microsoft-IIS/(\d+\.\d+)', r'IIS/(\d+\.\d+)'],
                'cves': {
                    '10.0': ['CVE-2021-31166'],
                    '8.5': ['CVE-2020-0645'],
                    'default': ['CVE-2021-31166']
                }
            }
        }
        
    def print_log(self, message: str, level: str = "INFO"):
        """Geliştirilmiş log sistemi"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{self.name}] [{level}] {message}")
        
    async def async_port_scan(self, target: str, ports: List[int], timeout: float = 1.0) -> Dict[str, Any]:
        """Asenkron port tarama ve servis tespiti"""
        self.print_log(f"Async port tarama başlatıldı: {target} - Portlar: {len(ports)}")
        
        async def scan_port(port: int) -> Dict[str, Any]:
            """Tek bir portu tara"""
            try:
                # TCP Connect
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout
                )
                
                # Port açık, banner al
                banner = await self.banner_grab(reader, writer, target, port, timeout)
                
                # Servis ve versiyon tespiti
                service_info = self.detect_service_version(banner, port)
                
                # CVE taraması
                cve_list = self.scan_cves(service_info['service'], service_info['version'])
                
                writer.close()
                await writer.wait_closed()
                
                return {
                    'port': port,
                    'state': 'open',
                    'banner': banner[:512] if banner else '',
                    'service': service_info['service'],
                    'version': service_info['version'],
                    'cves': cve_list,
                    'confidence': service_info['confidence']
                }
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return {'port': port, 'state': 'closed'}
            except Exception as e:
                self.print_log(f"Port {port} tarama hatası: {e}", "ERROR")
                return {'port': port, 'state': 'error', 'error': str(e)}
        
        # Tüm portları paralel tara
        tasks = [scan_port(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Sonuçları işle
        open_ports = []
        closed_ports = 0
        error_ports = 0
        
        for result in results:
            if isinstance(result, Exception):
                error_ports += 1
                continue
                
            if result['state'] == 'open':
                open_ports.append(result)
            elif result['state'] == 'closed':
                closed_ports += 1
            else:
                error_ports += 1
        
        return {
            'target': target,
            'total_ports': len(ports),
            'open_ports': len(open_ports),
            'closed_ports': closed_ports,
            'error_ports': error_ports,
            'port_details': open_ports,
            'scan_timestamp': datetime.now().isoformat(),
            'scan_duration': f"{timeout}s per port"
        }
    
    async def banner_grab(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                         host: str, port: int, timeout: float) -> str:
        """Banner grab işlemi"""
        try:
            # Bazı servisler için özel probe'lar
            if port in [80, 443, 8080, 8443]:
                # HTTP/HTTPS için HEAD isteği
                probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {self.user_agent}\r\n\r\n"
                writer.write(probe.encode())
                await writer.drain()
            elif port == 21:
                # FTP için basit bağlantı
                pass  # FTP genellikle banner'ı otomatik gönderir
            elif port == 22:
                # SSH için versiyon bilgisi
                pass  # SSH otomatik banner gönderir
            elif port == 25:
                # SMTP için EHLO
                probe = "EHLO example.com\r\n"
                writer.write(probe.encode())
                await writer.drain()
            elif port == 3306:
                # MySQL için basit bağlantı
                pass
            
            # Banner'ı oku
            banner = await asyncio.wait_for(reader.read(512), timeout=0.5)
            return banner.decode('utf-8', errors='ignore')
            
        except Exception as e:
            self.print_log(f"Banner grab hatası ({host}:{port}): {e}", "DEBUG")
            return ""
    
    def detect_service_version(self, banner: str, port: int) -> Dict[str, Any]:
        """Banner'dan servis ve versiyon tespiti"""
        banner_lower = banner.lower()
        
        # Port bazlı varsayılan servisler
        default_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 
            993: 'imaps', 995: 'pop3s', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis'
        }
        
        service = default_services.get(port, 'unknown')
        version = 'unknown'
        confidence = 'low'
        
        # Nginx tespiti
        nginx_match = re.search(r'nginx/(\d+\.\d+\.\d+)', banner, re.IGNORECASE)
        if nginx_match:
            service = 'nginx'
            version = nginx_match.group(1)
            confidence = 'high'
            return {'service': service, 'version': version, 'confidence': confidence}
        
        # Apache tespiti
        apache_match = re.search(r'Apache/(\d+\.\d+\.\d+)', banner, re.IGNORECASE)
        if apache_match:
            service = 'apache'
            version = apache_match.group(1)
            confidence = 'high'
            return {'service': service, 'version': version, 'confidence': confidence}
        
        # IIS tespiti
        iis_match = re.search(r'Microsoft-IIS/(\d+\.\d+)', banner, re.IGNORECASE)
        if iis_match:
            service = 'iis'
            version = iis_match.group(1)
            confidence = 'high'
            return {'service': service, 'version': version, 'confidence': confidence}
        
        # SSH tespiti
        ssh_match = re.search(r'SSH-2.0-OpenSSH_(\d+\.\d+)', banner)
        if ssh_match:
            service = 'ssh'
            version = ssh_match.group(1)
            confidence = 'high'
            return {'service': service, 'version': version, 'confidence': confidence}
        
        # FTP tespiti
        ftp_match = re.search(r'220.*(vsFTPd|ProFTPD)\s+(\d+\.\d+\.\d+)', banner, re.IGNORECASE)
        if ftp_match:
            service = 'ftp'
            version = ftp_match.group(2)
            confidence = 'medium'
            return {'service': service, 'version': version, 'confidence': confidence}
        
        # MySQL tespiti
        mysql_match = re.search(r'(\d+\.\d+\.\d+).*MySQL', banner, re.IGNORECASE)
        if mysql_match:
            service = 'mysql'
            version = mysql_match.group(1)
            confidence = 'medium'
            return {'service': service, 'version': version, 'confidence': confidence}
        
        # HTTP Server header tespiti
        server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
        if server_match:
            server_header = server_match.group(1)
            service = server_header.split('/')[0].lower() if '/' in server_header else server_header.lower()
            confidence = 'medium'
            
            # Versiyon çıkarmaya çalış
            version_match = re.search(r'/(\d+\.\d+(\.\d+)?)', server_header)
            if version_match:
                version = version_match.group(1)
        
        return {'service': service, 'version': version, 'confidence': confidence}
    
    def scan_cves(self, service: str, version: str) -> List[str]:
        """Servis ve versiyon için CVE taraması"""
        if service == 'unknown' or version == 'unknown':
            return []
        
        cves = []
        service_lower = service.lower()
        
        # Servis için CVE veritabanını kontrol et
        for service_name, service_data in self.cve_database.items():
            if service_name in service_lower:
                # Versiyon için pattern eşleştirme
                for pattern in service_data['patterns']:
                    version_match = re.search(pattern, version)
                    if version_match:
                        detected_version = version_match.group(1)
                        
                        # Tam versiyon eşleşmesi
                        if detected_version in service_data['cves']:
                            cves.extend(service_data['cves'][detected_version])
                        # Varsayılan CVE'ler
                        elif 'default' in service_data['cves']:
                            cves.extend(service_data['cves']['default'])
                        
                        break
        
        # Benzersiz CVE'leri döndür
        return list(set(cves))
    
    def enhanced_whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Gelişmiş WHOIS sorgusu"""
        try:
            self.print_log(f"WHOIS sorgusu yapılıyor: {domain}")
            w = whois.whois(domain)
            
            # WHOIS verilerini temizle ve düzenle
            whois_data = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': list(w.name_servers) if w.name_servers else [],
                'status': w.status,
                'emails': w.emails if w.emails else [],
                'dnssec': w.dnssec,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'country': w.country
            }
            
            # None değerleri temizle
            whois_data = {k: v for k, v in whois_data.items() if v is not None}
            
            return whois_data
        except Exception as e:
            self.print_log(f"WHOIS hatası: {e}", "ERROR")
            return {'error': str(e)}
            
    def comprehensive_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Kapsamlı DNS sorgulama"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
                self.print_log(f"DNS {record_type} kaydı bulundu: {len(records[record_type])} adet")
            except Exception as e:
                records[record_type] = []
                
        # DNS güvenlik kayıtları
        try:
            # SPF kaydı kontrolü
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = [r for r in answers if 'v=spf1' in str(r)]
            records['SPF'] = [str(r) for r in spf_records]
        except:
            records['SPF'] = []
            
        try:
            # DMARC kaydı
            answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            records['DMARC'] = [str(r) for r in answers]
        except:
            records['DMARC'] = []
            
        try:
            # DKIM kaydı (common selectors)
            dkim_selectors = ['default', 'google', 'selector1', 'selector2']
            records['DKIM'] = {}
            for selector in dkim_selectors:
                try:
                    answers = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                    records['DKIM'][selector] = [str(r) for r in answers]
                except:
                    records['DKIM'][selector] = []
        except Exception as e:
            records['DKIM'] = {'error': str(e)}
            
        return records
        
    def advanced_subdomain_scan(self, domain: str) -> Dict[str, Any]:
        """Gelişmiş subdomain taraması"""
        self.print_log(f"Subdomain taraması başlatıldı: {domain}")
        
        # Genişletilmiş subdomain listesi
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover'
        ]
        
        found_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                # IP çözümleme
                ip = socket.gethostbyname(full_domain)
                
                # Port tarama (temel portlar)
                open_ports = []
                for port in [80, 443, 21, 22, 25, 53]:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    except:
                        pass
                
                found_subdomains.append({
                    'subdomain': full_domain,
                    'ip': ip,
                    'open_ports': open_ports,
                    'status': 'active'
                })
                
                return full_domain, ip, open_ports
                
            except Exception as e:
                return full_domain, None, []
                
        # Paralel tarama
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, subdomain): subdomain 
                for subdomain in common_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    results.append(result)
        
        return {
            'total_found': len(found_subdomains),
            'subdomains': found_subdomains,
            'scan_timestamp': datetime.now().isoformat()
        }
        
    def enhanced_ip_geolocation(self, domain: str) -> Dict[str, Any]:
        """Gelişmiş IP ve coğrafi konum analizi"""
        try:
            ip = socket.gethostbyname(domain)
            
            # IP API ile coğrafi konum
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=self.timeout)
            ipapi_data = response.json()
            
            # IPWhois ile ASN bilgisi
            ipwhois_data = {}
            try:
                obj = ipwhois.IPWhois(ip)
                ipwhois_data = obj.lookup_rdap()
            except:
                pass
                
            # Shodan entegrasyonu
            shodan_data = {}
            if self.shodan_client:
                try:
                    shodan_data = self.shodan_client.host(ip)
                except:
                    pass
            
            return {
                'ip': ip,
                'geolocation': {
                    'country': ipapi_data.get('country'),
                    'country_code': ipapi_data.get('countryCode'),
                    'region': ipapi_data.get('regionName'),
                    'city': ipapi_data.get('city'),
                    'zip': ipapi_data.get('zip'),
                    'lat': ipapi_data.get('lat'),
                    'lon': ipapi_data.get('lon'),
                    'timezone': ipapi_data.get('timezone'),
                    'isp': ipapi_data.get('isp'),
                    'org': ipapi_data.get('org'),
                    'as': ipapi_data.get('as')
                },
                'ipwhois': {
                    'asn': ipwhois_data.get('asn'),
                    'asn_description': ipwhois_data.get('asn_description'),
                    'network': ipwhois_data.get('network')
                } if ipwhois_data else {},
                'shodan': shodan_data if shodan_data else {}
            }
        except Exception as e:
            self.print_log(f"IP geolocation hatası: {e}", "ERROR")
            return {'error': str(e)}
            
    def advanced_social_media_discovery(self, domain: str) -> Dict[str, Any]:
        """Gelişmiş sosyal medya keşfi"""
        self.print_log("Sosyal medya keşfi başlatıldı")
        found_accounts = {}
        
        try:
            # Web sayfası içeriğini al
            headers = {'User-Agent': self.user_agent}
            response = requests.get(f"https://{domain}", headers=headers, timeout=self.timeout, verify=False)
            content = response.text.lower()
            
            # Sosyal medya pattern'lerini tarama
            for platform, patterns in self.social_media_patterns.items():
                found_accounts[platform] = []
                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if isinstance(match, tuple):
                            username = match[1] if len(match) > 1 else match[0]
                        else:
                            username = match
                            
                        if username and len(username) > 1:
                            account_url = f"https://{pattern.split('(')[0]}{username}"
                            found_accounts[platform].append({
                                'username': username,
                                'url': account_url,
                                'confidence': 'high' if platform in ['github', 'linkedin'] else 'medium'
                            })
            
            # Meta tag'lerden sosyal medya linklerini çıkar
            soup = BeautifulSoup(content, 'html.parser')
            meta_tags = soup.find_all('meta')
            
            for meta in meta_tags:
                content_val = meta.get('content', '')
                if any(social in content_val for social in ['twitter', 'facebook', 'instagram', 'linkedin']):
                    platform = None
                    if 'twitter' in content_val:
                        platform = 'twitter'
                    elif 'facebook' in content_val:
                        platform = 'facebook'
                    elif 'instagram' in content_val:
                        platform = 'instagram'
                    elif 'linkedin' in content_val:
                        platform = 'linkedin'
                        
                    if platform and platform not in found_accounts:
                        found_accounts[platform] = []
                        
            # Temizleme: duplicate'ları kaldır
            for platform in found_accounts:
                unique_accounts = []
                seen = set()
                for account in found_accounts[platform]:
                    if account['username'] not in seen:
                        seen.add(account['username'])
                        unique_accounts.append(account)
                found_accounts[platform] = unique_accounts
                
        except Exception as e:
            self.print_log(f"Sosyal medya keşif hatası: {e}", "ERROR")
            
        return found_accounts
        
    def ssl_certificate_analysis(self, domain: str) -> Dict[str, Any]:
        """SSL sertifika analizi"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Sertifika detayları
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName', []),
                        'OCSP': cert.get('OCSP', []),
                        'caIssuers': cert.get('caIssuers', [])
                    }
                    
                    # Sertifika geçerlilik süresi
                    from datetime import datetime
                    not_after = cert['notAfter']
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    cert_info['days_until_expiry'] = days_until_expiry
                    cert_info['is_expired'] = days_until_expiry < 0
                    cert_info['expiry_status'] = 'expired' if days_until_expiry < 0 else 'valid'
                    
                    return cert_info
                    
        except Exception as e:
            self.print_log(f"SSL analiz hatası: {e}", "ERROR")
            return {'error': str(e)}
            
    def http_security_headers_check(self, domain: str) -> Dict[str, Any]:
        """HTTP güvenlik başlıkları kontrolü"""
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(f"https://{domain}", headers=headers, timeout=self.timeout, verify=False)
            
            security_headers = {
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'Referrer-Policy': response.headers.get('Referrer-Policy'),
                'Permissions-Policy': response.headers.get('Permissions-Policy'),
                'Server': response.headers.get('Server')
            }
            
            # Güvenlik skoru hesapla
            security_score = 0
            max_score = 8
            
            if security_headers['Content-Security-Policy']:
                security_score += 1
            if security_headers['X-Frame-Options']:
                security_score += 1
            if security_headers['X-Content-Type-Options']:
                security_score += 1
            if security_headers['Strict-Transport-Security']:
                security_score += 1
            if security_headers['X-XSS-Protection']:
                security_score += 1
            if security_headers['Referrer-Policy']:
                security_score += 1
            if security_headers['Permissions-Policy']:
                security_score += 1
            if 'nginx' not in str(security_headers['Server']).lower():
                security_score += 1
                
            security_headers['security_score'] = f"{security_score}/{max_score}"
            security_headers['security_percentage'] = (security_score / max_score) * 100
            
            return security_headers
            
        except Exception as e:
            self.print_log(f"Güvenlik başlıkları kontrol hatası: {e}", "ERROR")
            return {'error': str(e)}
            
    def run(self, target: str) -> Dict[str, Any]:
        """Ana çalıştırma metodu"""
        self.print_log(f"Gelişmiş OSINT analizi başlatıldı: {target}")
        start_time = time.time()
        
        # Hedefi domain formatına çevir
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
            
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        
        # Port tarama için IP adresini al
        try:
            ip_address = socket.gethostbyname(domain)
            
            # Kritik port listesi
            critical_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                             445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
            
            # Async port tarama
            self.print_log("Async port tarama başlatılıyor...")
            port_scan_results = asyncio.run(self.async_port_scan(ip_address, critical_ports, timeout=1.0))
            
        except Exception as e:
            self.print_log(f"Port tarama hatası: {e}", "ERROR")
            port_scan_results = {'error': str(e)}
        
        self.results = {
            'target': target,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'analysis_duration': 0,
            'whois': self.enhanced_whois_lookup(domain),
            'dns': self.comprehensive_dns_enumeration(domain),
            'subdomains': self.advanced_subdomain_scan(domain),
            'ip_info': self.enhanced_ip_geolocation(domain),
            'social_media': self.advanced_social_media_discovery(domain),
            'ssl_certificate': self.ssl_certificate_analysis(domain),
            'security_headers': self.http_security_headers_check(domain),
            'port_scan': port_scan_results
        }
        
        # Analiz süresi
        self.results['analysis_duration'] = time.time() - start_time
        
        self.print_log(f"OSINT analizi tamamlandı. Süre: {self.results['analysis_duration']:.2f}s")
        
        return self.results
        
    def report(self) -> str:
        """Detaylı rapor oluştur"""
        if not self.results:
            return "Henüz analiz yapılmadı"
            
        # Port tarama sonuçlarını formatla
        port_scan_info = ""
        if 'port_scan' in self.results and 'error' not in self.results['port_scan']:
            port_data = self.results['port_scan']
            port_scan_info = f"""
Port Tarama Sonuçları:
- Taranan Port: {port_data.get('total_ports', 0)}
- Açık Port: {port_data.get('open_ports', 0)}
- Kapalı Port: {port_data.get('closed_ports', 0)}
- Hata: {port_data.get('error_ports', 0)}

Açık Port Detayları:"""
            
            for port_detail in port_data.get('port_details', []):
                port_scan_info += f"""
  * Port {port_detail['port']}: {port_detail['service']} {port_detail['version']}
    - Banner: {port_detail.get('banner', '')[:100]}...
    - CVE'ler: {', '.join(port_detail.get('cves', [])) if port_detail.get('cves') else 'Bulunamadı'}
    - Güven: {port_detail.get('confidence', 'unknown')}"""
        
        report = f"""
SENTINEL NODE RAPORU v{self.version}
==================================
Hedef: {self.results['target']}
Domain: {self.results['domain']}
Analiz Zamanı: {self.results['timestamp']}
Analiz Süresi: {self.results['analysis_duration']:.2f} saniye

WHOIS Bilgileri:
- Registrar: {self.results['whois'].get('registrar', 'Bilinmiyor')}
- Oluşturulma: {self.results['whois'].get('creation_date', 'Bilinmiyor')}
- Son Geçerlilik: {self.results['whois'].get('expiration_date', 'Bilinmiyor')}
- Name Server'lar: {len(self.results['whois'].get('name_servers', []))} adet

DNS Analizi:
- A Kayıtları: {len(self.results['dns'].get('A', []))} bulundu
- MX Kayıtları: {len(self.results['dns'].get('MX', []))} bulundu
- TXT Kayıtları: {len(self.results['dns'].get('TXT', []))} bulundu
- SPF Kaydı: {'Var' if self.results['dns'].get('SPF') else 'Yok'}
- DMARC Kaydı: {'Var' if self.results['dns'].get('DMARC') else 'Yok'}

Subdomainler: {self.results['subdomains']['total_found']} aktif subdomain bulundu

IP ve Konum Bilgisi:
- IP: {self.results['ip_info'].get('ip', 'Bilinmiyor')}
- Ülke: {self.results['ip_info'].get('geolocation', {}).get('country', 'Bilinmiyor')}
- Şehir: {self.results['ip_info'].get('geolocation', {}).get('city', 'Bilinmiyor')}
- ISP: {self.results['ip_info'].get('geolocation', {}).get('isp', 'Bilinmiyor')}

Sosyal Medya Hesapları: {sum(len(accounts) for accounts in self.results['social_media'].values())} hesap bulundu

SSL Sertifikası:
- Durum: {self.results['ssl_certificate'].get('expiry_status', 'Bilinmiyor')}
- Son Geçerlilik: {self.results['ssl_certificate'].get('days_until_expiry', 'Bilinmiyor')} gün

Güvenlik Başlıkları Skoru: {self.results['security_headers'].get('security_score', 'Bilinmiyor')}

{port_scan_info}
"""
        return report