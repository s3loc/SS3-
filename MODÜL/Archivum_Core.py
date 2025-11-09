import hashlib
import json
from datetime import datetime
import os
import pickle
from cryptography.fernet import Fernet
import hmac
import zlib
import base64
from typing import Any, Dict, List, Optional

class ArchivumCore:
    def __init__(self, storage_path: str = "archives/"):
        self.name = "ArchivumCore"
        self.version = "2.0"
        self.archives = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.storage_path = storage_path
        self.compression_enabled = True
        
        # Storage dizinini oluştur
        os.makedirs(storage_path, exist_ok=True)
        
    def print_log(self, message: str, level: str = "INFO"):
        """Geliştirilmiş log sistemi"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{self.name}] [{level}] {message}")
        
    def generate_advanced_hash(self, data: Any) -> Dict[str, str]:
        """Gelişmiş hash algoritmaları"""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        elif not isinstance(data, str):
            data_str = str(data)
        else:
            data_str = data
            
        # Çoklu hash algoritması
        hash_results = {
            'md5': hashlib.md5(data_str.encode()).hexdigest(),
            'sha1': hashlib.sha1(data_str.encode()).hexdigest(),
            'sha256': hashlib.sha256(data_str.encode()).hexdigest(),
            'sha512': hashlib.sha512(data_str.encode()).hexdigest(),
            'blake2b': hashlib.blake2b(data_str.encode()).hexdigest(),
            'timestamp': datetime.now().isoformat(),
            'data_size': len(data_str)
        }
        
        return hash_results
        
    def compress_data(self, data: str) -> str:
        """Veri sıkıştırma"""
        if not self.compression_enabled:
            return data
            
        compressed = zlib.compress(data.encode())
        return base64.b64encode(compressed).decode()
        
    def decompress_data(self, compressed_data: str) -> str:
        """Sıkıştırılmış veriyi aç"""
        if not self.compression_enabled:
            return compressed_data
            
        compressed = base64.b64decode(compressed_data)
        return zlib.decompress(compressed).decode()
        
    def encrypt_data(self, data: str) -> str:
        """Güçlendirilmiş şifreleme"""
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return encrypted.decode()
        except Exception as e:
            self.print_log(f"Şifreleme hatası: {e}", "ERROR")
            return data
            
    def decrypt_data(self, encrypted_data: str) -> str:
        """Şifre çözme"""
        try:
            decrypted = self.cipher.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except Exception as e:
            self.print_log(f"Şifre çözme hatası: {e}", "ERROR")
            return encrypted_data
        
    def create_detailed_timestamp(self) -> Dict[str, Any]:
        """Detaylı zaman damgası"""
        now = datetime.now()
        return {
            'iso_format': now.isoformat(),
            'timestamp': now.timestamp(),
            'utc': datetime.utcnow().isoformat(),
            'human_readable': now.strftime("%Y-%m-%d %H:%M:%S"),
            'timezone': str(now.astimezone().tzinfo),
            'day_of_week': now.strftime("%A"),
            'week_number': now.isocalendar()[1]
        }
        
    def archive_data(self, data: Any, description: str = "", tags: List[str] = None, 
                    metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Gelişmiş veri arşivleme"""
        timestamp = self.create_detailed_timestamp()
        hashes = self.generate_advanced_hash(data)
        
        archive_id = f"ARC_{hashes['sha256'][:16]}_{int(timestamp['timestamp'])}"
        
        # Veriyi hazırla
        data_str = str(data)
        compressed_data = self.compress_data(data_str) if self.compression_enabled else data_str
        encrypted_data = self.encrypt_data(compressed_data)
        
        archive_entry = {
            'id': archive_id,
            'version': self.version,
            'timestamp': timestamp,
            'hashes': hashes,
            'description': description,
            'tags': tags or [],
            'metadata': metadata or {},
            'data_size_original': len(data_str),
            'data_size_compressed': len(compressed_data) if self.compression_enabled else len(data_str),
            'compression_ratio': len(compressed_data) / len(data_str) if self.compression_enabled else 1.0,
            'encrypted': encrypted_data,
            'compression_enabled': self.compression_enabled
        }
        
        # Bellekte sakla
        self.archives[archive_id] = archive_entry
        
        # Dosyaya yedekle
        self._save_to_disk(archive_id, archive_entry)
        
        self.print_log(f"Veri arşivlendi: {archive_id} - Boyut: {archive_entry['data_size_original']} byte")
        
        return archive_entry
        
    def _save_to_disk(self, archive_id: str, archive_entry: Dict[str, Any]):
        """Arşivi diske kaydet"""
        try:
            filename = f"{self.storage_path}{archive_id}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(archive_entry, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.print_log(f"Disk kayıt hatası: {e}", "ERROR")
            
    def verify_integrity(self, archive_id: str, original_data: Any = None) -> Dict[str, Any]:
        """Gelişmiş bütünlük doğrulama"""
        if archive_id not in self.archives:
            return {'valid': False, 'error': 'Archive not found'}
            
        archive_entry = self.archives[archive_id]
        verification_result = {
            'valid': True,
            'archive_id': archive_id,
            'checks': {}
        }
        
        # Hash doğrulama
        if original_data:
            current_hash = self.generate_advanced_hash(original_data)
            stored_hash = archive_entry['hashes']
            
            verification_result['checks']['hash_validation'] = {
                'sha256_match': current_hash['sha256'] == stored_hash['sha256'],
                'sha1_match': current_hash['sha1'] == stored_hash['sha1'],
                'md5_match': current_hash['md5'] == stored_hash['md5']
            }
            
            if not verification_result['checks']['hash_validation']['sha256_match']:
                verification_result['valid'] = False
                
        # Zaman damgası kontrolü
        try:
            archive_time = datetime.fromisoformat(archive_entry['timestamp']['iso_format'])
            time_diff = (datetime.now() - archive_time).total_seconds()
            verification_result['checks']['timestamp'] = {
                'archive_time': archive_entry['timestamp']['iso_format'],
                'time_diff_seconds': time_diff,
                'within_24h': time_diff < 86400
            }
        except Exception as e:
            verification_result['checks']['timestamp'] = {'error': str(e)}
            
        return verification_result
        
    def search_archives(self, query: str, search_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Arşivlerde arama"""
        if search_fields is None:
            search_fields = ['description', 'tags', 'id']
            
        results = []
        query_lower = query.lower()
        
        for archive_id, archive in self.archives.items():
            for field in search_fields:
                if field in archive:
                    field_value = archive[field]
                    if isinstance(field_value, list):
                        if any(query_lower in str(item).lower() for item in field_value):
                            results.append(archive)
                            break
                    elif query_lower in str(field_value).lower():
                        results.append(archive)
                        break
                        
        return results
        
    def run(self, data: Any) -> Dict[str, Any]:
        """Ana çalıştırma metodu"""
        self.print_log("Gelişmiş veri arşivleme başlatıldı")
        
        if isinstance(data, dict):
            for key, value in data.items():
                self.archive_data(
                    str(value), 
                    f"Sentinel Data - {key}",
                    tags=["sentinel", "automated", key.lower()],
                    metadata={'source': 'sentinel_node', 'data_type': type(value).__name__}
                )
        else:
            self.archive_data(
                data, 
                "OSINT Verisi",
                tags=["osint", "primary", "raw_data"],
                metadata={'source': 'direct_input', 'data_type': type(data).__name__}
            )
            
        return {
            'total_archives': len(self.archives),
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        }
        
    def report(self) -> str:
        """Detaylı rapor oluştur"""
        if not self.archives:
            return "Henüz arşivlenmiş veri yok"
            
        total_size = sum(arc['data_size_original'] for arc in self.archives.values())
        compressed_size = sum(arc['data_size_compressed'] for arc in self.archives.values())
        avg_compression = sum(arc['compression_ratio'] for arc in self.archives.values()) / len(self.archives)
        
        report = f"""
ARCHIVUM CORE RAPORU v{self.version}
====================================
Toplam Arşivlenmiş Veri: {len(self.archives)} kayıt
Toplam Boyut: {total_size} byte ({total_size/1024/1024:.2f} MB)
Sıkıştırılmış Boyut: {compressed_size} byte ({compressed_size/1024/1024:.2f} MB)
Ortalama Sıkıştırma Oranı: {avg_compression:.2%}

Son 10 Arşiv Kaydı:
"""
        for i, (archive_id, archive) in enumerate(list(self.archives.items())[-10:]):
            report += f"""
{i+1}. Kayıt ID: {archive_id}
   - Zaman: {archive['timestamp']['human_readable']}
   - Açıklama: {archive['description']}
   - SHA256: {archive['hashes']['sha256'][:32]}...
   - Boyut: {archive['data_size_original']} byte -> {archive['data_size_compressed']} byte
   - Etiketler: {', '.join(archive['tags'])}
   - Sıkıştırma: {archive['compression_ratio']:.2%}
"""

        return report

    def export_archive(self, archive_id: str, format: str = 'json') -> Optional[str]:
        """Arşivi dışa aktar"""
        if archive_id not in self.archives:
            return None
            
        archive = self.archives[archive_id]
        
        if format == 'json':
            return json.dumps(archive, indent=2, ensure_ascii=False)
        elif format == 'compact':
            return json.dumps(archive, separators=(',', ':'), ensure_ascii=False)
        else:
            return str(archive)