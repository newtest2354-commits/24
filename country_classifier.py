import os
import re
import json
import base64
import hashlib
import socket
import pickle
import threading
import concurrent.futures
import requests
from datetime import datetime
from urllib.parse import urlparse
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ConfigParser:
    def __init__(self):
        self.lock = threading.Lock()
        self.cdn_providers = {
            'cloudflare': ['.cloudflare.com', '.cloudflaressl.com'],
            'akamai': ['.akamai.net', '.akamaiedge.net', '.akamaihd.net'],
            'fastly': ['.fastly.net', '.fastlylb.net'],
            'aws': ['.amazonaws.com', '.cloudfront.net'],
            'azure': ['.azureedge.net', '.azurefd.net'],
            'google': ['.googleusercontent.com', '.gstatic.com', '.googlehosted.com']
        }
    
    def parse_vmess(self, config_str):
        try:
            base64_part = config_str[8:]
            if len(base64_part) % 4 != 0:
                base64_part += '=' * (4 - len(base64_part) % 4)
            config_data = json.loads(base64.b64decode(base64_part).decode('utf-8'))
            
            return {
                'protocol': 'vmess',
                'host': config_data.get('add', ''),
                'port': int(config_data.get('port', 0)),
                'sni': config_data.get('sni', '') or config_data.get('host', ''),
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse vmess: {e}")
            return None
    
    def parse_vless(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('?')[0]) if '?' in port_str else int(port_str)
            
            sni = ''
            params = parsed.query
            if params:
                for param in params.split('&'):
                    if param.startswith('sni='):
                        sni = param[4:]
                        break
            
            return {
                'protocol': 'vless',
                'host': host,
                'port': port,
                'sni': sni,
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse vless: {e}")
            return None
    
    def parse_trojan(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('#')[0]) if '#' in port_str else int(port_str)
            
            sni = ''
            params = parsed.query
            if params:
                for param in params.split('&'):
                    if param.startswith('sni='):
                        sni = param[4:]
                        break
            
            return {
                'protocol': 'trojan',
                'host': host,
                'port': port,
                'sni': sni,
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse trojan: {e}")
            return None
    
    def parse_ss(self, config_str):
        try:
            parts = config_str.split('#', 1)
            base_part = parts[0][5:]
            
            if '@' not in base_part:
                if len(base_part) % 4 != 0:
                    base_part += '=' * (4 - len(base_part) % 4)
                decoded = base64.b64decode(base_part).decode('utf-8')
                if '@' in decoded:
                    method_pass, server_part = decoded.split('@', 1)
                else:
                    return None
            else:
                encoded_method_pass, server_part = base_part.split('@', 1)
                
            server, port_str = server_part.split(':', 1)
            port = int(port_str)
            
            return {
                'protocol': 'ss',
                'host': server,
                'port': port,
                'sni': '',
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse ss: {e}")
            return None
    
    def parse_hysteria(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            return {
                'protocol': 'hysteria',
                'host': host,
                'port': port,
                'sni': '',
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse hysteria: {e}")
            return None
    
    def parse_tuic(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            return {
                'protocol': 'tuic',
                'host': host,
                'port': port,
                'sni': '',
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse tuic: {e}")
            return None
    
    def parse_wireguard(self, config_str):
        try:
            parsed = urlparse(config_str)
            params = parsed.query
            host = ''
            
            for param in params.split('&'):
                if param.startswith('address='):
                    host = param[8:].split(':')[0]
                    break
            
            return {
                'protocol': 'wireguard',
                'host': host,
                'port': 51820,
                'sni': '',
                'raw': config_str
            }
        except Exception as e:
            logger.debug(f"Failed to parse wireguard: {e}")
            return None
    
    def parse_config(self, config_str):
        config_str = config_str.strip()
        
        if config_str.startswith('vmess://'):
            return self.parse_vmess(config_str)
        elif config_str.startswith('vless://'):
            return self.parse_vless(config_str)
        elif config_str.startswith('trojan://'):
            return self.parse_trojan(config_str)
        elif config_str.startswith('ss://'):
            return self.parse_ss(config_str)
        elif config_str.startswith('hysteria://') or config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
            return self.parse_hysteria(config_str)
        elif config_str.startswith('tuic://'):
            return self.parse_tuic(config_str)
        elif config_str.startswith('wireguard://'):
            return self.parse_wireguard(config_str)
        
        return None
    
    def detect_cdn(self, domain):
        if not domain:
            return False, None
        
        domain_lower = domain.lower()
        for provider, patterns in self.cdn_providers.items():
            for pattern in patterns:
                if domain_lower.endswith(pattern):
                    return True, provider
        
        return False, None
    
    def extract_domain_info(self, parsed_config):
        target_domain = ''
        is_ip = False
        
        sni = parsed_config.get('sni', '')
        host = parsed_config.get('host', '')
        
        if sni:
            target_domain = sni
        elif host:
            target_domain = host
        
        if not target_domain:
            return '', False, False, None
        
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        is_ip = bool(re.match(ip_pattern, target_domain))
        
        if not is_ip and ':' in target_domain and not target_domain.startswith('['):
            is_ip = True
        
        is_cdn, cdn_provider = self.detect_cdn(target_domain)
        
        return target_domain, is_ip, is_cdn, cdn_provider

class DNSResolver:
    def __init__(self):
        self.cache = {}
        self.cache_file = 'dns_cache.pkl'
        self.lock = threading.Lock()
        self.load_cache()
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.cache = pickle.load(f)
        except:
            self.cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Failed to save DNS cache: {e}")
    
    def resolve(self, hostname, timeout=5.0):
        with self.lock:
            if hostname in self.cache:
                ips, timestamp = self.cache[hostname]
                if time.time() - timestamp < 3600:
                    return ips
        
        try:
            socket.setdefaulttimeout(timeout)
            
            if ':' in hostname and not hostname.startswith('['):
                results = socket.getaddrinfo(hostname, None, socket.AF_INET6)
                ips = [result[4][0] for result in results]
            else:
                ips = socket.gethostbyname_ex(hostname)[2]
            
            with self.lock:
                self.cache[hostname] = (ips, time.time())
            
            return ips
        except socket.gaierror:
            return []
        except socket.timeout:
            logger.debug(f"DNS resolution timeout for {hostname}")
            return []
        except Exception as e:
            logger.debug(f"DNS resolution failed for {hostname}: {e}")
            return []

class GeoIPClassifier:
    def __init__(self):
        self.db_path = 'GeoLite2-Country.mmdb'
        self.cache = {}
        self.cache_file = 'geoip_cache.pkl'
        self.lock = threading.Lock()
        self.load_cache()
        
        if not os.path.exists(self.db_path):
            self.download_geoip_db()
    
    def download_geoip_db(self):
        try:
            logger.info("Attempting to download GeoLite2 database...")
            
            urls = [
                "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
                "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
                "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
            ]
            
            for url in urls:
                try:
                    logger.info(f"Trying to download from: {url}")
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        with open(self.db_path, 'wb') as f:
                            f.write(response.content)
                        logger.info("GeoIP database downloaded successfully")
                        return
                except Exception as e:
                    logger.debug(f"Failed to download from {url}: {e}")
                    continue
            
            logger.warning("Could not download GeoIP database from any source")
            logger.warning("Country classification will use fallback method")
            
        except Exception as e:
            logger.error(f"Error downloading GeoIP database: {e}")
            logger.warning("Country classification will use fallback method")
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.cache = pickle.load(f)
        except:
            self.cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Failed to save GeoIP cache: {e}")
    
    def get_country_by_ipapi(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('countryCode', 'UNKNOWN')
        except:
            pass
        return "UNKNOWN"
    
    def get_country_fallback(self, ip):
        try:
            if ip.startswith('172.') or ip.startswith('10.') or ip.startswith('192.168.'):
                return "PRIVATE"
            
            if ':' in ip:
                return "IPV6"
                
            return "UNKNOWN"
        except:
            return "UNKNOWN"
    
    def get_country(self, ip):
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        
        country_code = "UNKNOWN"
        
        try:
            if os.path.exists(self.db_path):
                import geoip2.database
                
                with geoip2.database.Reader(self.db_path) as reader:
                    try:
                        response = reader.country(ip)
                        country_code = response.country.iso_code or "UNKNOWN"
                    except:
                        country_code = self.get_country_by_ipapi(ip)
            else:
                country_code = self.get_country_by_ipapi(ip)
                
        except ImportError:
            logger.warning("geoip2 not available, using ip-api.com")
            country_code = self.get_country_by_ipapi(ip)
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            country_code = self.get_country_fallback(ip)
        
        with self.lock:
            self.cache[ip] = country_code
        
        return country_code

class CountryClassifier:
    def __init__(self, max_workers=50):
        self.parser = ConfigParser()
        self.dns_resolver = DNSResolver()
        self.geoip = GeoIPClassifier()
        self.max_workers = max_workers
        self.results_lock = threading.Lock()
        self.results = {}
        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'by_country': {},
            'by_protocol': {},
            'cdn_count': 0,
            'domain_based': 0,
            'ip_based': 0
        }
    
    def get_country_by_domain_tld(self, domain):
        try:
            tld_patterns = {
                '.ir': 'IR',
                '.tr': 'TR',
                '.us': 'US',
                '.de': 'DE',
                '.fr': 'FR',
                '.uk': 'GB',
                '.ru': 'RU',
                '.cn': 'CN',
                '.jp': 'JP',
                '.kr': 'KR',
                '.in': 'IN',
                '.br': 'BR',
                '.ca': 'CA',
                '.au': 'AU',
                '.nl': 'NL',
                '.se': 'SE',
                '.ch': 'CH',
                '.sg': 'SG',
                '.hk': 'HK',
                '.tw': 'TW',
                '.ae': 'AE',
                '.sa': 'SA'
            }
            
            domain_lower = domain.lower()
            for tld, country_code in tld_patterns.items():
                if domain_lower.endswith(tld):
                    return country_code
            
            return "UNKNOWN"
        except:
            return "UNKNOWN"
    
    def process_single_config(self, config_str):
        try:
            parsed = self.parser.parse_config(config_str)
            if not parsed:
                return None
            
            target_domain, is_ip, is_cdn, cdn_provider = self.parser.extract_domain_info(parsed)
            
            if not target_domain:
                return None
            
            country = "UNKNOWN"
            classification_method = "UNKNOWN"
            
            if is_cdn:
                country = "CDN"
                classification_method = "CDN"
            elif is_ip:
                country = self.geoip.get_country(target_domain)
                classification_method = "IP"
            else:
                ips = self.dns_resolver.resolve(target_domain, timeout=3.0)
                if ips:
                    country = self.geoip.get_country(ips[0])
                    classification_method = "DNS_IP"
                else:
                    country = self.get_country_by_domain_tld(target_domain)
                    classification_method = "DOMAIN_TLD"
            
            return {
                'config': config_str,
                'parsed': parsed,
                'domain': target_domain,
                'is_ip': is_ip,
                'is_cdn': is_cdn,
                'cdn_provider': cdn_provider,
                'country': country,
                'classification_method': classification_method
            }
        except Exception as e:
            logger.debug(f"Failed to process config: {e}")
            return None
    
    def process_configs(self, configs):
        logger.info(f"Processing {len(configs)} configurations...")
        
        self.results = {}
        self.stats = {
            'total': len(configs),
            'success': 0,
            'failed': 0,
            'by_country': {},
            'by_protocol': {},
            'cdn_count': 0,
            'domain_based': 0,
            'ip_based': 0
        }
        
        unique_configs = []
        seen = set()
        
        for config in configs:
            config_hash = hashlib.md5(config.encode()).hexdigest()
            if config_hash not in seen:
                seen.add(config_hash)
                unique_configs.append(config)
        
        logger.info(f"After deduplication: {len(unique_configs)} unique configs")
        
        show_progress = len(unique_configs) <= 10000
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_config = {
                executor.submit(self.process_single_config, config): config 
                for config in unique_configs
            }
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_config):
                completed += 1
                if show_progress and completed % 100 == 0:
                    logger.info(f"Processed {completed}/{len(unique_configs)} configs")
                
                result = future.result()
                if result:
                    with self.results_lock:
                        self.stats['success'] += 1
                        
                        country = result['country']
                        protocol = result['parsed']['protocol']
                        method = result['classification_method']
                        
                        if country not in self.results:
                            self.results[country] = {}
                        
                        if protocol not in self.results[country]:
                            self.results[country][protocol] = []
                        
                        self.results[country][protocol].append(result['config'])
                        
                        self.stats['by_country'][country] = self.stats['by_country'].get(country, 0) + 1
                        self.stats['by_protocol'][protocol] = self.stats['by_protocol'].get(protocol, 0) + 1
                        
                        if result['is_cdn']:
                            self.stats['cdn_count'] += 1
                        
                        if method == "DOMAIN_TLD":
                            self.stats['domain_based'] += 1
                        elif method in ["IP", "DNS_IP"]:
                            self.stats['ip_based'] += 1
                else:
                    with self.results_lock:
                        self.stats['failed'] += 1
        
        self.dns_resolver.save_cache()
        self.geoip.save_cache()
        
        return {
            'results': self.results,
            'stats': self.stats
        }
    
    def save_results(self, results, output_dir='configs/country'):
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cdn_configs = []
        
        for country, protocols in results['results'].items():
            country_dir = os.path.join(output_dir, country)
            os.makedirs(country_dir, exist_ok=True)
            
            all_country_configs = []
            
            for protocol, configs in protocols.items():
                if configs:
                    protocol_file = os.path.join(country_dir, f"{protocol}.txt")
                    content = f"# {country} - {protocol.upper()} Configurations\n"
                    content += f"# Updated: {timestamp}\n"
                    content += f"# Count: {len(configs)}\n"
                    content += f"# Country Code: {country}\n\n"
                    content += "\n".join(configs)
                    
                    with open(protocol_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    all_country_configs.extend(configs)
                    
                    if country == "CDN":
                        cdn_configs.extend(configs)
            
            if all_country_configs:
                all_file = os.path.join(country_dir, "all.txt")
                content = f"# All Configurations for {country}\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_country_configs)}\n"
                content += f"# Country Code: {country}\n\n"
                content += "\n".join(all_country_configs)
                
                with open(all_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        if cdn_configs:
            cdn_dir = os.path.join(output_dir, "CDN")
            os.makedirs(cdn_dir, exist_ok=True)
            
            cdn_file = os.path.join(cdn_dir, "all.txt")
            content = f"# CDN Configurations\n"
            content += f"# Updated: {timestamp}\n"
            content += f"# Total Count: {len(cdn_configs)}\n"
            content += f"# Category: Content Delivery Networks\n\n"
            content += "\n".join(cdn_configs)
            
            with open(cdn_file, 'w', encoding='utf-8') as f:
                f.write(content)
        
        stats_file = os.path.join(output_dir, "stats.json")
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(results['stats'], f, indent=2)
        
        summary_file = os.path.join(output_dir, "summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# Country Classification Summary\n")
            f.write(f"# Updated: {timestamp}\n\n")
            f.write(f"Total configs processed: {results['stats']['total']}\n")
            f.write(f"Successfully classified: {results['stats']['success']}\n")
            f.write(f"Failed to classify: {results['stats']['failed']}\n")
            f.write(f"CDN configs: {results['stats']['cdn_count']}\n")
            f.write(f"IP-based classification: {results['stats']['ip_based']}\n")
            f.write(f"Domain-based classification: {results['stats']['domain_based']}\n\n")
            
            f.write("By Country:\n")
            for country, count in sorted(results['stats']['by_country'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {country}: {count}\n")
            
            f.write("\nBy Protocol:\n")
            for protocol, count in sorted(results['stats']['by_protocol'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {protocol}: {count}\n")
        
        logger.info(f"Results saved to {output_dir}")

def read_all_configs():
    configs = []
    
    combined_dir = 'configs/combined'
    if os.path.exists(combined_dir):
        for filename in os.listdir(combined_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(combined_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                configs.append(line)
                except Exception as e:
                    logger.error(f"Error reading {filepath}: {e}")
    
    if not configs:
        sources = [
            'configs/telegram/all.txt',
            'configs/github/all.txt',
            'configs/combined/all.txt'
        ]
        
        for filepath in sources:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                configs.append(line)
                except Exception as e:
                    logger.error(f"Error reading {filepath}: {e}")
    
    return configs

def main():
    print("=" * 60)
    print("COUNTRY CONFIG CLASSIFIER")
    print("=" * 60)
    
    try:
        configs = read_all_configs()
        if not configs:
            logger.error("No configurations found to process")
            return
        
        logger.info(f"Found {len(configs)} configurations")
        
        classifier = CountryClassifier(max_workers=30)
        start_time = time.time()
        
        results = classifier.process_configs(configs)
        
        elapsed_time = time.time() - start_time
        
        classifier.save_results(results)
        
        print(f"\n✅ CLASSIFICATION COMPLETE")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Total configs: {results['stats']['total']}")
        print(f"Successfully classified: {results['stats']['success']}")
        print(f"Failed: {results['stats']['failed']}")
        print(f"CDN configs: {results['stats']['cdn_count']}")
        print(f"IP-based: {results['stats']['ip_based']}")
        print(f"Domain-based: {results['stats']['domain_based']}")
        
        print(f"\n📊 Top Countries:")
        top_countries = sorted(
            results['stats']['by_country'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        for country, count in top_countries:
            print(f"  {country}: {count} configs")
        
        print(f"\n📁 Output saved to: configs/country/")
        print("=" * 60)
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()
