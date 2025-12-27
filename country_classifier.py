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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigParser:
    def __init__(self):
        self.lock = threading.Lock()
        self.cdn_domains = {
            'cloudflare': ['.cloudflare.com', '.cloudflaressl.com'],
            'akamai': ['.akamai.net', '.akamaiedge.net', '.akamaihd.net'],
            'fastly': ['.fastly.net', '.fastlylb.net'],
            'aws': ['.amazonaws.com', '.cloudfront.net'],
            'azure': ['.azureedge.net', '.azurefd.net'],
            'google': ['.googleusercontent.com', '.gstatic.com', '.googlehosted.com']
        }
        
        self.country_tlds = {
            '.ir': 'IR', '.tr': 'TR', '.ru': 'RU', '.de': 'DE', '.fr': 'FR',
            '.uk': 'GB', '.us': 'US', '.ca': 'CA', '.au': 'AU', '.jp': 'JP',
            '.kr': 'KR', '.cn': 'CN', '.in': 'IN', '.br': 'BR', '.mx': 'MX',
            '.it': 'IT', '.es': 'ES', '.nl': 'NL', '.se': 'SE', '.ch': 'CH',
            '.ae': 'AE', '.sa': 'SA', '.eg': 'EG', '.za': 'ZA', '.ar': 'AR',
            '.cl': 'CL', '.co': 'CO', '.pe': 'PE', '.ve': 'VE', '.id': 'ID',
            '.my': 'MY', '.th': 'TH', '.vn': 'VN', '.ph': 'PH', '.sg': 'SG'
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
        except:
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
        except:
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
        except:
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
        except:
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
        except:
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
        except:
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
        except:
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
    
    def get_tld_country(self, domain):
        for tld, country in self.country_tlds.items():
            if domain.lower().endswith(tld):
                return country
        return None
    
    def is_cdn_domain(self, domain):
        if not domain:
            return False, ''
        
        for provider, patterns in self.cdn_domains.items():
            for pattern in patterns:
                if domain.endswith(pattern):
                    return True, provider
        
        return False, ''

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
        except:
            pass
    
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
        except:
            return []

class ASNResolver:
    def __init__(self):
        self.cache = {}
        self.cache_file = 'asn_cache.pkl'
        self.lock = threading.Lock()
        self.load_cache()
        
        self.asn_country_map = {
            'AS12880': 'IR',
            'AS58224': 'IR',
            'AS20665': 'IR',
            'AS43754': 'IR',
            'AS49666': 'IR',
            'AS57218': 'IR',
            'AS42473': 'IR',
            'AS48159': 'IR',
            'AS197207': 'IR',
            'AS204196': 'IR',
            'AS47377': 'TR',
            'AS9121': 'TR',
            'AS34984': 'TR',
            'AS47331': 'TR',
            'AS15897': 'TR',
            'AS21342': 'TR',
            'AS20978': 'TR',
            'AS25513': 'RU',
            'AS12389': 'RU',
            'AS8402': 'RU',
            'AS13238': 'RU',
            'AS29076': 'RU',
            'AS42610': 'RU',
            'AS24940': 'DE',
            'AS3320': 'DE',
            'AS6805': 'DE',
            'AS8560': 'DE',
            'AS31334': 'DE',
            'AS14061': 'DE',
            'AS16276': 'FR',
            'AS12876': 'FR',
            'AS21502': 'FR',
            'AS15557': 'FR',
            'AS8075': 'US',
            'AS14618': 'US',
            'AS15169': 'US',
            'AS16509': 'US',
            'AS7018': 'US',
            'AS701': 'US',
            'AS3356': 'US',
            'AS13414': 'CH',
            'AS3303': 'CH',
            'AS51852': 'NL',
            'AS60404': 'NL',
            'AS49870': 'NL',
            'AS60068': 'NL',
            'AS1403': 'GB',
            'AS20825': 'GB',
            'AS54574': 'GB',
            'AS56630': 'GB',
            'AS45102': 'SG',
            'AS3758': 'SG',
            'AS7497': 'SG',
            'AS4788': 'MY',
            'AS9931': 'MY',
            'AS38193': 'JP',
            'AS17676': 'JP',
            'AS4713': 'JP',
            'AS4766': 'KR',
            'AS3786': 'KR',
            'AS9318': 'KR',
            'AS9808': 'CN',
            'AS4134': 'CN',
            'AS4837': 'CN',
            'AS23724': 'IN',
            'AS55836': 'IN',
            'AS9498': 'IN',
            'AS26347': 'BR',
            'AS27699': 'BR',
            'AS53006': 'BR',
            'AS13999': 'MX',
            'AS8151': 'MX',
            'AS22822': 'MX'
        }
    
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
        except:
            pass
    
    def get_asn_country(self, ip):
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        
        country = "UNKNOWN"
        
        try:
            response = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=5)
            if response.status_code == 200 and ',' in response.text:
                parts = response.text.strip().split(',')
                if len(parts) >= 2:
                    asn = parts[1].strip()
                    country = self.asn_country_map.get(asn, "UNKNOWN")
        except:
            pass
        
        with self.lock:
            self.cache[ip] = country
        
        return country

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
            urls = [
                "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
                "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
            ]
            
            for url in urls:
                try:
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        with open(self.db_path, 'wb') as f:
                            f.write(response.content)
                        return
                except:
                    continue
        except:
            pass
    
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
        except:
            pass
    
    def get_country_by_ipapi(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('countryCode', 'UNKNOWN')
        except:
            pass
        return "UNKNOWN"
    
    def get_country_maxmind(self, ip):
        try:
            import geoip2.database
            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.country(ip)
                return response.country.iso_code or "UNKNOWN"
        except:
            return "UNKNOWN"
    
    def get_country(self, ip):
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        
        country = "UNKNOWN"
        
        if re.match(r'^172\.|^10\.|^192\.168\.', ip):
            country = "PRIVATE"
        elif ':' in ip:
            country = "IPV6"
        elif os.path.exists(self.db_path):
            country = self.get_country_maxmind(ip)
            if country == "UNKNOWN":
                country = self.get_country_by_ipapi(ip)
        else:
            country = self.get_country_by_ipapi(ip)
        
        with self.lock:
            self.cache[ip] = country
        
        return country

class CountryClassifier:
    def __init__(self, max_workers=50):
        self.parser = ConfigParser()
        self.dns_resolver = DNSResolver()
        self.asn_resolver = ASNResolver()
        self.geoip = GeoIPClassifier()
        self.max_workers = max_workers
        self.results_lock = threading.Lock()
        self.results = {}
        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'by_country': {},
            'by_protocol': {}
        }
    
    def get_final_country(self, geoip_country, asn_country, hostname, ip):
        if geoip_country == "UNKNOWN" and asn_country == "UNKNOWN":
            return "UNKNOWN"
        
        if geoip_country == "PRIVATE" or geoip_country == "IPV6":
            return geoip_country
        
        if asn_country != "UNKNOWN" and asn_country != geoip_country:
            asn_evidence = self.check_asn_evidence(ip, asn_country)
            geoip_evidence = self.check_geoip_evidence(ip, geoip_country)
            
            if asn_evidence > geoip_evidence:
                return asn_country
        
        return geoip_country
    
    def check_asn_evidence(self, ip, country):
        evidence = 1
        
        try:
            response = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}", timeout=3)
            if response.status_code == 200:
                text = response.text.lower()
                if country.lower() in text:
                    evidence += 1
        except:
            pass
        
        return evidence
    
    def check_geoip_evidence(self, ip, country):
        evidence = 1
        
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('countryCode') == country:
                    evidence += 1
                if data.get('region') and country in ['US', 'CA', 'AU', 'CN', 'IN', 'BR']:
                    evidence += 0.5
        except:
            pass
        
        return evidence
    
    def process_single_config(self, config_str):
        try:
            parsed = self.parser.parse_config(config_str)
            if not parsed:
                return None
            
            target_host = parsed.get('host', '')
            sni = parsed.get('sni', '')
            
            if not target_host:
                return None
            
            is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_host)
            
            if not is_ip:
                is_ipv6 = ':' in target_host and not target_host.startswith('[')
                if not is_ipv6:
                    ips = self.dns_resolver.resolve(target_host, timeout=3.0)
                    if not ips:
                        return None
                    ip = ips[0]
                else:
                    ip = target_host
            else:
                ip = target_host
            
            if re.match(r'^172\.|^10\.|^192\.168\.', ip):
                country = "PRIVATE"
            elif ':' in ip:
                country = "IPV6"
            else:
                geoip_country = self.geoip.get_country(ip)
                asn_country = self.asn_resolver.get_asn_country(ip)
                
                is_cdn, cdn_provider = self.parser.is_cdn_domain(target_host)
                if is_cdn:
                    country = "CDN"
                else:
                    country = self.get_final_country(geoip_country, asn_country, target_host, ip)
            
            return {
                'config': config_str,
                'parsed': parsed,
                'ip': ip,
                'country': country,
                'host': target_host
            }
        except:
            return None
    
    def process_configs(self, configs):
        logger.info(f"Processing {len(configs)} configurations...")
        
        self.results = {}
        self.stats = {
            'total': len(configs),
            'success': 0,
            'failed': 0,
            'by_country': {},
            'by_protocol': {}
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
                        
                        if country not in self.results:
                            self.results[country] = {}
                        
                        if protocol not in self.results[country]:
                            self.results[country][protocol] = []
                        
                        self.results[country][protocol].append(result['config'])
                        
                        self.stats['by_country'][country] = self.stats['by_country'].get(country, 0) + 1
                        self.stats['by_protocol'][protocol] = self.stats['by_protocol'].get(protocol, 0) + 1
                else:
                    with self.results_lock:
                        self.stats['failed'] += 1
        
        self.dns_resolver.save_cache()
        self.geoip.save_cache()
        self.asn_resolver.save_cache()
        
        return {
            'results': self.results,
            'stats': self.stats
        }
    
    def save_results(self, results, output_dir='configs/country'):
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
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
            
            if all_country_configs:
                all_file = os.path.join(country_dir, "all.txt")
                content = f"# All Configurations for {country}\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_country_configs)}\n"
                    content += f"# Country Code: {country}\n\n"
                content += "\n".join(all_country_configs)
                
                with open(all_file, 'w', encoding='utf-8') as f:
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
            f.write(f"Failed to classify: {results['stats']['failed']}\n\n")
            
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
                except:
                    pass
    
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
                except:
                    pass
    
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

if __name__ == "__main__":
    main()
