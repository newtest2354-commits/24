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
import ipaddress

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ConfigParser:
    def __init__(self):
        self.lock = threading.Lock()
        
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

class ASNLookup:
    def __init__(self):
        self.cache = {}
        self.cache_file = 'asn_cache.pkl'
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
    
    def get_asn_info(self, ip):
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
        
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                asn = data.get('org', '')
                country = data.get('country', '')
                isp = data.get('org', '').lower()
                
                result = {
                    'asn': asn,
                    'country': country,
                    'isp': isp
                }
                
                with self.lock:
                    self.cache[ip] = result
                
                return result
        except:
            pass
        
        return None

class CountryClassifier:
    def __init__(self, max_workers=50):
        self.parser = ConfigParser()
        self.dns_resolver = DNSResolver()
        self.asn_lookup = ASNLookup()
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
        
        self.asn_country_mapping = {
            'turksat': 'TR',
            'turk telekom': 'TR',
            'turk telekomunikasyon': 'TR',
            'türk telekom': 'TR',
            'türk telekomünikasyon': 'TR',
            'vodafone turkey': 'TR',
            'turkcell': 'TR',
            'turknet': 'TR',
            'pars online': 'IR',
            'mobinnet': 'IR',
            'mobin': 'IR',
            'shatel': 'IR',
            'irancell': 'IR',
            'rightel': 'IR',
            'asia tech': 'IR',
            'irantelecom': 'IR',
            'telecommunication company of iran': 'IR',
            'telecommunication infrastructure company': 'IR',
            'mci': 'IR',
            'mtn iran': 'IR',
            'rtk': 'IR',
            'iran': 'IR',
            'hetzner': 'DE',
            'digitalocean': 'US',
            'linode': 'US',
            'vultr': 'US',
            'aws': 'US',
            'amazon': 'US',
            'google': 'US',
            'microsoft': 'US',
            'azure': 'US',
            'oracle': 'US',
            'alibaba': 'CN',
            'tencent': 'CN',
            'huawei': 'CN',
            'ovh': 'FR',
            'online.net': 'FR',
            'contabo': 'DE',
            'ionos': 'DE',
            'godaddy': 'US',
            'namecheap': 'US',
            'hostinger': 'LT',
            'bluehost': 'US',
            'siteground': 'BG',
            'cloudflare': 'US',
            'gcore': 'LU',
            'leaseweb': 'NL',
            'serverius': 'NL',
            'worldstream': 'NL',
            'psychz': 'US',
            'choopa': 'US',
            'cogent': 'US',
            'level3': 'US',
            'he': 'US',
            'franken': 'DE',
            'man-da': 'RU',
            'selectel': 'RU',
            'yandex': 'RU',
            'mts': 'RU',
            'beeline': 'RU',
            'megafon': 'RU',
            'rostelecom': 'RU',
            'sberbank': 'RU',
            'gazprom': 'RU',
        }
    
    def is_private_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def get_country_from_geoip(self, ip):
        try:
            import maxminddb
            reader = maxminddb.open_database('geoip_data/GeoLite2-Country.mmdb')
            response = reader.get(ip)
            reader.close()
            
            if response and 'country' in response:
                iso_code = response['country'].get('iso_code', 'UNKNOWN')
                if iso_code and iso_code != 'UNKNOWN':
                    return iso_code
        except:
            pass
        
        try:
            import geoip2.database
            with geoip2.database.Reader('geoip_data/GeoLite2-Country.mmdb') as reader:
                response = reader.country(ip)
                return response.country.iso_code or 'UNKNOWN'
        except:
            pass
        
        return 'UNKNOWN'
    
    def get_country_from_asn(self, ip):
        asn_info = self.asn_lookup.get_asn_info(ip)
        if not asn_info:
            return None
        
        isp_lower = asn_info['isp'].lower()
        
        for keyword, country_code in self.asn_country_mapping.items():
            if keyword in isp_lower:
                return country_code
        
        return asn_info.get('country')
    
    def get_country_from_rdns(self, ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            
            tld_country_map = {
                '.tr': 'TR',
                '.ir': 'IR',
                '.ru': 'RU',
                '.ua': 'UA',
                '.by': 'BY',
                '.kz': 'KZ',
                '.az': 'AZ',
                '.ge': 'GE',
                '.am': 'AM',
                '.de': 'DE',
                '.fr': 'FR',
                '.nl': 'NL',
                '.uk': 'GB',
                '.us': 'US',
                '.ca': 'CA',
                '.au': 'AU',
                '.jp': 'JP',
                '.kr': 'KR',
                '.cn': 'CN',
                '.in': 'IN',
                '.br': 'BR',
                '.mx': 'MX',
                '.es': 'ES',
                '.it': 'IT',
                '.ch': 'CH',
                '.se': 'SE',
                '.no': 'NO',
                '.dk': 'DK',
                '.fi': 'FI',
                '.pl': 'PL',
                '.cz': 'CZ',
                '.hu': 'HU',
                '.ro': 'RO',
                '.bg': 'BG',
                '.gr': 'GR',
                '.il': 'IL',
                '.sa': 'SA',
                '.ae': 'AE',
                '.eg': 'EG',
                '.za': 'ZA',
            }
            
            for tld, country in tld_country_map.items():
                if hostname.endswith(tld):
                    return country
            
            for keyword, country in self.asn_country_mapping.items():
                if keyword in hostname.lower():
                    return country
        except:
            pass
        
        return None
    
    def determine_country(self, ip, hostname):
        if self.is_private_ip(ip):
            return 'PRIVATE'
        
        if ':' in ip:
            return 'IPV6'
        
        geoip_country = self.get_country_from_geoip(ip)
        
        asn_country = self.get_country_from_asn(ip)
        
        rdns_country = self.get_country_from_rdns(ip)
        
        votes = {}
        
        if geoip_country and geoip_country != 'UNKNOWN':
            votes[geoip_country] = votes.get(geoip_country, 0) + 3
        
        if asn_country and asn_country != 'UNKNOWN':
            votes[asn_country] = votes.get(asn_country, 0) + 2
        
        if rdns_country:
            votes[rdns_country] = votes.get(rdns_country, 0) + 1
        
        if not votes:
            return 'UNKNOWN'
        
        if geoip_country in votes and asn_country in votes and geoip_country != asn_country:
            if asn_country in ['IR', 'TR', 'RU', 'CN']:
                return asn_country
        
        max_votes = max(votes.values())
        candidates = [country for country, votes_count in votes.items() if votes_count == max_votes]
        
        if len(candidates) == 1:
            return candidates[0]
        
        if geoip_country in candidates:
            return geoip_country
        
        return candidates[0] if candidates else 'UNKNOWN'
    
    def process_single_config(self, config_str):
        try:
            parsed = self.parser.parse_config(config_str)
            if not parsed:
                return None
            
            target_host = parsed.get('sni', '') or parsed.get('host', '')
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
            
            country = self.determine_country(ip, target_host)
            
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
        self.asn_lookup.save_cache()
        
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
    print("ENHANCED COUNTRY CONFIG CLASSIFIER")
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
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()
