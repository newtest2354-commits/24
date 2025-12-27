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

class DomainCountryDetector:
    def __init__(self):
        self.tld_country_map = {
            '.ir': 'IR', '.us': 'US', '.uk': 'GB', '.gb': 'GB',
            '.de': 'DE', '.fr': 'FR', '.nl': 'NL', '.ru': 'RU',
            '.tr': 'TR', '.ae': 'AE', '.sa': 'SA', '.qa': 'QA',
            '.kw': 'KW', '.om': 'OM', '.bh': 'BH', '.jo': 'JO',
            '.lb': 'LB', '.eg': 'EG', '.sy': 'SY', '.iq': 'IQ',
            '.az': 'AZ', '.am': 'AM', '.ge': 'GE', '.kz': 'KZ',
            '.uz': 'UZ', '.tj': 'TJ', '.tm': 'TM', '.kg': 'KG',
            '.af': 'AF', '.pk': 'PK', '.in': 'IN', '.cn': 'CN',
            '.jp': 'JP', '.kr': 'KR', '.sg': 'SG', '.my': 'MY',
            '.id': 'ID', '.th': 'TH', '.vn': 'VN', '.ph': 'PH',
            '.au': 'AU', '.ca': 'CA', '.br': 'BR', '.mx': 'MX',
            '.ar': 'AR', '.cl': 'CL', '.co': 'CO', '.pe': 'PE',
            '.ch': 'CH', '.se': 'SE', '.no': 'NO', '.fi': 'FI',
            '.dk': 'DK', '.pl': 'PL', '.cz': 'CZ', '.hu': 'HU',
            '.at': 'AT', '.it': 'IT', '.es': 'ES', '.pt': 'PT',
            '.gr': 'GR', '.il': 'IL', '.za': 'ZA', '.ng': 'NG',
            '.ke': 'KE', '.et': 'ET'
        }
        self.domain_patterns = {
            'IR': ['.ir', '.co.ir', '.ac.ir', '.gov.ir', '.org.ir', '.net.ir', '.sch.ir'],
            'TR': ['.tr', '.com.tr', '.org.tr', '.net.tr', '.edu.tr', '.gov.tr', '.k12.tr'],
            'DE': ['.de', '.com.de'],
            'US': ['.us', '.com', '.net', '.org', '.edu', '.gov'],
            'RU': ['.ru', '.su', '.рф', '.com.ru', '.org.ru', '.net.ru'],
            'CN': ['.cn', '.com.cn', '.net.cn', '.org.cn', '.gov.cn', '.中国'],
            'FR': ['.fr', '.com.fr', '.org.fr'],
            'GB': ['.uk', '.co.uk', '.org.uk', '.gov.uk', '.ac.uk'],
            'NL': ['.nl', '.co.nl'],
            'AE': ['.ae', '.co.ae', '.gov.ae'],
            'SA': ['.sa', '.com.sa', '.org.sa', '.gov.sa'],
            'CA': ['.ca', '.co.ca', '.on.ca', '.qc.ca'],
            'AU': ['.au', '.com.au', '.org.au', '.net.au'],
            'JP': ['.jp', '.co.jp', '.or.jp', '.go.jp', '.ac.jp'],
            'KR': ['.kr', '.co.kr', '.or.kr', '.go.kr', '.ac.kr'],
            'SG': ['.sg', '.com.sg', '.org.sg', '.gov.sg'],
            'IN': ['.in', '.co.in', '.org.in', '.net.in', '.gov.in'],
            'BR': ['.br', '.com.br', '.org.br', '.gov.br', '.net.br'],
            'MX': ['.mx', '.com.mx', '.org.mx', '.gob.mx'],
            'IT': ['.it', '.com.it', '.org.it', '.gov.it'],
            'ES': ['.es', '.com.es', '.org.es', '.gob.es'],
            'PL': ['.pl', '.com.pl', '.org.pl', '.net.pl', '.gov.pl'],
            'SE': ['.se', '.com.se', '.org.se'],
            'NO': ['.no', '.com.no', '.org.no'],
            'DK': ['.dk', '.com.dk', '.org.dk'],
            'FI': ['.fi', '.com.fi', '.org.fi'],
            'CH': ['.ch', '.com.ch', '.org.ch'],
            'AT': ['.at', '.co.at', '.or.at'],
            'BE': ['.be', '.com.be', '.org.be'],
            'CZ': ['.cz', '.co.cz', '.org.cz'],
            'HU': ['.hu', '.co.hu', '.org.hu'],
            'RO': ['.ro', '.com.ro', '.org.ro'],
            'BG': ['.bg', '.com.bg', '.org.bg'],
            'GR': ['.gr', '.com.gr', '.org.gr'],
            'IL': ['.il', '.co.il', '.org.il', '.gov.il', '.ac.il'],
            'ZA': ['.za', '.co.za', '.org.za'],
            'EG': ['.eg', '.com.eg', '.org.eg', '.gov.eg', '.edu.eg'],
            'MA': ['.ma', '.co.ma', '.org.ma', '.gov.ma'],
            'TN': ['.tn', '.com.tn', '.org.tn', '.gov.tn'],
            'DZ': ['.dz', '.com.dz', '.org.dz', '.gov.dz'],
            'LY': ['.ly', '.com.ly', '.org.ly', '.gov.ly'],
            'SD': ['.sd', '.com.sd', '.org.sd', '.gov.sd'],
            'YE': ['.ye', '.com.ye', '.org.ye', '.gov.ye'],
            'SO': ['.so', '.com.so', '.org.so', '.gov.so'],
            'DJ': ['.dj', '.com.dj', '.org.dj', '.gov.dj'],
            'KM': ['.km', '.com.km', '.org.km', '.gov.km'],
            'MR': ['.mr', '.com.mr', '.org.mr', '.gov.mr'],
            'NE': ['.ne', '.com.ne', '.org.ne', '.gov.ne'],
            'TD': ['.td', '.com.td', '.org.td', '.gov.td'],
            'ML': ['.ml', '.com.ml', '.org.ml', '.gov.ml'],
            'BF': ['.bf', '.com.bf', '.org.bf', '.gov.bf'],
            'BJ': ['.bj', '.com.bj', '.org.bj', '.gov.bj'],
            'TG': ['.tg', '.com.tg', '.org.tg', '.gov.tg'],
            'GH': ['.gh', '.com.gh', '.org.gh', '.gov.gh'],
            'CI': ['.ci', '.com.ci', '.org.ci', '.gov.ci'],
            'GN': ['.gn', '.com.gn', '.org.gn', '.gov.gn'],
            'SN': ['.sn', '.com.sn', '.org.sn', '.gov.sn'],
            'GM': ['.gm', '.com.gm', '.org.gm', '.gov.gm'],
            'GW': ['.gw', '.com.gw', '.org.gw', '.gov.gw'],
            'LR': ['.lr', '.com.lr', '.org.lr', '.gov.lr'],
            'SL': ['.sl', '.com.sl', '.org.sl', '.gov.sl'],
            'NG': ['.ng', '.com.ng', '.org.ng', '.gov.ng'],
            'CM': ['.cm', '.com.cm', '.org.cm', '.gov.cm'],
            'GA': ['.ga', '.com.ga', '.org.ga', '.gov.ga'],
            'CG': ['.cg', '.com.cg', '.org.cg', '.gov.cg'],
            'CD': ['.cd', '.com.cd', '.org.cd', '.gov.cd'],
            'AO': ['.ao', '.com.ao', '.org.ao', '.gov.ao'],
            'NA': ['.na', '.com.na', '.org.na', '.gov.na'],
            'BW': ['.bw', '.com.bw', '.org.bw', '.gov.bw'],
            'ZW': ['.zw', '.com.zw', '.org.zw', '.gov.zw'],
            'MZ': ['.mz', '.com.mz', '.org.mz', '.gov.mz'],
            'MW': ['.mw', '.com.mw', '.org.mw', '.gov.mw'],
            'ZM': ['.zm', '.com.zm', '.org.zm', '.gov.zm'],
            'TZ': ['.tz', '.co.tz', '.or.tz', '.go.tz', '.ac.tz'],
            'UG': ['.ug', '.co.ug', '.or.ug', '.go.ug', '.ac.ug'],
            'KE': ['.ke', '.co.ke', '.or.ke', '.go.ke', '.ac.ke'],
            'ET': ['.et', '.com.et', '.org.et', '.gov.et', '.edu.et'],
            'SD': ['.sd', '.com.sd', '.org.sd', '.gov.sd'],
            'SS': ['.ss', '.com.ss', '.org.ss', '.gov.ss'],
            'ER': ['.er', '.com.er', '.org.er', '.gov.er'],
            'DJ': ['.dj', '.com.dj', '.org.dj', '.gov.dj']
        }
    
    def get_country_by_domain(self, domain):
        if not domain:
            return None
        
        domain_lower = domain.lower()
        
        for country, patterns in self.domain_patterns.items():
            for pattern in patterns:
                if domain_lower.endswith(pattern):
                    return country
        
        for tld, country in self.tld_country_map.items():
            if domain_lower.endswith(tld):
                return country
        
        return None

class ConfigParser:
    def __init__(self):
        self.cdn_domains = {
            'cloudflare': [
                'cloudflare.com', 'cloudflaressl.com', 
                'workers.dev', 'pages.dev', 'r2.dev'
            ],
            'akamai': [
                'akamai.net', 'akamaiedge.net', 'akamaihd.net',
                'edgesuite.net', 'edgekey.net'
            ],
            'fastly': [
                'fastly.net', 'fastlylb.net', 'global.ssl.fastly.net'
            ],
            'aws': [
                'amazonaws.com', 'cloudfront.net', 'awsglobalaccelerator.com',
                's3.amazonaws.com', 'elasticbeanstalk.com'
            ],
            'azure': [
                'azureedge.net', 'azurefd.net', 'azurewebsites.net',
                'cloudapp.azure.com', 'trafficmanager.net'
            ],
            'google': [
                'googleusercontent.com', 'gstatic.com', 'googlehosted.com',
                'withgoogle.com', 'googleapis.com', 'appspot.com'
            ],
            'alibaba': [
                'aliyuncs.com', 'alicloud.com', 'aliyun.com'
            ],
            'cloudfront': ['cloudfront.net'],
            'incapsula': ['incapdns.net'],
            'stackpath': ['stackpathcdn.com'],
            'keycdn': ['kxcdn.com'],
            'bunny': ['b-cdn.net'],
            'cdn77': ['cdn77.org', 'cdn77.net'],
            'leaseweb': ['lswcdn.net'],
            'limelight': ['lldns.net'],
            'cachefly': ['cachefly.net'],
            'cdnnetworks': ['cdnnetworks.com'],
            'highwinds': ['hwcdn.net'],
            'maxcdn': ['maxcdn.com']
        }
        self.domain_detector = DomainCountryDetector()
    
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
    
    def is_cdn_domain(self, domain):
        if not domain:
            return False, None
        
        domain_lower = domain.lower()
        
        for provider, domains in self.cdn_domains.items():
            for cdn_domain in domains:
                if domain_lower.endswith(cdn_domain):
                    return True, provider
        
        cdn_keywords = ['cdn', 'cache', 'edge', 'cloud', 'global', 'accelerator']
        for keyword in cdn_keywords:
            if keyword in domain_lower:
                return True, 'generic'
        
        return False, None
    
    def get_target_host(self, parsed_config):
        sni = parsed_config.get('sni', '')
        host = parsed_config.get('host', '')
        
        if sni:
            return sni
        return host

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
            return []
        except Exception as e:
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
            urls = [
                "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
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
            country_code = self.get_country_by_ipapi(ip)
        except Exception as e:
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
        self.cdn_configs = {}
        self.stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'by_country': {},
            'by_protocol': {},
            'cdn_count': 0
        }
    
    def process_single_config(self, config_str):
        try:
            parsed = self.parser.parse_config(config_str)
            if not parsed:
                return None
            
            target_host = self.parser.get_target_host(parsed)
            if not target_host:
                return None
            
            is_cdn, cdn_provider = self.parser.is_cdn_domain(target_host)
            if is_cdn:
                with self.results_lock:
                    if cdn_provider not in self.cdn_configs:
                        self.cdn_configs[cdn_provider] = []
                    self.cdn_configs[cdn_provider].append(config_str)
                    self.stats['cdn_count'] += 1
                
                return {
                    'config': config_str,
                    'parsed': parsed,
                    'host': target_host,
                    'country': 'CDN',
                    'cdn_provider': cdn_provider,
                    'is_cdn': True
                }
            
            country_by_domain = self.parser.domain_detector.get_country_by_domain(target_host)
            
            is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target_host)
            if not is_ip:
                is_ipv6 = ':' in target_host and not target_host.startswith('[')
                if not is_ipv6:
                    ips = self.dns_resolver.resolve(target_host, timeout=3.0)
                    if not ips:
                        if country_by_domain:
                            ip_country = country_by_domain
                        else:
                            return None
                    else:
                        ip = ips[0]
                        ip_country = self.geoip.get_country(ip)
                else:
                    ip = target_host
                    ip_country = self.geoip.get_country(ip)
            else:
                ip = target_host
                ip_country = self.geoip.get_country(ip)
            
            if ip_country == "UNKNOWN" and country_by_domain:
                country = country_by_domain
            else:
                country = ip_country
            
            return {
                'config': config_str,
                'parsed': parsed,
                'ip': ip if 'ip' in locals() else None,
                'country': country,
                'is_cdn': False,
                'cdn_provider': None,
                'host': target_host
            }
        except Exception as e:
            return None
    
    def process_configs(self, configs):
        logger.info(f"Processing {len(configs)} configurations...")
        
        self.results = {}
        self.cdn_configs = {}
        self.stats = {
            'total': len(configs),
            'success': 0,
            'failed': 0,
            'by_country': {},
            'by_protocol': {},
            'cdn_count': 0
        }
        
        unique_configs = []
        seen = set()
        
        for config in configs:
            config_hash = hashlib.md5(config.encode()).hexdigest()
            if config_hash not in seen:
                seen.add(config_hash)
                unique_configs.append(config)
        
        logger.info(f"After deduplication: {len(unique_configs)} unique configs")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_config = {
                executor.submit(self.process_single_config, config): config 
                for config in unique_configs
            }
            
            for future in concurrent.futures.as_completed(future_to_config):
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
        
        return {
            'results': self.results,
            'cdn_configs': self.cdn_configs,
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
        
        if results['cdn_configs']:
            cdn_dir = 'configs/cdn'
            os.makedirs(cdn_dir, exist_ok=True)
            
            all_cdn_configs = []
            
            for provider, configs in results['cdn_configs'].items():
                if configs:
                    provider_file = os.path.join(cdn_dir, f"{provider}.txt")
                    content = f"# CDN Configurations - {provider}\n"
                    content += f"# Updated: {timestamp}\n"
                    content += f"# Count: {len(configs)}\n\n"
                    content += "\n".join(configs)
                    
                    with open(provider_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    all_cdn_configs.extend(configs)
            
            if all_cdn_configs:
                all_file = os.path.join(cdn_dir, "all.txt")
                content = f"# All CDN Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_cdn_configs)}\n\n"
                content += "\n".join(all_cdn_configs)
                
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
            f.write(f"Failed to classify: {results['stats']['failed']}\n")
            f.write(f"CDN configs: {results['stats']['cdn_count']}\n\n")
            
            f.write("By Country:\n")
            for country, count in sorted(results['stats']['by_country'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {country}: {count}\n")
            
            f.write("\nBy Protocol:\n")
            for protocol, count in sorted(results['stats']['by_protocol'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {protocol}: {count}\n")

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
        
        print(f"\n📊 Top Countries:")
        top_countries = sorted(
            results['stats']['by_country'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        for country, count in top_countries:
            print(f"  {country}: {count} configs")
        
        print(f"\n📁 Output saved to: configs/country/")
        print(f"📁 CDN configs saved to: configs/cdn/")
        print("=" * 60)
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()
