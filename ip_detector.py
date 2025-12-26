import re
import socket
import geoip2.database
import geoip2.errors
from urllib.parse import urlparse
import base64
import json

class IPDetector:
    def __init__(self):
        self.geoip_db = None
        try:
            self.geoip_db = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmr')
        except:
            pass
            
    def extract_server_from_config(self, config_str):
        if config_str.startswith('vmess://'):
            try:
                base64_part = config_str[8:]
                if len(base64_part) % 4 != 0:
                    base64_part += '=' * (4 - len(base64_part) % 4)
                decoded = json.loads(base64.b64decode(base64_part).decode('utf-8'))
                return decoded.get('add')
            except:
                pass
        elif config_str.startswith('vless://'):
            match = re.search(r'@([^:#]+)', config_str)
            if match:
                return match.group(1)
        elif config_str.startswith('trojan://'):
            match = re.search(r'@([^:#]+)', config_str)
            if match:
                return match.group(1)
        elif config_str.startswith('ss://'):
            try:
                parts = config_str.split('#', 1)
                base_part = parts[0][5:]
                if '@' not in base_part:
                    if len(base_part) % 4 != 0:
                        base_part += '=' * (4 - len(base_part) % 4)
                    decoded = base64.b64decode(base_part).decode('utf-8')
                    if '@' in decoded:
                        _, server_part = decoded.split('@', 1)
                        return server_part.split(':')[0]
                else:
                    encoded_method_pass, server_part = base_part.split('@', 1)
                    return server_part.split(':')[0]
            except:
                pass
        elif config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
            match = re.search(r'://([^?#]+)', config_str)
            if match:
                return match.group(1).split(':')[0]
        elif config_str.startswith('hysteria://'):
            match = re.search(r'://([^?#]+)', config_str)
            if match:
                return match.group(1).split(':')[0]
        elif config_str.startswith('tuic://'):
            match = re.search(r'://([^?#]+)', config_str)
            if match:
                return match.group(1).split(':')[0]
        return None
    
    def is_ip_address(self, server_str):
        if not server_str:
            return False
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, server_str):
            parts = server_str.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def resolve_domain(self, domain):
        try:
            return socket.gethostbyname(domain)
        except:
            return None
    
    def get_country_info(self, ip_address):
        if not self.geoip_db:
            return "Unknown", "Unknown"
        
        try:
            response = self.geoip_db.city(ip_address)
            country_name = response.country.name or "Unknown"
            country_code = response.country.iso_code or "Unknown"
            return country_name, country_code
        except geoip2.errors.AddressNotFoundError:
            return "Unknown", "Unknown"
        except:
            return "Unknown", "Unknown"
    
    def detect_country(self, config_str):
        server = self.extract_server_from_config(config_str)
        if not server:
            return "Unknown", "Unknown"
        
        if self.is_ip_address(server):
            ip_address = server
        else:
            ip_address = self.resolve_domain(server)
            if not ip_address:
                return "Unknown", "Unknown"
        
        return self.get_country_info(ip_address)
    
    def get_flag_emoji(self, country_code):
        if country_code == "Unknown":
            return "🏴"
        
        OFFSET = 127397
        try:
            return ''.join(chr(ord(c) + OFFSET) for c in country_code.upper())
        except:
            return "🏴"
