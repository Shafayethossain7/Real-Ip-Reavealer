#!/usr/bin/env python3
import sys
import re
import socket
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def check_dependencies():
    """Verify required packages are installed"""
    required = {'requests', 'dns', 'colorama'}
    missing = []
    try:
        import requests
        import dns.resolver
        from colorama import Fore, Style, init
    except ImportError as e:
        missing.append(str(e).split()[-1])
    
    if missing:
        print(f"{Fore.RED}Error: Missing required packages - {', '.join(missing)}")
        print(f"{Fore.CYAN}Install with: pip install {' '.join(missing)}{Style.RESET_ALL}")
        sys.exit(1)

check_dependencies()

HEADER = f"""
{Fore.CYAN}
▓█████▄  ▄▄▄       ███▄ ▄███▓ ██▓███   ██▀███   ▒█████   ██▓    
▒██▀ ██▌▒████▄    ▓██▒▀█▀ ██▒▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▓██▒    
░██   █▌▒██  ▀█▄  ▓██    ▓██░▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒▒██░    
░▓█▄   ▌░██▄▄▄▄██ ▒██    ▒██ ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░▒██░    
░▒████▓  ▓█   ▓██▒▒██▒   ░██▒▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░░██████▒
 ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒░   ░  ░▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▓  ░
 ░ ▒  ▒   ▒   ▒▒ ░░  ░      ░░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░ ▒  ░
 ░ ░  ░   ░   ▒   ░      ░   ░░         ░░   ░ ░ ░ ░ ▒    ░ ░   
   ░          ░  ░       ░               ░         ░ ░      ░  ░
 ░                                                            
{Fore.YELLOW}
Real-IP Revealer - Find the Truth!
* Created by Shafayet
* No IP is safe, No CDN is perfect!
{Style.RESET_ALL}
"""

class IPInvestigator:
    CDN_PROVIDERS = [
        'cloudflare', 'akamai', 'fastly', 'incapsula',
        'sucuri', 'stackpath', 'azureedge', 'aws',
        'google', 'cloudfront'
    ]

    def __init__(self, domain):
        self.domain = domain
        self.found_ips = set()
        self.real_ips = []
        self.cdn_ips = []

    def validate_domain(self):
        """Validate domain format"""
        pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        return re.match(pattern, self.domain) is not None

    def dns_resolution(self):
        """Perform comprehensive DNS lookup"""
        try:
            answers = dns.resolver.resolve(self.domain, 'A')
            ips = {str(r) for r in answers}
            if ips:
                print(f"{Fore.GREEN}[+] DNS Resolution Found: {', '.join(ips)}")
                self.found_ips.update(ips)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            print(f"{Fore.YELLOW}[-] No DNS records found")
        except Exception as e:
            print(f"{Fore.RED}[-] DNS Error: {str(e)}")

    def check_ssl_certificates(self):
        """Check certificate transparency logs"""
        try:
            response = requests.get(f'https://crt.sh/?q=%25.{self.domain}&output=json', timeout=15)
            if response.status_code == 200:
                certs = response.json()
                ips = set()
                for cert in certs:
                    if 'common_name' in cert:
                        try:
                            resolved = socket.gethostbyname(cert['common_name'])
                            ips.add(resolved)
                        except socket.gaierror:
                            continue
                if ips:
                    print(f"{Fore.GREEN}[+] Certificate IPs Found: {', '.join(ips)}")
                    self.found_ips.update(ips)
        except Exception as e:
            print(f"{Fore.RED}[-] Certificate Check Failed: {str(e)}")

    def port_scan(self):
        """Scan common ports for origin server"""
        ports = [80, 443, 8080, 8443, 8888]
        print(f"{Fore.CYAN}[*] Scanning common ports...")
        
        def test_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((self.domain, port))
                    return s.getpeername()[0]
            except:
                return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(test_port, ports)
        
        found = {ip for ip in results if ip}
        if found:
            print(f"{Fore.GREEN}[+] Port Scan IPs: {', '.join(found)}")
            self.found_ips.update(found)

    def analyze_ips(self):
        """Classify IPs as CDN or potential real IPs"""
        for ip in self.found_ips:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                if any(cdn in hostname.lower() for cdn in self.CDN_PROVIDERS):
                    self.cdn_ips.append(f"{ip} ({hostname})")
                else:
                    self.real_ips.append(ip)
            except socket.herror:
                self.real_ips.append(ip)
            except Exception as e:
                print(f"{Fore.RED}[-] Analysis Error: {str(e)}")

    def display_results(self):
        """Show final investigation results"""
        print(f"\n{Fore.CYAN}{'='*40}")
        print(f"{Fore.YELLOW}=== Investigation Results for {self.domain} ===")
        print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
        
        if self.real_ips:
            print(f"\n{Fore.GREEN}[✓] Potential Real IP Addresses:")
            for ip in self.real_ips:
                print(f"  → {ip}")
        
        if self.cdn_ips:
            print(f"\n{Fore.MAGENTA}[!] CDN-Protected IP Addresses:")
            for cdn in self.cdn_ips:
                print(f"  → {cdn}")
        
        if not self.real_ips and not self.cdn_ips:
            print(f"\n{Fore.RED}[-] No IP addresses found through investigation")

def main():
    print(HEADER)
    
    # Get valid domain input
    while True:
        domain = input(f"{Fore.GREEN}[?] Enter target domain (e.g., example.com): ").strip()
        if not domain:
            continue
        
        investigator = IPInvestigator(domain)
        if investigator.validate_domain():
            break
        print(f"{Fore.RED}[!] Invalid domain format. Please try again.")

    # Conduct investigation
    try:
        print(f"\n{Fore.YELLOW}[*] Starting investigation...{Style.RESET_ALL}")
        investigator.dns_resolution()
        investigator.check_ssl_certificates()
        investigator.port_scan()
        investigator.analyze_ips()
        investigator.display_results()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Investigation aborted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Critical Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()