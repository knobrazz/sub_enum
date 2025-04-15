#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import os
import requests
import sys
import subprocess
import time
from datetime import datetime
from colorama import Fore, Style, init
from tqdm import tqdm
import re
import urllib3
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
import httpx
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

def print_banner():
    console = Console()
    banner = """[cyan]
██╗    ██╗███████╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║    ██║██╔════╝██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝[/cyan]"""

    console.print(banner)
    time.sleep(0.1)
    
    info_panel = Panel(
        Text.assemble(
            ("🚀 Created by: ", "bold cyan"),
            ("Nabaraj Lamichhane\n", "bold white"),
            ("🔖 Version: ", "bold cyan"),
            ("1.0", "bold white")
        ),
        border_style="cyan"
    )
    console.print(info_panel)

def process_domain(self, domain):
    console = Console()
    console.print(f"\n[bold cyan]🎯 Target Domain:[/bold cyan] [bold white]{domain}[/bold white]\n")
    
    categories = {
        "Primary Sources 🔍": ['virustotal', 'crtsh', 'certspotter', 'securitytrails'],
        "Secondary Sources 🔎": ['threatcrowd', 'dnsdumpster', 'hackertarget'],
        "Backup Tools 🛠️": ['subfinder', 'assetfinder', 'findomain']
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        for category, tools in categories.items():
            console.print(f"\n[bold yellow]⚡ Running {category}...[/bold yellow]")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_tool = {executor.submit(self.run_tool, tool, domain): tool for tool in tools}
                
                task = progress.add_task(f"[cyan]Processing {category}", total=len(tools))
                for future in concurrent.futures.as_completed(future_to_tool):
                    tool = future_to_tool[future]
                    try:
                        new_subdomains = future.result()
                        self.subdomains.update(new_subdomains)
                        console.print(f"[green]✅ {tool}:[/green] Found [bold white]{len(new_subdomains)}[/bold white] subdomains")
                    except Exception as e:
                        console.print(f"[red]❌ Error with {tool}: {str(e)}[/red]")
                    progress.advance(task)

class WebHunter:
    def __init__(self, domains, output_file, output_format, threads):
        self.domains = domains
        self.output_file = output_file
        self.output_format = output_format
        self.threads = threads
        self.subdomains = set()
        
        # Expanded tools dictionary with all categories
        self.tools = {
            # Active Enumeration (using CLI tools)
            'sublist3r': self.run_sublist3r,
            'amass': self.run_amass,
            'subfinder': self.run_subfinder,
            'knockpy': self.run_knockpy,
            'gobuster': self.run_gobuster,
            'assetfinder': self.run_assetfinder,
            'findomain': self.run_findomain,
            
            # Passive Enumeration
            'crtsh': self.run_crtsh,
            'certspotter': self.run_certspotter,
            'virustotal': self.run_virustotal,
            'securitytrails': self.run_securitytrails,
            'threatcrowd': self.run_threatcrowd,
            'dnsdumpster': self.run_dnsdumpster,
            
            # DNS Tools
            'dnsrecon': self.run_dnsrecon,
            'massdns': self.run_massdns,
            'aquatone': self.run_aquatone,
            'hackertarget': self.run_hackertarget,
            'oneforall': self.run_oneforall
        }

    def process_domain(self, domain):
        print(f"\n{Fore.CYAN}[+] Processing domain: {domain}{Style.RESET_ALL}")
        
        # Define categories for tool organization
        categories = {
            "Primary Sources": ['virustotal', 'crtsh', 'certspotter', 'securitytrails'],
            "Secondary Sources": ['threatcrowd', 'dnsdumpster', 'hackertarget'],
            "Backup Tools": ['subfinder', 'assetfinder', 'findomain']
        }

        for category, tools in categories.items():
            print(f"\n{Fore.YELLOW}[*] Running {category} tools...{Style.RESET_ALL}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_tool = {executor.submit(self.run_tool, tool, domain): tool for tool in tools}
                
                for future in tqdm(concurrent.futures.as_completed(future_to_tool), 
                                 total=len(future_to_tool),
                                 desc=category):
                    tool = future_to_tool[future]
                    try:
                        new_subdomains = future.result()
                        self.subdomains.update(new_subdomains)
                        print(f"{Fore.GREEN}[+] {tool}: Found {len(new_subdomains)} subdomains{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.RED}[-] Error with {tool}: {str(e)}{Style.RESET_ALL}")

    def save_results(self):
        console = Console()
        console.print("\n[bold cyan]💾 Saving results...[/bold cyan]")
        
        os.makedirs('results', exist_ok=True)
        output_path = os.path.join('results', self.output_file)
    
        # Create a table for results summary
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("📊 Category", style="cyan")
        table.add_column("📝 Details", style="white")
    
        table.add_row(
            "Total Subdomains",
            str(len(self.subdomains))
        )
        table.add_row(
            "Output Format",
            self.output_format.upper()
        )
        table.add_row(
            "Output File",
            output_path
        )
    
        console.print(table)
        
        # Save results with animation
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Saving results...", total=100)
            
            if self.output_format == 'json':
                output = {
                    'total': len(self.subdomains),
                    'subdomains': sorted(list(self.subdomains)),
                    'timestamp': datetime.now().isoformat(),
                    'domain': self.domains[0] if len(self.domains) == 1 else 'multiple_domains'
                }
                with open(output_path, 'w') as f:
                    json.dump(output, f, indent=4)
            
            elif self.output_format == 'md':
                with open(output_path, 'w') as f:
                    f.write('# Subdomain Enumeration Results\n\n')
                    f.write(f'## Target Domain(s)\n')
                    for domain in self.domains:
                        f.write(f'- {domain}\n')
                    f.write(f'\n## Summary\n')
                    f.write(f'- Total subdomains found: {len(self.subdomains)}\n')
                    f.write(f'- Scan completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n')
                    f.write('## Discovered Subdomains\n\n')
                    for subdomain in sorted(self.subdomains):
                        f.write(f'- {subdomain}\n')
            
            else:  # text format
                with open(output_path, 'w') as f:
                    f.write('# Target Domain(s):\n')
                    f.write('\n'.join(self.domains))
                    f.write('\n\n# Discovered Subdomains:\n')
                    f.write('\n'.join(sorted(self.subdomains)))
            
            progress.update(task, advance=100)
        
        console.print(f"\n[bold green]✨ Results successfully saved to: [/bold green][cyan]{output_path}[/cyan]")

    def run_crtsh(self, domain):
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        subdomains = set()
                        for entry in data:
                            if isinstance(entry, dict) and 'name_value' in entry:
                                name_value = entry['name_value']
                                if name_value.endswith(domain):
                                    subdomains.add(name_value)
                        return subdomains
                except json.JSONDecodeError:
                    print(f"{Fore.YELLOW}Warning: Invalid JSON response from crt.sh{Style.RESET_ALL}")
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in crt.sh: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_certspotter(self, domain):
        try:
            url = f"https://api.certspotter.com/v1/issuances"
            params = {
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names"
            }
            response = requests.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for cert in data:
                    for dns_name in cert.get('dns_names', []):
                        if dns_name.endswith(domain):
                            subdomains.add(dns_name)
                return subdomains
        except Exception as e:
            print(f"{Fore.RED}Error in CertSpotter: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_virustotal(self, domain):
        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            params = {
                'domain': domain,
                'apikey': 'YOUR_VIRUSTOTAL_API_KEY'
            }
            response = requests.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                # Collect from subdomains field
                if 'subdomains' in data:
                    subdomains.update(f"{sub}.{domain}" for sub in data['subdomains'])
                
                # Collect from domain_siblings field
                if 'domain_siblings' in data:
                    subdomains.update(sibling for sibling in data['domain_siblings'] 
                                    if sibling.endswith(domain))
                
                # Collect from resolutions field
                if 'resolutions' in data:
                    for resolution in data['resolutions']:
                        hostname = resolution.get('hostname', '')
                        if hostname and hostname.endswith(domain):
                            subdomains.add(hostname)
                
                return subdomains
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in VirusTotal: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_dnsdumpster(self, domain):
        try:
            url = "https://dnsdumpster.com/"
            session = requests.Session()
            
            # Get initial page and cookies
            response = session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            
            if csrf_token is None:
                print(f"{Fore.YELLOW}Warning: Could not find CSRF token for DNSDumpster{Style.RESET_ALL}")
                return set()
                
            csrf_token = csrf_token.get('value')
            
            headers = {
                'Referer': url,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Origin': 'https://dnsdumpster.com'
            }
            
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': domain,
                'user': 'free'
            }
            
            # Make post request with proper headers and cookies
            response = session.post(
                url,
                headers=headers,
                data=data,
                cookies=session.cookies,
                allow_redirects=True
            )
            
            # Parse the response for subdomains
            soup = BeautifulSoup(response.text, 'html.parser')
            tables = soup.findAll('table', {'class': 'table'})
            subdomains = set()
            
            for table in tables:
                for td in table.findAll('td'):
                    if domain in str(td):
                        subdomain = td.text.strip()
                        if subdomain.endswith(domain):
                            subdomains.add(subdomain)
            
            return subdomains
        except Exception as e:
            print(f"{Fore.RED}Error in DNSDumpster: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_threatcrowd(self, domain):
        try:
            url = "https://threatcrowd.org/searchApi/v2/domain/report/"
            params = {'domain': domain}
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Referer': 'https://threatcrowd.org'
            }
            
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == '1' and 'subdomains' in data:
                    return {sub for sub in data['subdomains'] if isinstance(sub, str) and sub.endswith(domain)}
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in ThreatCrowd: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_securitytrails(self, domain):
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {
                'apikey': 'Enter-API-Key-Here',  # Replace with your actual API key
                'Accept': 'application/json'
            }
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data and data['subdomains']:
                    return {f"{sub}.{domain}" for sub in data['subdomains']}
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in SecurityTrails: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_hackertarget(self, domain):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                subdomains = set()
                for line in response.text.splitlines():
                    if ',' in line:
                        subdomain = line.split(',')[0]
                        if subdomain.endswith(domain):
                            subdomains.add(subdomain)
                return subdomains
        except Exception as e:
            print(f"{Fore.RED}Error in HackerTarget: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_tool(self, tool_name, domain):
        """Helper method to run a specific tool"""
        if tool_name in self.tools:
            return self.tools[tool_name](domain)
        return set()

    def run_sublist3r(self, domain):
        try:
            result = subprocess.run(['sublist3r', '-d', domain], 
                                 capture_output=True, 
                                 text=True)
            return {line.strip() for line in result.stdout.splitlines() 
                   if line.strip().endswith(domain)}
        except Exception as e:
            print(f"{Fore.RED}Error in Sublist3r: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_amass(self, domain):
        try:
            result = subprocess.run(['amass', 'enum', '-passive', '-d', domain],
                                 capture_output=True,
                                 text=True)
            return {line.strip() for line in result.stdout.splitlines() 
                   if line.strip().endswith(domain)}
        except Exception as e:
            print(f"{Fore.RED}Error in Amass: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_subfinder(self, domain):
        try:
            result = subprocess.run(['subfinder', '-d', domain],
                                 capture_output=True,
                                 text=True)
            return {line.strip() for line in result.stdout.splitlines() 
                   if line.strip().endswith(domain)}
        except Exception as e:
            print(f"{Fore.RED}Error in Subfinder: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_knockpy(self, domain):
        try:
            result = subprocess.run(['knockpy', '-d', domain, '--recon', '--bruteforce'],
                                 capture_output=True,
                                 text=True)
            return {line.strip() for line in result.stdout.splitlines() 
                   if line.strip().endswith(domain)}
        except Exception as e:
            print(f"{Fore.RED}Error in Knockpy: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_gobuster(self, domain):
        try:
            result = subprocess.run(['gobuster', 'dns', '-d', domain, '-w', '/usr/share/wordlists/dns.txt'],
                                 capture_output=True,
                                 text=True)
            return {line.split()[1].strip() for line in result.stdout.splitlines() 
                   if 'Found:' in line and line.strip().endswith(domain)}
        except Exception as e:
            print(f"{Fore.RED}Error in Gobuster: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_assetfinder(self, domain):
        try:
            result = subprocess.run(['assetfinder', '--subs-only', domain],
                                 capture_output=True,
                                 text=True)
            return {line.strip() for line in result.stdout.splitlines() 
                   if line.strip().endswith(domain)}
        except Exception as e:
            print(f"{Fore.RED}Error in Assetfinder: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_findomain(self, domain):
        try:
            result = subprocess.run(['findomain', '-t', domain],
                                 capture_output=True,
                                 text=True)
            return {line.strip() for line in result.stdout.splitlines() 
                   if line.strip().endswith(domain)}
        except Exception as e:
            print(f"{Fore.RED}Error in Findomain: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_dnsrecon(self, domain):
        try:
            url = f"https://api.dnsrecon.com/v1/scan"
            params = {'domain': domain}
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {sub for sub in data.get('records', []) if sub.endswith(domain)}
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in DNSRecon: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_massdns(self, domain):
        try:
            url = f"https://api.massdns.com/v1/resolve/{domain}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {sub for sub in data.get('resolved', []) if sub.endswith(domain)}
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in MassDNS: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_aquatone(self, domain):
        try:
            url = f"https://api.aquatone.com/v1/discover/{domain}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {sub for sub in data.get('discovered', []) if sub.endswith(domain)}
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in Aquatone: {str(e)}{Style.RESET_ALL}")
            return set()

    def run_oneforall(self, domain):
        try:
            url = f"https://api.oneforall.com/v1/collect/{domain}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return {sub for sub in data.get('collected', []) if sub.endswith(domain)}
            return set()
        except Exception as e:
            print(f"{Fore.RED}Error in OneForAll: {str(e)}{Style.RESET_ALL}")
            return set()

    def validate_subdomain(self, subdomain):
        try:
            # Try HTTPS first
            url = f"https://{subdomain}"
            response = httpx.get(url, timeout=5, verify=False, follow_redirects=True)
            return url if response.status_code in [200, 301, 302, 403] else None
        except:
            try:
                # Try HTTP if HTTPS fails
                url = f"http://{subdomain}"
                response = httpx.get(url, timeout=5, verify=False, follow_redirects=True)
                return url if response.status_code in [200, 301, 302, 403] else None
            except:
                return None

    def filter_valid_subdomains(self):  # Fixed indentation to be at class level
        console = Console()
        valid_subdomains = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Validating subdomains...", total=len(self.subdomains))
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {executor.submit(self.validate_subdomain, subdomain): subdomain 
                                     for subdomain in self.subdomains}
                
                for future in as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        result = future.result()
                        if result:
                            valid_subdomains.add(subdomain)
                            console.print(f"[green]✅ Valid:[/green] {subdomain}")
                    except Exception as e:
                        console.print(f"[red]❌ Error validating {subdomain}: {str(e)}[/red]")
                    progress.advance(task)
            
            return valid_subdomains

def main():
    parser = argparse.ArgumentParser(
        description='WebHunter - Advanced Subdomain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-d', '--domain', help='Target domain (e.g., example.com)')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    parser.add_argument('-o', '--output', help='Output file name', default='subdomains.txt')
    parser.add_argument('-f', '--format', choices=['txt', 'json', 'md'], 
                        default='txt', help='Output format')
    parser.add_argument('-t', '--threads', type=int, default=5, 
                        help='Number of concurrent threads')
    parser.add_argument('--httpx', action='store_true', 
                        help='Filter and save only valid subdomains')

    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)

    print_banner()

    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.list:
        with open(args.list) as f:
            domains.extend(f.read().splitlines())

    hunter = WebHunter(domains, args.output, args.format, args.threads)
    
    for domain in domains:
        hunter.process_domain(domain)

    if args.httpx:
        console = Console()
        console.print("\n[bold cyan]🔍 Filtering valid subdomains...[/bold cyan]")
        valid_subdomains = hunter.filter_valid_subdomains()
        
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        valid_output = os.path.join('results', 'valid.txt')
        valid_urls_output = os.path.join('results', 'valid_urls.txt')
        
        # Save valid subdomains
        with open(valid_output, 'w') as f:
            for subdomain in sorted(valid_subdomains):
                f.write(f"{subdomain}\n")
        
        # Save valid URLs (with http/https)
        with open(valid_urls_output, 'w') as f:
            for subdomain in sorted(valid_subdomains):
                url = hunter.validate_subdomain(subdomain)
                if url:
                    f.write(f"{url}\n")
        
        console.print(f"\n[bold green]✨ Found {len(valid_subdomains)} valid subdomains[/bold green]")
        console.print(f"[bold green]✨ Valid subdomains saved to: [/bold green][cyan]{valid_output}[/cyan]")
        console.print(f"[bold green]✨ Valid URLs saved to: [/bold green][cyan]{valid_urls_output}[/cyan]")

    hunter.save_results()
    print(f"\n{Fore.GREEN}[+] Total unique subdomains found: {len(hunter.subdomains)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Results saved to: {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

