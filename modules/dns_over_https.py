import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from colorama import Fore, init
from time import sleep

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from util import clean_domain_input, validate_domain
from settings import DEFAULT_TIMEOUT  

init(autoreset=True)
console = Console()

def check_dns_over_https(domain, dns_type="A"):
    """Checks DNS over HTTPS (DoH) support for a given domain and DNS type."""
    try:
        api_url = f"https://dns.google/resolve?name={domain}&type={dns_type}"
        response = requests.get(api_url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            return "Supported"
        return "Not Supported"
    except requests.Timeout:
        console.print(Fore.RED + "[!] Request timed out.")
        return None
    except requests.ConnectionError:
        console.print(Fore.RED + "[!] Connection error. Please check your internet connection.")
        return None
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error checking DNS over HTTPS: {e}")
        return None

def display_dns_over_https(status, domain, dns_type):
    """Displays the DNS over HTTPS status in a formatted table."""
    table = Table(show_header=True, header_style="bold magenta", title=f"DoH Status for {domain} ({dns_type})")
    table.add_column("Domain", style="cyan")
    table.add_column("DNS Type", style="green")
    table.add_column("DoH Status", style="bold yellow" if status == "Supported" else "bold red")
    table.add_row(domain, dns_type, status)
    console.print(table)

def main(target, dns_type="A", retries=3):
    """Main function to process domain DoH checking with retries and DNS type options."""
    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[!] Invalid domain format. Please check the domain and try again.")
        return

    console.print(Fore.WHITE + f"[*] Checking DNS over HTTPS support for: {domain} (Type: {dns_type})")
    
    for attempt in range(retries):
        doh_status = check_dns_over_https(domain, dns_type)
        
        if doh_status:
            display_dns_over_https(doh_status, domain, dns_type)
            break
        else:
            console.print(Fore.YELLOW + f"[!] Attempt {attempt + 1}/{retries} failed. Retrying...")
            sleep(1)
    else:
        console.print(Fore.RED + "[!] All attempts failed. Could not retrieve DNS over HTTPS information.")
    
    console.print(Fore.CYAN + "[*] DNS Over HTTPS check completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        dns_type = sys.argv[2] if len(sys.argv) > 2 else "A"
        main(target, dns_type)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
