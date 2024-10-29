import sys
import ssl
import socket
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box
from colorama import Fore, init
import concurrent.futures
import threading

init(autoreset=True)
console = Console()
lock = threading.Lock()

def clean_domain_input(domain: str) -> str:
    domain = domain.strip()
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    parsed_url = urlparse(domain)
    return parsed_url.hostname

def get_certificate_details(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                
                # Check for null bytes in binary certificate data
                if b'\x00' in cert_bin:
                    raise ValueError("Certificate data contains embedded null bytes, which cannot be processed.")
                
                cert = ssl.DER_cert_to_PEM_cert(cert_bin)
                x509 = ssl._ssl._test_decode_cert(cert_bin)
                return x509

    except ValueError as e:
        with lock:
            console.print(Fore.RED + f"[!] Error processing certificate from {domain}: {e}")
        return None
    except Exception as e:
        with lock:
            console.print(Fore.RED + f"[!] General error retrieving certificate from {domain}: {e}")
        return None


def display_certificate_info(domain, cert_details):
    table = Table(title=f"Certificate Details for {domain}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Field", style="cyan", justify="left")
    table.add_column("Value", style="green")
    
    # Subject Details
    subject = dict(x[0] for x in cert_details.get('subject', []))
    issuer = dict(x[0] for x in cert_details.get('issuer', []))
    serial_number = cert_details.get('serialNumber', '')
    version = cert_details.get('version', '')
    not_before = cert_details.get('notBefore', '')
    not_after = cert_details.get('notAfter', '')
    signature_algorithm = cert_details.get('signatureAlgorithm', '')
    
    table.add_row("Common Name (CN)", subject.get('commonName', 'N/A'))
    table.add_row("Organization (O)", subject.get('organizationName', 'N/A'))
    table.add_row("Organizational Unit (OU)", subject.get('organizationalUnitName', 'N/A'))
    table.add_row("Country (C)", subject.get('countryName', 'N/A'))
    table.add_row("State (ST)", subject.get('stateOrProvinceName', 'N/A'))
    table.add_row("Locality (L)", subject.get('localityName', 'N/A'))
    
    # Issuer Details
    table.add_row("Issuer CN", issuer.get('commonName', 'N/A'))
    table.add_row("Issuer O", issuer.get('organizationName', 'N/A'))
    table.add_row("Issuer C", issuer.get('countryName', 'N/A'))
    
    # Other Details
    table.add_row("Serial Number", serial_number)
    table.add_row("Version", str(version))
    table.add_row("Signature Algorithm", signature_algorithm)
    table.add_row("Valid From", not_before)
    table.add_row("Valid To", not_after)
    
    # Subject Alternative Names
    san_list = []
    for ext in cert_details.get('extensions', []):
        if ext.get('shortName') == 'subjectAltName':
            san_list = [i[1] for i in ext.get('value', ())]
            break
    table.add_row("Subject Alternative Names", ', '.join(san_list))
    
    console.print(table)

def process_domain(domain):
    domain = clean_domain_input(domain)
    with lock:
        console.print(Fore.WHITE + f"[*] Fetching certificate details for: {domain}")
    cert_details = get_certificate_details(domain)
    if cert_details:
        display_certificate_info(domain, cert_details)
    else:
        with lock:
            console.print(Fore.RED + f"[!] No certificate details found for {domain}.")

def main():
    # User input for domains and thread count
    domain_input = input("Enter the domains to analyze (separated by commas): ")
    domains = [d.strip() for d in domain_input.split(",") if d.strip()]
    
    # Default thread count and user input with validation
    while True:
        try:
            thread_count = int(input("Enter the number of concurrent threads (default 5): ") or 5)
            break
        except ValueError:
            console.print(Fore.RED + "[!] Please enter a valid integer for thread count.")

    # Concurrently process each domain
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(process_domain, domain): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            pass  # Results are handled in process_domain

    console.print(Fore.CYAN + "[*] Certificate Authority Recon completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
