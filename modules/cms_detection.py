import sys, os
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

# Import custom utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from util import clean_url, make_request, validate_url

init(autoreset=True)
console = Console()

CMS_SIGNATURES = {
    # CMS Signatures here (as in the original code)
    "WordPress": {
        "meta_generator": "WordPress",
        "html_comments": "wp-content",
        "path_indicators": ["/wp-content/", "/wp-includes/", "/wp-json/"]
    },
    # Add other CMS details (not shown here for brevity)
}

def detect_cms_from_meta(soup):
    """Check for CMS signatures in meta tags."""
    for cms, details in CMS_SIGNATURES.items():
        meta_tag = soup.find("meta", {"name": "generator"})
        if meta_tag and details["meta_generator"] in meta_tag.get("content", ""):
            return cms
    return None

def detect_cms_from_html_comments(html_content):
    """Check for CMS signatures in HTML comments."""
    for cms, details in CMS_SIGNATURES.items():
        if details["html_comments"] in html_content:
            return cms
    return None

def detect_cms_from_paths(url):
    """Check for CMS-specific paths."""
    for cms, details in CMS_SIGNATURES.items():
        for path in details["path_indicators"]:
            test_url = f"{url.rstrip('/')}{path}"
            response = make_request(test_url)
            if response and response.status_code == 200:
                return cms
    return None

def enumerate_cms(target):
    """Main function to detect the CMS based on various indicators."""
    try:
        cleaned_url = clean_url(target)
        if not validate_url(cleaned_url):
            console.print(Fore.RED + f"[!] Invalid URL: {target}")
            return None

        response = make_request(cleaned_url)
        if not response or response.status_code != 200:
            console.print(Fore.RED + f"[!] Error: Received status code {response.status_code}")
            return None

        soup = BeautifulSoup(response.content, 'html.parser')
        html_content = response.text

        # Check in meta tags
        detected_cms = detect_cms_from_meta(soup)
        if detected_cms:
            return detected_cms

        # Check in HTML comments
        detected_cms = detect_cms_from_html_comments(html_content)
        if detected_cms:
            return detected_cms

        # Check in CMS-specific paths
        detected_cms = detect_cms_from_paths(cleaned_url)
        if detected_cms:
            return detected_cms

        return "Unknown CMS"
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error: {e}")
        return None

def display_cms_result(cms_name):
    """Display the CMS detection result in a table format."""
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("CMS Detection Result", style="cyan", justify="left")
    table.add_row(cms_name)
    console.print(table)

def main():
    target = input("Enter the target URL to analyze: ").strip()

    console.print(Fore.WHITE + f"[*] Enumerating CMS for: {target}")
    cms_name = enumerate_cms(target)
    if cms_name:
        display_cms_result(cms_name)
    else:
        console.print(Fore.RED + "[!] CMS could not be detected.")
    console.print(Fore.CYAN + "[*] CMS Enumeration completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
