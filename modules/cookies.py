import sys
import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box
from colorama import Fore, init
import concurrent.futures
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10

def clean_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def get_cookies_using_requests(url):
    try:
        session = requests.Session()
        response = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        response.raise_for_status()  # Raise an error for bad responses
        return session.cookies
    except requests.RequestException as e:
        console.print(Fore.RED + f"[!] Error retrieving cookies from {url} using requests: {e}")
        return None

def get_cookies_using_selenium(url):
    try:
        options = Options()
        options.headless = True  # Run in headless mode (no GUI)
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
        driver.get(url)
        
        # Allow some time for JavaScript to run and cookies to be set
        driver.implicitly_wait(DEFAULT_TIMEOUT)
        
        cookies = driver.get_cookies()
        driver.quit()
        return cookies
    except Exception as e:
        console.print(Fore.RED + f"[!] Error retrieving cookies from {url} using Selenium: {e}")
        return None

def get_cookies(url):
    cookies = get_cookies_using_requests(url)
    if cookies is None or not cookies:
        console.print(Fore.YELLOW + f"[!] No cookies found using requests, trying Selenium...")
        cookies = get_cookies_using_selenium(url)
    return cookies

def analyze_cookies(cookies, url):
    issues = []
    for cookie in cookies:
        # Check for Secure flag
        if not cookie['secure'] and urlparse(url).scheme == 'https':
            issues.append(f"Cookie '{cookie['name']}' is missing the Secure flag over HTTPS.")
        # Check for HttpOnly flag
        if 'HttpOnly' not in cookie:
            issues.append(f"Cookie '{cookie['name']}' is missing the HttpOnly flag.")
        # Check for SameSite attribute
        if 'SameSite' not in cookie:
            issues.append(f"Cookie '{cookie['name']}' is missing the SameSite attribute.")
    return issues

def display_cookies(cookies, url):
    table = Table(title=f"Cookies for {url}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Domain", style="yellow")
    table.add_column("Path", style="blue")
    table.add_column("Secure", style="red")
    table.add_column("HttpOnly", style="red")
    table.add_column("SameSite", style="red")

    for cookie in cookies:
        secure = 'Yes' if cookie['secure'] else 'No'
        httponly = 'Yes' if 'HttpOnly' in cookie else 'No'
        samesite = cookie.get('SameSite', 'None')
        table.add_row(cookie['name'], cookie['value'], cookie['domain'], cookie['path'], secure, httponly, samesite)

    console.print(table)

    issues = analyze_cookies(cookies, url)
    if issues:
        console.print(Fore.YELLOW + "[!] Security Issues Detected:")
        for issue in issues:
            console.print(Fore.YELLOW + f"    - {issue}")
    else:
        console.print(Fore.GREEN + "[+] No security issues detected with cookies.")

def process_url(url):
    url = clean_url(url)
    console.print(Fore.WHITE + f"[*] Fetching cookies for: {url}")
    cookies = get_cookies(url)
    if cookies:
        display_cookies(cookies, url)
    else:
        console.print(Fore.RED + f"[!] No cookies found for {url}.")
    console.print(Fore.WHITE + f"[*] Cookie analysis completed for {url}.\n")

def main():
    console.print(Fore.WHITE + "Welcome to the Argus - Advanced Cookie Analyzer.")
    while True:
        target_url = input(Fore.CYAN + "[*] Enter the target URL (or type 'exit' to quit): ").strip()
        if target_url.lower() == 'exit':
            console.print(Fore.GREEN + "[*] Exiting the Cookie Analyzer.")
            break
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(process_url, target_url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
