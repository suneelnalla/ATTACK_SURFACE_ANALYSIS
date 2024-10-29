import sys
import requests
import logging
import time
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

# Initialize colorama and rich console
init(autoreset=True)
console = Console()

# Set up logging
logging.basicConfig(
    filename="monitoring.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Configuration
SCYLLA_API_URL = "https://scylla.sh/search?q=email:*@{}&size=100"
PASTEBIN_API_URL = "https://psbdmp.ws/api/v3/search/{}"
HEADERS = {'User-Agent': 'Mozilla/5.0'}

# Scylla Monitoring
def monitor_scylla(query):
    try:
        url = SCYLLA_API_URL.format(query)
        response = requests.get(url, headers=HEADERS, timeout=30)
        response.raise_for_status()
        results = response.json()
        logging.info(f"Scylla query successful for domain: {query}")
        return results
    except requests.exceptions.ConnectionError as e:
        logging.error(f"DNS resolution failed or Scylla API is unreachable: {e}")
        print(Fore.RED + f"[!] Error querying Scylla: DNS resolution failed or API is unreachable.")
    except requests.RequestException as e:
        logging.error(f"Error querying Scylla: {e}")
        print(Fore.RED + f"[!] Error querying Scylla: {e}")
    return []

# Pastebin Monitoring with Enhanced Error Handling
def monitor_pastebin(query):
    try:
        url = PASTEBIN_API_URL.format(query)
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()

        # Check for unexpected data format
        if isinstance(data, list):
            logging.warning("Unexpected list format from Pastebin API.")
            print(Fore.RED + "[!] Unexpected response format from Pastebin API.")
            return []
        elif "data" not in data:
            logging.warning("Expected 'data' key missing in Pastebin response.")
            print(Fore.RED + "[!] No 'data' found in Pastebin API response.")
            return []

        results = data['data']
        logging.info(f"Pastebin query successful for domain: {query}")
        return results

    except requests.RequestException as e:
        logging.error(f"Error querying Pastebin dumps: {e}")
        print(Fore.RED + f"[!] Error querying Pastebin dumps: {e}")
    except ValueError as e:
        logging.error(f"Error parsing Pastebin response: {e}")
        print(Fore.RED + "[!] Error parsing Pastebin response.")

    return []

# Display Scylla Results
def display_scylla_results(results):
    if not results:
        console.print(Fore.RED + "[!] No data found on Scylla.")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Email", style="cyan", justify="left")
    table.add_column("Password", style="green")
    table.add_column("Source", style="white")

    for result in results:
        email = result.get("email", "N/A")
        password = result.get("password", "N/A")
        source = result.get("source", "N/A")
        table.add_row(email, password, source)

    console.print(table)

# Display Pastebin Results
def display_pastebin_results(results):
    if not results:
        console.print(Fore.RED + "[!] No data found on Pastebin.")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", justify="left")
    table.add_column("Title", style="green")
    table.add_column("Date", style="white")

    for result in results:
        paste_id = result.get("id", "N/A")
        title = result.get("title", "N/A")
        date = result.get("date", "N/A")
        table.add_row(paste_id, title, date)

    console.print(table)

# Main function to execute monitoring
def main(target, rate_limit=1.5):
    logging.info(f"Starting monitoring for domain: {target}")
    print(Fore.WHITE + f"[*] Monitoring for domain: {target}")

    # Monitor Scylla
    console.print(Fore.YELLOW + "[*] Querying Scylla.sh...")
    scylla_results = monitor_scylla(target)
    time.sleep(rate_limit)  # Rate limiting

    # Monitor Pastebin Dumps
    console.print(Fore.YELLOW + "[*] Querying Pastebin Dumps...")
    pastebin_results = monitor_pastebin(target)
    time.sleep(rate_limit)  # Rate limiting

    # Display results if any data is found
    if scylla_results:
        console.print(Fore.GREEN + "[+] Data found on Scylla:")
        display_scylla_results(scylla_results)
    else:
        console.print(Fore.RED + "[!] No data found on Scylla.")

    if pastebin_results:
        console.print(Fore.GREEN + "[+] Data found on Pastebin:")
        display_pastebin_results(pastebin_results)
    else:
        console.print(Fore.RED + "[!] No data found on Pastebin.")

    print(Fore.CYAN + "[*] Monitoring completed.")
    logging.info(f"Monitoring completed for domain: {target}")

# Entry point
if __name__ == "__main__":
    try:
        # Prompt user for input
        target = input("Enter the domain to monitor: ")
        rate_limit = input("Enter rate limit between API requests (default 1.5 seconds): ")
        rate_limit = float(rate_limit) if rate_limit else 1.5  # Use 1.5 if no input is provided
        
        main(target, rate_limit)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Process interrupted by user.")
        logging.warning("Process interrupted by user.")
        sys.exit(1)
    except ValueError:
        print(Fore.RED + "[!] Invalid rate limit entered. Please enter a numeric value.")
        sys.exit(1)
