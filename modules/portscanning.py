import logging
import socket
import concurrent.futures
from datetime import datetime

# Configure logging with timestamp and log level
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_port(ip, port, timeout):
    """
    Scans a single port on the given IP address.
    Returns the port status and handles errors.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    
    try:
        if not s.connect_ex((ip, port)):  # Successful connection means port is open
            return port, "OPEN"
        else:
            return port, "CLOSED"
    except socket.timeout:
        return port, "FILTERED"  # Timed out, could be filtered by firewall
    except Exception as e:
        logging.error(f"Error scanning port {port} on {ip}: {e}")
        return port, "ERROR"
    finally:
        s.close()

def port_scanner(ip, port_range, timeout=1):
    """
    Scans the specified port range on the provided IP address.
    """
    logging.info(f"Starting port scan on {ip}...")

    open_ports = []
    closed_ports = []
    filtered_ports = []

    # Parallelizing the scanning using ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # Submit scan tasks to the executor
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in range(port_range[0], port_range[1])}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port, status = future.result()
            if status == "OPEN":
                open_ports.append(port)
                logging.info(f"Port {port} on {ip} is OPEN.")
            elif status == "CLOSED":
                closed_ports.append(port)
            elif status == "FILTERED":
                filtered_ports.append(port)

    # Log the completion
    logging.info(f"Completed port scan on {ip}.")
    
    # Create result summary
    results = {
        "Open Ports": open_ports,
        "Closed Ports": closed_ports,
        "Filtered Ports": filtered_ports
    }
    return results

def print_scan_results(results):
    """
    Formats and prints the scan results.
    """
    print("\nPort Scan Results:")
    print("-" * 30)
    
    if results['Open Ports']:
        print("Open Ports:")
        for port in results['Open Ports']:
            print(f"  - Port {port} is OPEN")
    else:
        print("No open ports found.")
    
    if results['Filtered Ports']:
        print("\nFiltered Ports (Possibly firewalled):")
        for port in results['Filtered Ports']:
            print(f"  - Port {port} is FILTERED")
    
    print("\nScan complete.\n")

# Example usage
if __name__ == "__main__":
    target_ip = '192.168.181.130'
    ports_to_scan = (1, 1024)  # Define the port range
    scan_timeout = 0.5  # Custom timeout for connections
    
    scan_results = port_scanner(target_ip, ports_to_scan, timeout=scan_timeout)
    print_scan_results(scan_results)
