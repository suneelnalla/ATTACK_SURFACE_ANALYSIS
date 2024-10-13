import nmap

def external_port_scan(target_ip):
    # Initialize the Nmap Port Scanner
    nm = nmap.PortScanner()
    
    # Define the ports to scan (common external ports)
    common_ports = '22,80,443,21,25,53,110,143,3389'
    
    print(f"Starting scan on {target_ip} for specified external ports: {common_ports}...")
    
    # Scan the target IP on the specified ports
    scan_result = nm.scan(target_ip, common_ports, arguments='-Pn')  # -Pn skips host discovery

    # Check if the host is up
    if nm[target_ip].state() == 'up':
        print(f"Host {target_ip} is up.")
        
        # Iterate through the scanned ports and print open ones
        if 'tcp' in nm[target_ip]:
            print(f"Open ports on {target_ip}:")
            for port in nm[target_ip]['tcp']:
                state = nm[target_ip]['tcp'][port]['state']
                name = nm[target_ip]['tcp'][port]['name']
                print(f"Port {port}: {state} (Service: {name})")
        else:
            print("No open TCP ports found.")
    else:
        print(f"Host {target_ip} is down or unreachable.")

if __name__ == "__main__":
    # User inputs the target IP address
    target_ip = input("Enter the target IP address: ")
    
    # Perform the scan
    external_port_scan(target_ip)
