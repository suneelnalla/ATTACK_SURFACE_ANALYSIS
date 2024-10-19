import socket
import threading
import json
from datetime import datetime

# Function to grab banner from a specific IP and port
def banner_grabbing(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode().strip()
            print(f"Banner on port {port}: {banner}")
            return {'port': port, 'banner': banner}
        except socket.timeout:
            print(f"Timeout on port {port}")
            return {'port': port, 'error': 'Timeout'}
        finally:
            s.close()
    except ConnectionRefusedError:
        print(f"Connection refused on port {port}")
        return {'port': port, 'error': 'Connection refused'}
    except socket.gaierror:
        print(f"Host unreachable: {ip}")
        return {'port': port, 'error': 'Host unreachable'}
    except Exception as e:
        print(f"Error on port {port}: {e}")
        return {'port': port, 'error': str(e)}

# Multithreaded worker for banner grabbing
def banner_worker(ip, ports, timeout, results):
    for port in ports:
        result = banner_grabbing(ip, port, timeout)
        results.append(result)

# Function to run multithreaded banner grabbing for multiple ports
def run_banner_grabber(ip, ports, timeout=2):
    results = []
    threads = []
    num_threads = min(10, len(ports))  # Limit to 10 threads to prevent excessive system resource use
    chunk_size = len(ports) // num_threads

    for i in range(num_threads):
        start = i * chunk_size
        if i == num_threads - 1:
            end = len(ports)
        else:
            end = (i + 1) * chunk_size

        thread = threading.Thread(target=banner_worker, args=(ip, ports[start:end], timeout, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return results

# Save the results to a JSON file
def save_results_to_file(ip, results):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"banner_results_{ip}_{timestamp}.json"
    with open(filename, 'w') as file:
        json.dump(results, file, indent=4)
    print(f"Results saved to {filename}")

# Main function
if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    target_ports = input("Enter target ports (comma-separated or a range, e.g., 80,443 or 1-1024): ")

    # Parse ports input
    if '-' in target_ports:
        start_port, end_port = map(int, target_ports.split('-'))
        ports = list(range(start_port, end_port + 1))
    else:
        ports = [int(port.strip()) for port in target_ports.split(',')]

    timeout = int(input("Enter timeout (in seconds, default is 2): ") or 2)

    # Run the banner grabber
    results = run_banner_grabber(target_ip, ports, timeout)

    # Save the results
    save_results_to_file(target_ip, results)
