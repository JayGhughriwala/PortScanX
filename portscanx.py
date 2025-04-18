# PortScanX:  An Advanced CLI Port Scanner ( still in development, not useful much )
#  -----------------------------------
#  -----------------------------------
# Please use it at your own risk
# This is a multi-threaded port scanner that checks for open
# TCP Ports on a target IP or domain, with optional banner grabbing
# It supports different port scanning profiles, output formats
#  summarize by service types
# It's mainly for running on Linux, not supported on Windows, and requires some changes.

import argparse # for parsing command line arguments
import socket # for networking operations to connect with ports
import threading # for concurrency, multi-threading
import json # for saving results in JSON format if you want
import os # for file system operations and other
import time # for measuring time
import ipaddress # for IP validation and hostname to IP 
import platform # to detect OS ( for pinging)
import subprocess # to execute shell commands (ping)
import re # for banner regex parsing
import signal # 
import sys # for reading user input keypress
import termios # for Unix terminal input 
import tty # for raw terminal input 
from queue import Queue # therad safe queue for port distribution
# if os.name == 'nt':
#     import msvcrt # for windows 
# else:
#     import termios  # for unix terminal input
#     import tty

# --------------------------- CONFIG section ---------------------------
# Port profiles (smart presets)
PORT_PROFILES = {
    "web": [80, 443, 8080, 8443], # common
    "common": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 8080],
    "full": list(range(1, 65536)) # all possible tcp ports
}

# Map common ports to service types (for summary)
SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}

# ---------------------- Reachability Check section ---------------------
def is_host_up(host):
    """Ping the host to check if it's up."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(["ping", param, "1", host], stdout=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

# ---------------------- version info detection section ---------------------

def extract_version_info(banner):
    #  try to extract version info from the banner string
    version_pattern = r"([A-Za-z\-]+)[/ ]?(\d+\.\d+(?:\.\d+)?)"
    matches = re.findall(version_pattern,banner)
    if matches:
        return ", ".join([f"{name}/{ver}" for name,ver in matches])
    return "Unknown"


# ------------------------ Scanner Logic ------------------------
def scan_port(target, port, timeout, results):
    """scan a single port if open, attempt to grab banner and version info."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout) # set how long to wait for a response
            result = s.connect_ex((target, port)) # try to connect
            if result == 0:
                banner = ""
                try:
                    s.sendall(b"\r\n") # trigger response banner
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except:
                    pass # igonre banner errors
                version_info=extract_version_info(banner)
                results.append({
                    "port": port,
                    "service": SERVICE_MAP.get(port, "Unknown"),
                    "banner": banner
                })
    except:
        pass # ignore connection errors

# ---------------------- Thread Worker ----------------------
def worker(target, queue, timeout, results):
    while not queue.empty():
        port = queue.get()
        scan_port(target, port, timeout, results)
        queue.task_done()



#-------------------- keypress mointoring for checking progress --------------------

def keypress_monitor(queue,total_ports):
    #  monitor for Ctrl+c to exit and ctrl+x , spacebar and enter key press to show progress
    
    def getch():
        fd= sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch=sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd,termios.TCSADRAIN,old_settings)
        return ch
    print("[+] Press Ctrl+C to stop , Ctrl+X or Enter/Space to view Progress\n")
    
    try:
        while not queue.empty():
            key=getch()
            if key in ('\x18','r',' ' ,'\n'): # ctrl+x ,etner or space
                percent_left=(queue.qsize()/total_ports) *100
                print(f"[*] Progress : {100 - percent_left:.2f}% complete ({total_ports - queue.qsize()}/{total_ports} ports scanned) ")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        os._exit(0)
# ------------------------ Main ------------------------
def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner - PortScanX")
    parser.add_argument("--target", required=True, help="Target IP or domain")
    parser.add_argument("--ports", help="Comma-separated list or range (e.g. 22,80,443 or 1-1024)")
    parser.add_argument("--profile", choices=PORT_PROFILES.keys(), help="Use a port profile")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=1, help="Socket timeout in seconds")
    parser.add_argument("--output", help="Path to save output result")
    parser.add_argument("--json", action="store_true", help="Save output as JSON format")
    args = parser.parse_args()

    # Resolve domain to IP
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("[!] Could not resolve target.")
        return

    print(f"[*] Target IP: {target_ip}")

    # Check reachability
    print(f"[*] Pinging target...")
    if not is_host_up(target_ip):
        print("[!] Host seems to be down or blocking ICMP requests. Proceeding anyway...")
    else:
        print("[+] Host is up.")

    # Determine port list
    port_list = []
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            port_list = list(range(start, end + 1))
        else:
            port_list = list(map(int, args.ports.split(',')))
    elif args.profile:
        port_list = PORT_PROFILES[args.profile]
    else:
        port_list = PORT_PROFILES["common"]

    print(f"[*] Scanning {len(port_list)} ports with {args.threads} threads...")
    start_time = time.time()

    queue = Queue()
    for port in port_list:
        queue.put(port)

    results = []
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(target_ip, queue, args.timeout, results))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()
    # sort results by port num
    elapsed = time.time() - start_time
    results = sorted(results, key=lambda x: x['port'])

    # Display results
    if results:
        print("\n[+] Open Ports:")
        for res in results:
            print(f" - {res['port']}/tcp ({res['service']}) => {res['banner'] if res['banner'] else 'No Banner'}")

        print(f"\n[OK] Scan completed in {elapsed:.2f} seconds. {len(results)} ports open.")

        # Save results
        if args.output:
            os.makedirs(os.path.dirname(args.output), exist_ok=True)
            with open(args.output, 'w') as f:
                for res in results:
                    f.write(f"{res['port']}/tcp ({res['service']}) => {res['banner']}\n")
            print(f"[+] Results saved to {args.output}")

        # Save JSON
        if args.json:
            json_path = args.output.replace(".txt", ".json") if args.output else f"{args.target}_scan.json"
            with open(json_path, 'w') as jf:
                json.dump(results, jf, indent=2)
            print(f"[+] JSON output saved to {json_path}")

        # Summary by service
        service_summary = {}
        for res in results:
            service = res['service']
            service_summary[service] = service_summary.get(service, 0) + 1

        print("\n[$] Service Summary:")
        for svc, count in service_summary.items():
            print(f" - {svc}: {count} port(s)")

    else:
        print("[!] No open ports found.")

if __name__ == "__main__":
    main()
