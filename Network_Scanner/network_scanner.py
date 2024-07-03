import nmap

# Function to scan open ports on a target IP
def scan_ports(target_ip):
    nm = nmap.PortScanner()
    print(f"Scanning {target_ip} for open ports...")
    nm.scan(target_ip, '1-1024')  # Scanning ports 1-1024
    print(f"Scan results for {target_ip}:")
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}")
    return nm

if __name__ == "__main__":
    # Define the target network
    target_network = input("Enter network: ")
    scan_ports(target_network)
