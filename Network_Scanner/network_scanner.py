from scapy.all import srp, Ether, ARP, IP, TCP, sr1

def network_scan(network):
    # Create an ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

    # Send the packet and capture responses
    answered_list = srp(arp_request, timeout=2, verbose=False)[0]

    # Create a list to store the results
    results = []

    # Iterate through the responses
    for element in answered_list:
        # Extract IP and MAC addresses from response
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        results.append(client_dict)

    return results

def port_scan(host, ports):
    results = []

    for port in ports:
        # Create a TCP SYN packet
        syn_packet = IP(dst=host) / TCP(dport=port, flags="S")

        # Send the packet and capture responses
        response = sr1(syn_packet, timeout=1, verbose=False)

        # Check if response received
        if response is not None:
            # Check if port is open
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                results.append({"port": port, "status": "open"})
            else:
                results.append({"port": port, "status": "closed"})

    return results

if __name__ == "__main__":
    # Define the target network
    target_network = "192.168.6.0/24"

    # Perform network scan
    hosts = network_scan(target_network)
    print("Active Hosts:")
    for host in hosts:
        print(f"IP: {host['ip']}, MAC: {host['mac']}")
        target_ports = [80, 443, 22, 23, 3389]  # Example ports, modify as needed
        # Perform port scan
        print("\nPort Scan Results:")
        port_results = port_scan(host, target_ports)
        for result in port_results:
            print(f"Port: {result['port']}, Status: {result['status']}")