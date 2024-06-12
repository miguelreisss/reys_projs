import subprocess
import sys

class IPBlocker:
    def block_ip(ip_address):
        # Call iptables to block the IP
        result = subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Blocked IP: {ip_address}")
        else:
            print("Error executing iptables command:", result.stderr)

    def unblock_ip(ip_address):
        # Call iptables to unblock the IP
        result = IPBlocker.list_blocked_ip().stdout        
        if ip_address in result:
            result2 = subprocess.run(['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'], capture_output=True, text=True)
            if result2.returncode == 0:
                print(f"Unblocked IP: {ip_address}")
            else:
                print("Error executing iptables command:", result2.stderr)
        else:
            print(f"IP: {ip_address} is not blocked")
    
    def list_blocked_ip():
        # Call iptables to view the list of blocked the IP
        result = subprocess.run(['iptables', '-L', '-v'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            print("Error executing iptables command:", result.stderr)

    def print_list_blocked_ip():
        # Call iptables to print the list of blocked the IP
        result = IPBlocker().list_blocked_ip()

        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Error executing iptables command:", result.stderr)

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == '-ipb':
        IPBlocker.block_ip(args[1])
    elif len(args) == 2 and args[0] == '-ipub':
        IPBlocker.unblock_ip(args[1])
    elif len(args) == 1 and args[0] == '-iplb':
        IPBlocker.print_list_blocked_ip()
    else:
        print("Command incorrent")


