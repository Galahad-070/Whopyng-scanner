import subprocess
import platform
import threading
from scapy.all import ARP,Ether,srp,IP, ICMP,sr1
from mac_vendor_lookup import MacLookup


lock = threading.Lock()

def ping_ip(ip_address):
    system = platform.system().lower()
    if system == "windows":
        cmd = ['ping', '-n', '1', ip_address] 
    else:
        cmd = ['ping', '-c', '1', ip_address] 
    
    try:
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def ping_ip_thread(ip_address, up_ips):
    """Function to ping an IP address and append it to the list of up IPs."""
    if ping_ip(ip_address):
        with lock:  
            up_ips.append(ip_address)

def ping_ips_concurrently(ip_list):
    up_ips = []  
    threads = []

    for ip in ip_list:
        thread = threading.Thread(target=ping_ip_thread, args=(ip, up_ips))
        threads.append(thread)
        thread.start()  


    for thread in threads:
        thread.join()

    return up_ips  


def detect_device_os(ip_address):
    try:
       
        arp_request = ARP(pdst=ip_address)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = broadcast / arp_request
        answered_list = srp(arp_packet, timeout=2, verbose=0)[0]

        if not answered_list:
            return f"No response from {ip_address}\n"
        
        mac_address = answered_list[0][1].hwsrc
        vendor = MacLookup().lookup(mac_address)

        icmp_request = IP(dst=ip_address) / ICMP()
        response = sr1(icmp_request, timeout=2, verbose=0)

        if not response:
            return f"MAC: {mac_address} ({vendor}) — ICMP timed out, OS detection incomplete."

        ttl = response.ttl

        if ttl >= 128:
            os_guess = "Windows"
        elif ttl >= 64:
            os_guess = "Linux/Unix"
        elif ttl >= 255:
            os_guess = "Cisco/Networking device"
        else:
            os_guess = "Unknown"

        return f"IP: {ip_address}\nMAC: {mac_address} ({vendor})\nTTL: {ttl}\nLikely OS: {os_guess}"

    except Exception as e:
        return f"Error: {str(e)}\n"
