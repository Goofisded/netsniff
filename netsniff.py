#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ====================== DEPENDENCIES ======================
import argparse
import sys
import time
from collections import defaultdict
from datetime import datetime
import signal
import platform
from scapy.all import *
from colorama import Fore, Style, init
from pyfiglet import Figlet

init(autoreset=True)  

# ====================== GLOBAL VARIABLES & CONFIG (Change only if you know the stuff you are doing!!!) ======================
CONFIG = {
    "CHECK_INTERVAL": 5,      # Seconds between stats updates
    "SCAN_THRESHOLD": 15,     # SYN packets/min to trigger port scan alert
    "DNS_THRESHOLD": 50,      # DNS queries/min to trigger alert
    "WHITELISTED_IPS": ["8.8.8.8", "1.1.1.1"],  # Trusted IP addresses
    "LOG_FILE": "netsniff.log"
}

COLORS = {
    "INFO": Fore.CYAN,
    "WARNING": Fore.YELLOW,
    "ALERT": Fore.RED,
    "SUCCESS": Fore.GREEN,
    "DEBUG": Fore.MAGENTA
}

BANNER = Figlet(font='slant').renderText('NetSniff')

# ====================== MAIN ======================
class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.connections = defaultdict(lambda: {
            'destinations': defaultdict(lambda: defaultdict(int)),
            'total': 0,
            'syn_count': 0
        })
        self.alerts = []
        self.start_time = time.time()
        self.running = True
        self.protocols = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "OTHER": 0
        }
        
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.display_stats(final=True)
        self.running = False
        print(f"\n{COLORS['INFO']}[*] Cleaning up...")
        sys.exit(0)

    def log_event(self, event_type, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{event_type}] {message}"
        
        with open(CONFIG["LOG_FILE"], "a") as f:
            f.write(log_entry + "\n")
        
        self.alerts.append(log_entry)

    def display_banner(self):
        print(f"{COLORS['SUCCESS']}{BANNER}")
        print(f"{'='*50}")
        print(f"{COLORS['INFO']} Monitoring interface: {self.interface}")
        print(f"{COLORS['INFO']} Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*50}\n")

    def display_stats(self, final=False):
        os_name = platform.system()
        clear_cmd = "cls" if os_name == "Windows" else "clear"
        os.system(clear_cmd) if not final else None
        
        print(f"{COLORS['INFO']}\n{'='*50}")
        print(f"{COLORS['SUCCESS']} Network Statistics (Updated: {datetime.now().strftime('%H:%M:%S')})")
        print(f"{COLORS['INFO']}{'='*50}")
        print(f"\n{COLORS['INFO']}[ Protocol Breakdown ]")
        for proto, count in self.protocols.items():
            print(f"  {proto.ljust(6)}: {COLORS['DEBUG']}{count}")
            
    
        print(f"\n{COLORS['INFO']}[ Top Talkers ]")
        try:
            talker_stats = [
                (src, data['total']) 
                for src, data in self.connections.items()
            ]
        
            sorted_talkers = sorted(talker_stats, key=lambda x: x[1], reverse=True)[:5]
        
            for src, total in sorted_talkers:
                print(f"  {src.ljust(15)} => {COLORS['DEBUG']}{total} packets")
            
        except Exception as e:
            self.log_event("ERROR", f"Talker stats failed: {str(e)}")
            print(f"{COLORS['ALERT']}[!] Stats error: {str(e)}")

    def process_packet(self, packet):
        try:
            src_ip = dst_ip = port = None
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if src_ip in CONFIG["WHITELISTED_IPS"] or dst_ip in CONFIG["WHITELISTED_IPS"]:
                    return

      
                if packet.haslayer(TCP):
                    self.protocols["TCP"] += 1
                    tcp_layer = packet[TCP]
                    port = tcp_layer.dport
                    self.track_connection(src_ip, dst_ip, port)

                    if 'S' in str(tcp_layer.flags):
                        self.connections[src_ip]['syn_count'] += 1
                        if self.connections[src_ip]['syn_count'] > CONFIG["SCAN_THRESHOLD"]:
                            msg = f"Port scan detected from {src_ip} (SYN packets: {self.connections[src_ip]['syn_count']})"
                            self.log_event("ALERT", msg)
                            print(f"{COLORS['ALERT']}[!] {msg}")

                elif packet.haslayer(UDP):
                    self.protocols["UDP"] += 1

                elif packet.haslayer(ICMP):
                    self.protocols["ICMP"] += 1
                    msg = f"ICMP packet detected: {src_ip} -> {dst_ip}"
                    self.log_event("WARNING", msg)

                if packet.haslayer(DNSQR):
                    self.protocols["DNS"] += 1
                    query = packet[DNSQR].qname.decode(errors='ignore').rstrip('.')
                    self.log_event("INFO", f"DNS Query: {query}")

        except Exception as e:
            error_src = src_ip if src_ip else "Unknown"
            packet_summary = packet.summary() if hasattr(packet, 'summary') else "Malformed packet"
            self.log_event("ERROR", 
                f"Packet processing failed from {error_src}: {str(e)}\n"
                f"Packet Summary: {packet_summary}")

    def track_connection(self, src_ip, dst_ip, port):
        self.connections[src_ip]['destinations'][dst_ip][port] += 1
        self.connections[src_ip]['total'] += 1

        if port > 49152 and self.connections[src_ip]['destinations'][dst_ip][port] > 10:
            msg = f"High traffic on port {port} from {src_ip} to {dst_ip}"
            self.log_event("WARNING", msg)
            print(f"{COLORS['WARNING']}[*] {msg}")

    def start_monitoring(self):
        self.display_banner()
        last_update = time.time()
        
        sniff_kwargs = {
            'prn': self.process_packet,
            'store': 0,
            'iface': self.interface,
            'filter': 'ip'  
        }
        
        sniff_thread = AsyncSniffer(**sniff_kwargs)
        sniff_thread.start()
        
        try:
            while self.running:
                if time.time() - last_update >= CONFIG["CHECK_INTERVAL"]:
                    self.display_stats()
                    last_update = time.time()
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.signal_handler(None, None)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{COLORS['SUCCESS']}NetSniff - Advanced Network Monitoring Tool{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-i", "--interface", required=True,
                      help="Network interface to monitor")
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose output")
    
    args = parser.parse_args()
    
    try:
        print(f"{COLORS['INFO']}[*] Initializing NetSniff...")
        monitor = NetworkMonitor(args.interface)
        monitor.start_monitoring()
        
    except PermissionError:
        print(f"{COLORS['ALERT']}[!] Error: Requires administrator privileges!")
        sys.exit(1)
        
    except Exception as e:
        print(f"{COLORS['ALERT']}[!] Critical error: {str(e)}")
        sys.exit(1)
