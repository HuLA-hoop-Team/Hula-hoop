#!/usr/bin/env python
import sys
import struct
import os
import argparse

from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

global count
global maxCount
count = 0
maxCount = 10  # 设定一个初始值

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [
        _IPOption_HDR,
        FieldLenField(
            "length",
            None,
            fmt="B",
            length_of="swids",
            adjust=lambda pkt, l: l + 4,
        ),
        ShortField("count", 0),
        FieldListField(
            "swids",
            [],
            IntField("", 0),
            length_from=lambda pkt: pkt.count * 4,
        ),
    ]


class Hula(Packet):
    fields_desc = [BitField("dst_tor", 0, 24), BitField("path_util", 0, 8)]


def handle_pkt(pkt, show_probes):
    global count, maxCount
    if pkt.haslayer(Hula) and not show_probes:
        return
    else:
        pkt.show2()
        sys.stdout.flush()
        # 发送 ACK 数据包
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if(pkt[TCP].ack == 0):
                count += 1
                print(count)
                if count >= maxCount:
                    count = 0
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    seq = pkt[TCP].seq
                    ack = pkt[TCP].seq + len(pkt[TCP].payload)  # 计算 ACK 值
                    isAck = 1

                    # 构造 ACK 数据包
                    ack_pkt = (
                        IP(src=dst_ip, dst=src_ip) /
                        TCP(sport=dst_port, dport=src_port, flags="A", seq=seq, ack=isAck)
                    )
                    send(ack_pkt)
                    print("Sent ACK packet:")
                    ack_pkt.show2()


bind_layers(IP, Hula, proto=66)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p',
        '--show-probes',
        help='Parse and show probe packets',
        action='store_true',
        required=False,
        default=False,
    )
    return parser.parse_args()


def main():
    args = get_args()
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = list(ifaces)[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x, args.show_probes))


if __name__ == '__main__':
    main()
