#!/usr/bin/env python3

import pyshark
from utils import get_packet
from utils import pretty_print_tcp_info
from utils import g_pkt_list

cap_file = pyshark.FileCapture('TCP数据包文件.cap')
session_dict = dict()


def print_tcp_by_session():
    """
    按TCP会话分组打印数据字段信息
    :return:
    """
    for key, pkt_list in session_dict.items():
        for pkt in pkt_list:
            if pkt.transport_layer:
                pretty_print_tcp_info(pkt)


def tcp_capture_file_to_list():
    """
    将TCP数据文件转换为Python数组
    :return:
    """
    for pkt in g_pkt_list:
        # 判断是否存在传输层，比如TCP。ICMP是没有传输层的
        if pkt.transport_layer:
            # pretty_print_tcp_info(pkt)

            src_ip = pkt.ip.src
            src_port = pkt[pkt.transport_layer].srcport

            dst_ip = pkt.ip.dst
            dst_port = pkt[pkt.transport_layer].dstport

            key = '%s:%s %s:%s' % (src_ip, src_port, dst_ip, dst_port)

            if key in session_dict:
                session_dict[key].append(pkt)
            else:
                session_dict[key] = [pkt]
        else:
            pass


def main():
    cap_file.apply_on_packets(get_packet, timeout=100)
    tcp_capture_file_to_list()
    print_tcp_by_session()


if __name__ == '__main__':
    main()
