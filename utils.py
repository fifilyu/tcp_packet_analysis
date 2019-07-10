#!/usr/bin/env python3

import pandas
from pyshark.packet import packet

# 全局包列表
g_pkt_list = list()


def get_packet(pkt: packet):
    """
    pyshark回调函数，用于获取包内容
    :param pkt:包对象
    :return None:
    """
    g_pkt_list.append(pkt)


def ns_timestamp_to_datetime(ns_ts: str):
    """
    纳秒时间戳转换为带纳秒的日期格式，比如 2019.07.10 00:00:01.78691234
    :param ns_ts: 纳秒时间戳
    :return:
    """
    ts = float(ns_ts)
    ts = pandas.to_datetime(ts * (10 ** 9), unit='ns')
    ts = str(ts)
    ts_len = len(ts)

    if ts_len == 19:
        ts += '.'

    ts = '{:0<29s}'.format(ts)

    return ts


def pretty_print_tcp_info(pkt: packet):
    """
    打印格式化的TCP数据
    :param pkt:
    :return None:
    """
    protocol = pkt.transport_layer
    tcp_data = pkt[protocol]

    print("绝对时间：%s, 源IP：%s，源端口：%s，目的IP：%s,目的端口：%s,协议：%s,数据包大小：%s,负载大小：%s"
          % (ns_timestamp_to_datetime(pkt.sniff_timestamp),
             '{:<15s}'.format(pkt.ip.src),
             '{:<6s}'.format(tcp_data.srcport),
             '{:<15s}'.format(pkt.ip.dst),
             '{:<6s}'.format(tcp_data.dstport),
             protocol,
             '{:<4s}'.format(pkt.captured_length),
             '{:<4s}'.format(tcp_data.len))
          )
