#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author：albert time:2024/7/7
import os
import re
import socket


def get_host_ip():
    """
    获取本地ipv4地址
    """
    ipv4 = []
    result = os.popen('ipconfig')
    result_str = result.read()
    # pattern 是一个字符串形式的正则表达式，flag 是一个可选参数，表示匹配模式，比如忽略大小写，多行模式等。re.i表示匹配int类型
    ipv4_pattern = re.compile('IPv4 地址[\.\s]+:\s[\d\.]+', re.I)
    p = re.compile(r'\d+\.\d+\.\d+\.\d+')
    ipv4_list = ipv4_pattern.findall(result_str)

    for i, ip in enumerate(ipv4_list, 1):
        if p.search(ip) == "None":
            print('IP Address could not be found!')
        else:
            ipv4.append(p.search(ip)[0])
    return ipv4


class IpTool:
    """
    获取本地IP地址
    """

    def __init__(self):
        self.hostname = None
        self.host_name = None
        self.host_ip = None
        self.get_self_ip()

    def get_self_ip(self):
        try:
            self.hostname = socket.gethostname()  # 获取主机名
            self.host_name, self.host_aliaslist, self.host_ip = socket.gethostbyname_ex(self.hostname)  # 获取IP

        except Exception as e:
            print('当前登录用户为中文无法正常获取ip地址,将使用其他方法获取')
            self.host_ip = get_host_ip()
            print(e)

    def get_ip(self):
        return self.host_ip
