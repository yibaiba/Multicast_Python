#!/usr/bin/env python
# -*- coding: utf-8 -*-
# author：albert time:2024/7/7
import base64
import os

open_icon = open("./cat.ico", "rb")
b64str = base64.b64encode(open_icon.read())  # 转换为base64编码
open_icon.close()
write_data = "imgBase64 = %s" % b64str
os.makedirs("./img", exist_ok=True)
f = open("./img/logo.py", "w+")
f.write(write_data)
f.close()
