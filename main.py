import base64
import os
import socket
import struct
import threading
import time
import tkinter as tk
from queue import Queue
from tkinter import messagebox, ttk

import ipTool
from img.logo import imgBase64

send_bytes = 0
recv_bytes = 0
recv_queue = Queue()
is_clearing_data = False
exit_event = threading.Event()

send_bytes_lock = threading.Lock()
recv_bytes_lock = threading.Lock()

send_sock = None
recv_sock = None

is_multicast_bound = False


def send_message(multicast_group, multicast_port, message, local_ip, send_count, send_bytes_label, text_widget):
    global send_bytes, send_sock
    # Create the datagram socket for sending if not already created
    if send_sock is None:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Set the time-to-live for messages
        ttl = struct.pack('b', 1)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

    try:
        for _ in range(send_count):
            if exit_event.is_set():
                break
            # Send data to the multicast group
            time.sleep(0.02)  # Add a small delay to avoid flooding the network
            _ = send_sock.sendto(message.encode(), (multicast_group, multicast_port))
            with send_bytes_lock:  # Acquire lock before modifying send_bytes
                send_bytes += len(message.encode())  # Correctly calculate the sent bytes
            send_bytes_label.config(text=f"发送字节: {send_bytes}")
            text_widget.insert(tk.END, f'发送数据: {message}\n')
            text_widget.see(tk.END)  # print(f"Sent {len(message.encode())} bytes")

    finally:
        print(f"Total sent bytes: {send_bytes}")
        print('Closing send socket')
        send_sock.close()
        send_sock = None


def update_recv_bytes_label():
    recv_bytes_label.config(text=f"接收字节: {recv_bytes}")


def process_queue():
    while not recv_queue.empty():
        data, _ = recv_queue.get()
        text_widget.insert(tk.END, f'收到数据: {data.decode()}\n')
        text_widget.see(tk.END)  # print(f"Received {len(data)} bytes from {addr}")  # Debugging information
    if recv_queue.empty():
        root.after(100, process_queue)


def receive_message(multicast_group, multicast_port, local_ip, recv_bytes_label):
    global recv_bytes, is_clearing_data, recv_sock
    # 防止重复创建接收socket
    if recv_sock is None:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            recv_sock.bind((local_ip, multicast_port))
        except Exception as e:
            messagebox.showerror("Error", f"绑定 {local_ip} 失败: {e}")
            return

        mreq = struct.pack('4sL', socket.inet_aton(multicast_group), socket.INADDR_ANY)
        recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    try:
        while not exit_event.is_set():
            data, addr = recv_sock.recvfrom(1024)
            if is_clearing_data:
                continue
            with recv_bytes_lock:
                recv_bytes += len(data)
            recv_queue.put((data, addr))
            root.after(0, update_recv_bytes_label)

            # print(f"Total received bytes: {recv_bytes}")
    except Exception as e:
        print(f'Error: {e}')
    finally:
        print('Closing receive socket')
        recv_sock.close()
        recv_sock = None


def start_threads():
    global send_bytes, recv_bytes, recv_queue, is_multicast_bound
    send_bytes = 0
    recv_bytes = 0
    recv_queue.queue.clear()
    multicast_group = multicast_group_entry.get()
    multicast_port = int(multicast_port_entry.get())
    message = message_entry.get()
    local_ip = local_ip_entry.get()
    send_count = int(send_count_entry.get())
    exit_event.clear()
    send_thread = threading.Thread(target=send_message, args=(multicast_group, multicast_port, message, local_ip, send_count, send_bytes_label, text_widget))
    send_thread.start()
    if not is_multicast_bound:
        recv_thread = threading.Thread(target=receive_message, args=(multicast_group, multicast_port, local_ip, recv_bytes_label))
        recv_thread.start()
        is_multicast_bound = True
    send_bytes_label.config(text="发送字节: 0")
    recv_bytes_label.config(text="接收字节: 0")


def bind_multicast():
    global recv_bytes, recv_queue, is_multicast_bound
    recv_bytes = 0
    recv_queue.queue.clear()
    multicast_group = multicast_group_entry.get()
    multicast_port = int(multicast_port_entry.get())
    local_ip = local_ip_entry.get()
    recv_bytes_label.config(text="接收字节: 0")
    if not is_multicast_bound:
        recv_thread = threading.Thread(target=receive_message, args=(multicast_group, multicast_port, local_ip, recv_bytes_label))
        recv_thread.start()
        is_multicast_bound = True


def clear_bytes():
    global send_bytes, recv_bytes, is_clearing_data

    is_clearing_data = True

    with send_bytes_lock, recv_bytes_lock:
        send_bytes = 0
        recv_bytes = 0
        recv_queue.queue.clear()
        send_bytes_label.config(text="发送字节: 0")
        recv_bytes_label.config(text="接收字节: 0")
    exit_event.set()

    is_clearing_data = False


def on_closing():
    exit_event.set()
    print('Exiting...')
    root.destroy()
    os._exit(0)


def create_temp_logo():  # 处理图片
    def run():
        tmp = open("temp.ico", "wb+")  # 创建temp.ico临时文件
        tmp.write(base64.b64decode(imgBase64))  # 写入img的base64
        tmp.close()

        if os.path.exists("temp.ico"):
            # 使用wm_iconbitmap引入创建的ico
            root.wm_iconbitmap("temp.ico")
            os.remove("temp.ico")

    logo_thread = threading.Thread(target=run)
    logo_thread.start()


def update_combobox_values(combobox, values):
    combobox['values'] = values


def set_default_ip():
    def run():
        try:
            ip = ipTool.IpTool()
            local_ips = ip.get_ip()
            # text_widget.insert(tk.END, f'收到数据: {local_ips}\n')
            # text_widget.see(tk.END)
            if local_ips:
                def update_ips():
                    local_ip_entry['values'] = local_ips
                    if len(local_ips) > 0:
                        local_ip_entry.current(1)

                root.after(90, update_ips)
        except Exception as e:
            print(f"Error setting default IP: {e}")

    set_ip_thread = threading.Thread(target=run)
    set_ip_thread.start()


if __name__ == "__main__":
    root = tk.Tk()
    create_temp_logo()
    root.title("组播测试工具 v2.0")

    tk.Label(root, text="组播组IP地址:").grid(row=0, column=0, padx=10, pady=5)
    multicast_group_entry = tk.Entry(root)
    multicast_group_entry.grid(row=0, column=1, padx=10, pady=5)
    multicast_group_entry.insert(0, '224.1.1.1')

    tk.Label(root, text="组播端口:").grid(row=1, column=0, padx=10, pady=5)
    multicast_port_entry = tk.Entry(root)
    multicast_port_entry.grid(row=1, column=1, padx=10, pady=5)
    multicast_port_entry.insert(0, '5007')

    tk.Label(root, text="信息内容:").grid(row=2, column=0, padx=10, pady=5)
    message_entry = tk.Entry(root)
    message_entry.grid(row=2, column=1, padx=10, pady=5)
    message_entry.insert(0, 'Multicast message')

    tk.Label(root, text="本机IP地址:").grid(row=3, column=0, padx=10, pady=5)
    local_ip_entry = ttk.Combobox(root, width=17)
    local_ip_entry.grid(row=3, column=1, padx=10, pady=5)


    tk.Label(root, text="发送次数:").grid(row=4, column=0, padx=10, pady=5)
    send_count_entry = tk.Entry(root)
    send_count_entry.grid(row=4, column=1, padx=10, pady=5)
    send_count_entry.insert(0, '1000')

    start_button = tk.Button(root, text="发送", command=start_threads)
    start_button.grid(row=5, column=0, columnspan=10, pady=5)

    bind_button = tk.Button(root, text="绑定组播", command=bind_multicast)
    bind_button.grid(row=5, column=1, columnspan=10, pady=5)

    text_widget = tk.Text(root, height=10, width=50)
    text_widget.grid(row=7, column=0, columnspan=2, padx=10, pady=5)

    send_bytes_label = tk.Label(root, text="发送字节: 0")
    send_bytes_label.grid(row=8, column=0, padx=10, pady=5)

    recv_bytes_label = tk.Label(root, text="接收字节: 0")
    recv_bytes_label.grid(row=8, column=1, padx=10, pady=5)

    clear_button = tk.Button(root, text="清除数据", command=clear_bytes)
    clear_button.grid(row=9, column=0, columnspan=2, pady=10)
    tk.Label(root, text="by: yibaiba").grid(row=9, column=1, padx=10, pady=5, sticky="se")

    root.after(100, process_queue)  # Start processing the queue
    root.protocol("WM_DELETE_WINDOW", on_closing)
    set_default_ip()
    root.mainloop()
