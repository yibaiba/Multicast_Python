import socket
import struct
import threading
import time
import tkinter as tk
from tkinter import messagebox
from queue import Queue

send_bytes = 0
recv_bytes = 0
recv_queue = Queue()
is_clearing_data = False
exit_event = threading.Event()

# Initialize locks
send_bytes_lock = threading.Lock()
recv_bytes_lock = threading.Lock()

# Global socket variables
send_sock = None
recv_sock = None


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
            sent = send_sock.sendto(message.encode(), (multicast_group, multicast_port))
            with send_bytes_lock:  # Acquire lock before modifying send_bytes
                send_bytes += len(message.encode())  # Correctly calculate the sent bytes
            send_bytes_label.config(text=f"发送字节: {send_bytes}")
            text_widget.insert(tk.END, f'发送数据: {message}\n')
            text_widget.see(tk.END)  # print(f"Sent {len(message.encode())} bytes")

    finally:
        print(f"Total sent bytes: {send_bytes}")  # Debugging information
        print('Closing send socket')
        send_sock.close()
        send_sock = None


def update_recv_bytes_label():
    # This function will be called in the main thread to safely update the GUI
    recv_bytes_label.config(text=f"接收字节: {recv_bytes}")


def process_queue():
    while not recv_queue.empty():
        data, addr = recv_queue.get()
        text_widget.insert(tk.END, f'收到数据: {data.decode()}\n')
        text_widget.see(tk.END)  # print(f"Received {len(data)} bytes from {addr}")  # Debugging information
    if recv_queue.empty():
        root.after(100, process_queue)  # Schedule the next processing


def receive_message(multicast_group, multicast_port, local_ip, recv_bytes_label):
    global recv_bytes, is_clearing_data, recv_sock
    # Create the datagram socket for receiving if not already created
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
    global send_bytes, recv_bytes, recv_queue
    send_bytes = 0
    recv_bytes = 0
    recv_queue.queue.clear()
    multicast_group = multicast_group_entry.get()
    multicast_port = int(multicast_port_entry.get())
    message = message_entry.get()
    local_ip = local_ip_entry.get()
    send_count = int(send_count_entry.get())
    send_bytes_label.config(text="发送字节: 0")
    recv_bytes_label.config(text="接收字节: 0")

    send_thread = threading.Thread(target=send_message, args=(multicast_group, multicast_port, message, local_ip, send_count, send_bytes_label, text_widget))
    recv_thread = threading.Thread(target=receive_message, args=(multicast_group, multicast_port, local_ip, recv_bytes_label))

    send_thread.start()
    recv_thread.start()


def clear_bytes():
    global send_bytes, recv_bytes, is_clearing_data

    is_clearing_data = True

    with send_bytes_lock, recv_bytes_lock:
        send_bytes = 0
        recv_bytes = 0
        recv_queue.queue.clear()
        send_bytes_label.config(text="发送字节: 0")
        recv_bytes_label.config(text="接收字节: 0")
    # Data has been cleared, resume receiving operations
    is_clearing_data = False


def bind_multicast():
    global recv_bytes, recv_queue
    recv_bytes = 0
    recv_queue.queue.clear()
    multicast_group = multicast_group_entry.get()
    multicast_port = int(multicast_port_entry.get())
    local_ip = local_ip_entry.get()
    recv_bytes_label.config(text="接收字节: 0")

    recv_thread = threading.Thread(target=receive_message, args=(multicast_group, multicast_port, local_ip, recv_bytes_label))
    recv_thread.start()


def on_closing():
    exit_event.set()
    root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    root.title("组播测试工具_v1.5")

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
    local_ip_entry = tk.Entry(root)
    local_ip_entry.grid(row=3, column=1, padx=10, pady=5)
    local_ip_entry.insert(0, '192.168.31.173')

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

    root.after(100, process_queue)  # Start processing the queue
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
