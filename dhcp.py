import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import struct
import random
import threading
import time
from datetime import datetime
import uuid

# DHCP Message Types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

class DHCPPacket:
    def __init__(self):
        self.op = 1  # 1 for client request, 2 for server reply
        self.htype = 1  # Hardware type (Ethernet)
        self.hlen = 6  # Hardware address length
        self.hops = 0
        self.xid = 0  # Transaction ID
        self.secs = 0
        self.flags = 0
        self.ciaddr = '0.0.0.0'  # Client IP
        self.yiaddr = '0.0.0.0'  # Your IP
        self.siaddr = '0.0.0.0'  # Server IP
        self.giaddr = '0.0.0.0'  # Gateway IP
        self.chaddr = b'\x00' * 16  # Client hardware address
        self.options = []

    def pack(self):
        packet = struct.pack('!BBBB', self.op, self.htype, self.hlen, self.hops)
        packet += struct.pack('!I', self.xid)
        packet += struct.pack('!HH', self.secs, self.flags)
        packet += socket.inet_aton(self.ciaddr)
        packet += socket.inet_aton(self.yiaddr)
        packet += socket.inet_aton(self.siaddr)
        packet += socket.inet_aton(self.giaddr)
        packet += self.chaddr
        packet += b'\x00' * 192  # Server name and boot file
        packet += struct.pack('!I', 0x63825363)  # Magic cookie

        for option in self.options:
            packet += option

        packet += b'\xff'  # End option
        return packet

    @staticmethod
    def unpack(data):
        packet = DHCPPacket()
        packet.op, packet.htype, packet.hlen, packet.hops = struct.unpack('!BBBB', data[0:4])
        packet.xid = struct.unpack('!I', data[4:8])[0]
        packet.secs, packet.flags = struct.unpack('!HH', data[8:12])
        packet.ciaddr = socket.inet_ntoa(data[12:16])
        packet.yiaddr = socket.inet_ntoa(data[16:20])
        packet.siaddr = socket.inet_ntoa(data[20:24])
        packet.giaddr = socket.inet_ntoa(data[24:28])
        packet.chaddr = data[28:44]

        # Parse options
        i = 240
        while i < len(data) and data[i] != 0xff:
            opt_type = data[i]
            if opt_type == 0:  # Pad
                i += 1
                continue
            # protect against malformed packet
            if i + 1 >= len(data):
                break
            opt_len = data[i + 1]
            if (i + 2 + opt_len) > len(data):
                break
            opt_data = data[i + 2:i + 2 + opt_len]
            packet.options.append((opt_type, opt_data))
            i += 2 + opt_len

        return packet

    def get_option(self, opt_type):
        for opt, data in self.options:
            if opt == opt_type:
                return data
        return None

class DHCPServer:
    def __init__(self, server_ip='192.168.1.1', pool_start='192.168.1.100',
                 pool_end='192.168.1.200', subnet_mask='255.255.255.0',
                 gateway='192.168.1.1', dns='8.8.8.8', lease_time=10):
        self.server_ip = server_ip
        self.pool_start = self.ip_to_int(pool_start)
        self.pool_end = self.ip_to_int(pool_end)
        self.subnet_mask = subnet_mask
        self.gateway = gateway
        self.dns = dns
        self.lease_time = lease_time
        self.leases = {}  # MAC -> (IP, expiry_time)
        self.running = False
        self.sock = None
        self.log_callback = None

    def ip_to_int(self, ip):
        return struct.unpack('!I', socket.inet_aton(ip))[0]

    def int_to_ip(self, num):
        return socket.inet_ntoa(struct.pack('!I', num))

    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_msg = f"[{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_msg)

    def get_available_ip(self, mac):
        # Check if client already has a lease
        if mac in self.leases:
            ip, expiry = self.leases[mac]
            if time.time() < expiry:
                return ip

        # Find available IP
        for ip_int in range(self.pool_start, self.pool_end + 1):
            ip = self.int_to_ip(ip_int)
            if ip not in [lease[0] for lease in self.leases.values()]:
                return ip
        return None

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        try:
            self.sock.bind(('', 67))
            self.log(f"DHCP Server started on {self.server_ip}")

            while self.running:
                try:
                    self.sock.settimeout(1.0)
                    data, addr = self.sock.recvfrom(1024)
                    self.handle_packet(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log(f"Error: {e}")
        except Exception as e:
            self.log(f"Failed to start server: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self.log("DHCP Server stopped")

    def handle_packet(self, data, addr):
        packet = DHCPPacket.unpack(data)
        msg_type_data = packet.get_option(53)

        if not msg_type_data:
            return

        msg_type = msg_type_data[0]
        mac = packet.chaddr[:6].hex(':')
        print(f"Received message type {msg_type} from {mac}")
        if msg_type == DHCP_DISCOVER:
            self.log(f"DISCOVER from {mac}")
            self.send_offer(packet, mac)
        elif msg_type == DHCP_REQUEST:
            self.log(f"REQUEST from {mac}")
            self.send_ack(packet, mac)
        elif msg_type == DHCP_RELEASE:
            self.log(f"RELEASE from {mac}")
            if mac in self.leases:
                del self.leases[mac]

    def send_offer(self, request, mac):
        ip = self.get_available_ip(mac)
        if not ip:
            self.log("No available IPs in pool")
            return

        response = DHCPPacket()
        response.op = 2
        response.xid = request.xid
        response.yiaddr = ip
        response.siaddr = self.server_ip
        response.chaddr = request.chaddr
        response.flags = request.flags

        # DHCP Message Type: OFFER
        response.options.append(struct.pack('!BBB', 53, 1, DHCP_OFFER))
        # Server Identifier
        response.options.append(struct.pack('!BB', 54, 4) + socket.inet_aton(self.server_ip))
        # Lease Time
        response.options.append(struct.pack('!BBI', 51, 4, self.lease_time))
        # Subnet Mask
        response.options.append(struct.pack('!BB', 1, 4) + socket.inet_aton(self.subnet_mask))
        # Router
        response.options.append(struct.pack('!BB', 3, 4) + socket.inet_aton(self.gateway))
        # DNS
        response.options.append(struct.pack('!BB', 6, 4) + socket.inet_aton(self.dns))

        self.sock.sendto(response.pack(), ('<broadcast>', 68))
        self.log(f"OFFER sent: {ip} to {mac}")

    # def send_ack(self, request, mac):
    #     requested_ip_data = request.get_option(50)
    #     if requested_ip_data and len(requested_ip_data) == 4:
    #         ip = socket.inet_ntoa(requested_ip_data)
    #     else:
    #         ip = request.ciaddr if request.ciaddr != '0.0.0.0' else request.yiaddr

    #     # If ip still empty, try to allocate one
    #     if not ip or ip == '0.0.0.0':
    #         ip = self.get_available_ip(mac)
    #         if not ip:
    #             self.log("No available IPs to ACK")
    #             return

    #     response = DHCPPacket()
    #     response.op = 2
    #     response.xid = request.xid
    #     response.yiaddr = ip
    #     response.siaddr = self.server_ip
    #     response.chaddr = request.chaddr
    #     response.flags = request.flags

    #     # DHCP Message Type: ACK
    #     response.options.append(struct.pack('!BBB', 53, 1, DHCP_ACK))
    #     # Server Identifier
    #     response.options.append(struct.pack('!BB', 54, 4) + socket.inet_aton(self.server_ip))
    #     # Lease Time
    #     response.options.append(struct.pack('!BBI', 51, 4, self.lease_time))
    #     # Subnet Mask
    #     response.options.append(struct.pack('!BB', 1, 4) + socket.inet_aton(self.subnet_mask))
    #     # Router
    #     response.options.append(struct.pack('!BB', 3, 4) + socket.inet_aton(self.gateway))
    #     # DNS
    #     response.options.append(struct.pack('!BB', 6, 4) + socket.inet_aton(self.dns))

    #     self.sock.sendto(response.pack(), ('<broadcast>', 68))

    #     # Record lease
    #     expiry = time.time() + self.lease_time
    #     self.leases[mac] = (ip, expiry)

    #     self.log(f"ACK sent: {ip} to {mac}")
    def send_ack(self, request, mac):
        """
        Robust ACK handler:
        - Treat as renewal if (ciaddr set & no option 50) OR (we already have a lease for this MAC & no option 50).
        - Unicast ACK for renewals (to leased IP), broadcast ACK for normal requests.
        """
        requested_opt = request.get_option(50)  # requested IP option (may be None)
        ciaddr = request.ciaddr

        # Determine if this should be treated as a renewal
        is_renewal = (ciaddr != "0.0.0.0" and requested_opt is None) or (mac in self.leases and requested_opt is None)

        if is_renewal:
            # Prefer ciaddr if present, otherwise use the IP we have in lease
            if ciaddr != "0.0.0.0":
                ip = ciaddr
            else:
                ip, expiry = self.leases.get(mac, (None, None))
                if ip is None:
                    # No lease to renew, fall back to normal processing
                    is_renewal = False

        if is_renewal:
            self.log(f"RENEWAL REQUEST from {mac} for {ip}")

            response = DHCPPacket()
            response.op = 2
            response.xid = request.xid
            response.yiaddr = ip
            response.siaddr = self.server_ip
            response.chaddr = request.chaddr
            response.flags = 0  # unicast

            # ACK + common options
            response.options.append(struct.pack('!BBB', 53, 1, DHCP_ACK))
            response.options.append(struct.pack('!BB', 54, 4) + socket.inet_aton(self.server_ip))
            response.options.append(struct.pack('!BBI', 51, 4, self.lease_time))
            response.options.append(struct.pack('!BB', 1, 4) + socket.inet_aton(self.subnet_mask))
            response.options.append(struct.pack('!BB', 3, 4) + socket.inet_aton(self.gateway))
            response.options.append(struct.pack('!BB', 6, 4) + socket.inet_aton(self.dns))

            # Try unicast to client IP; fall back to broadcast if that fails
            try:
                # self.sock.sendto(response.pack(), (ip, 68))
                # SEND BROADCAST for renewal, because client cannot receive unicast
                self.sock.sendto(response.pack(), ('<broadcast>', 68))

            except Exception:
                try:
                    self.sock.sendto(response.pack(), ('<broadcast>', 68))
                except Exception as e:
                    self.log(f"Failed to send renewal ACK to {ip}: {e}")
                    return

            # Refresh/record lease
            expiry = time.time() + self.lease_time
            self.leases[mac] = (ip, expiry)

            self.log(f"Lease renewed for {mac}: {ip}")
            return

        # ---------- Normal REQUEST handling ----------
        # If option 50 present use it; else prefer ciaddr (if not 0) else yiaddr
        if requested_opt and len(requested_opt) == 4:
            ip = socket.inet_ntoa(requested_opt)
        else:
            ip = ciaddr if ciaddr != "0.0.0.0" else request.yiaddr

        # allocate if needed
        if not ip or ip == "0.0.0.0":
            ip = self.get_available_ip(mac)
            if not ip:
                self.log("No IP available for ACK")
                return

        response = DHCPPacket()
        response.op = 2
        response.xid = request.xid
        response.yiaddr = ip
        response.siaddr = self.server_ip
        response.chaddr = request.chaddr
        response.flags = request.flags

        # ACK + common options
        response.options.append(struct.pack('!BBB', 53, 1, DHCP_ACK))
        response.options.append(struct.pack('!BB', 54, 4) + socket.inet_aton(self.server_ip))
        response.options.append(struct.pack('!BBI', 51, 4, self.lease_time))
        response.options.append(struct.pack('!BB', 1, 4) + socket.inet_aton(self.subnet_mask))
        response.options.append(struct.pack('!BB', 3, 4) + socket.inet_aton(self.gateway))
        response.options.append(struct.pack('!BB', 6, 4) + socket.inet_aton(self.dns))

        # Broadcast ACK for normal bind/select path
        try:
            self.sock.sendto(response.pack(), ('<broadcast>', 68))
        except Exception as e:
            self.log(f"Failed to send ACK broadcast: {e}")
            return

        # Record lease
        expiry = time.time() + self.lease_time
        self.leases[mac] = (ip, expiry)

        self.log(f"ACK sent to {mac} for {ip}")


class DHCPClient:
    def __init__(self):
        self.mac = self.generate_mac()
        self.ip = None
        self.server_ip = None
        self.subnet_mask = None
        self.gateway = None
        self.dns = None
        self.lease_time = None
        self.xid = random.randint(0, 0xFFFFFFFF)
        self.sock = None
        self.log_callback = None

        # Renewal management
        self.renew_thread = None
        self.renew_stop_event = threading.Event()
        self.renewal_count = 0
        self.lease_expiry = None

    def generate_mac(self):
        mac = uuid.getnode()
        return mac.to_bytes(6, 'big')

    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_msg = f"[{timestamp}] {message}"
        if self.log_callback:
            self.log_callback(log_msg)

    def discover(self):
        self.log(f"Sending DISCOVER (MAC: {self.mac.hex(':')})")

        packet = DHCPPacket()
        packet.xid = self.xid
        packet.chaddr = self.mac + b'\x00' * 10
        packet.flags = 0x8000  # Broadcast flag

        # DHCP Message Type: DISCOVER
        packet.options.append(struct.pack('!BBB', 53, 1, DHCP_DISCOVER))
        # Parameter Request List (common params)
        packet.options.append(struct.pack('!BBBBBB', 55, 4, 1, 3, 6, 15))

        # Create socket
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # try to bind to port 68 if possible (may require permissions)
        try:
            self.sock.bind(('', 68))
        except Exception:
            # If bind fails (e.g. already in use), still proceed (some systems allow ephemeral port)
            pass

        try:
            self.sock.sendto(packet.pack(), ('<broadcast>', 67))
        except Exception as e:
            self.log(f"Failed to send DISCOVER: {e}")
            return False

        return self.wait_for_offer()

    def wait_for_offer(self):
        if not self.sock:
            return False
        self.sock.settimeout(5.0)
        try:
            data, addr = self.sock.recvfrom(1024)
            packet = DHCPPacket.unpack(data)

            if packet.xid != self.xid:
                return False

            msg_type_data = packet.get_option(53)
            if msg_type_data and msg_type_data[0] == DHCP_OFFER:
                self.ip = packet.yiaddr

                server_id = packet.get_option(54)
                if server_id:
                    self.server_ip = socket.inet_ntoa(server_id)

                lease_time = packet.get_option(51)
                if lease_time and len(lease_time) == 4:
                    self.lease_time = struct.unpack('!I', lease_time)[0]

                subnet_mask = packet.get_option(1)
                if subnet_mask and len(subnet_mask) == 4:
                    self.subnet_mask = socket.inet_ntoa(subnet_mask)

                router = packet.get_option(3)
                if router and len(router) == 4:
                    self.gateway = socket.inet_ntoa(router)

                dns = packet.get_option(6)
                if dns and len(dns) >= 4:
                    # if multiple DNS addresses are present pick first 4 bytes
                    self.dns = socket.inet_ntoa(dns[:4])

                self.log(f"Received OFFER: {self.ip} (server {self.server_ip})")
                return self.send_request()

        except socket.timeout:
            self.log("No OFFER received (timeout)")
            return False
        except Exception as e:
            self.log(f"Error while waiting for OFFER: {e}")
            return False

    def send_request(self):
        self.log(f"Sending REQUEST for {self.ip}")

        packet = DHCPPacket()
        packet.xid = self.xid
        packet.chaddr = self.mac + b'\x00' * 10
        packet.flags = 0x8000

        # DHCP Message Type: REQUEST
        packet.options.append(struct.pack('!BBB', 53, 1, DHCP_REQUEST))
        # Requested IP
        packet.options.append(struct.pack('!BB', 50, 4) + socket.inet_aton(self.ip))
        # Server Identifier
        if self.server_ip:
            packet.options.append(struct.pack('!BB', 54, 4) + socket.inet_aton(self.server_ip))

        try:
            self.sock.sendto(packet.pack(), ('<broadcast>', 67))
        except Exception as e:
            self.log(f"Failed to send REQUEST: {e}")
            return False

        return self.wait_for_ack()

    def wait_for_ack(self):
        if not self.sock:
            return False
        self.sock.settimeout(5.0)
        try:
            data, addr = self.sock.recvfrom(1024)
            packet = DHCPPacket.unpack(data)

            if packet.xid != self.xid:
                return False

            msg_type_data = packet.get_option(53)
            if msg_type_data and msg_type_data[0] == DHCP_ACK:
                # update lease expiry
                if self.lease_time:
                    self.lease_expiry = time.time() + self.lease_time
                self.log(f"Received ACK - IP configured: {self.ip} (lease {self.lease_time}s)")
                # start renewal thread
                self.start_renewal_thread()
                return True

        except socket.timeout:
            self.log("No ACK received (timeout)")
            return False
        except Exception as e:
            self.log(f"Error while waiting for ACK: {e}")
            return False

    def start_renewal_thread(self):
        # stop old thread
        self.stop_renewal_thread()

        self.renew_stop_event.clear()
        self.renew_thread = threading.Thread(target=self._renewal_loop, daemon=True)
        self.renew_thread.start()

    def stop_renewal_thread(self):
        self.renew_stop_event.set()
        if self.renew_thread and self.renew_thread.is_alive():
            self.renew_thread.join(timeout=0.1)
        self.renew_thread = None
        self.renew_stop_event.clear()

    def _renewal_loop(self):
        """
        Attempt renewal at roughly 50% of the lease time (T1). If renewal fails,
        retry every 5 seconds until lease expires. If lease expires and no renewal,
        we mark IP as lost.
        """
        while not self.renew_stop_event.is_set():
            if not self.lease_time or not self.lease_expiry:
                break

            now = time.time()
            time_until_expiry = self.lease_expiry - now
            # schedule renewal at 50% of remaining lease (T1-like)
            renew_after = max(1, self.lease_time * 0.5)

            # if time_until_expiry smaller than a margin, try immediately
            sleep_time = min(renew_after, max(0, time_until_expiry - 1))
            # wait until it's time to attempt renewal (or stop)
            finished = self.renew_stop_event.wait(timeout=sleep_time)
            if finished:
                break

            # attempt renewal
            self.log("Attempting lease renewal...")
            success = self.attempt_renewal()
            if success:
                self.renewal_count += 1
                self.log(f"Renewal successful (count={self.renewal_count})")
                # continue loop with updated lease_time/expiry
                continue
            else:
                # if failed, retry every 5 seconds until expiry or success
                retry_interval = 5
                while not self.renew_stop_event.is_set() and time.time() < self.lease_expiry:
                    self.log("Renewal failed — retrying...")
                    finished = self.renew_stop_event.wait(timeout=retry_interval)
                    if finished:
                        break
                    success = self.attempt_renewal()
                    if success:
                        self.renewal_count += 1
                        self.log(f"Renewal successful (count={self.renewal_count})")
                        break

                # if lease expired and still no renewal
                if time.time() >= self.lease_expiry and not success:
                    self.log("Lease expired and renewal failed. IP lost.")
                    self.ip = None
                    self.server_ip = None
                    self.subnet_mask = None
                    self.gateway = None
                    self.dns = None
                    self.lease_time = None
                    self.lease_expiry = None
                    break

    def attempt_renewal(self):
        if not self.server_ip or not self.ip:
            return False

        packet = DHCPPacket()
        packet.xid = self.xid
        packet.chaddr = self.mac + b'\x00' * 10
        packet.flags = 0
        packet.ciaddr = self.ip

        # DHCP Message Type: REQUEST
        packet.options.append(struct.pack('!BBB', 53, 1, DHCP_REQUEST))
        packet.options.append(struct.pack('!BB', 54, 4) + socket.inet_aton(self.server_ip))

        # IMPORTANT: use a NEW socket, not self.sock
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.sendto(packet.pack(), ('<broadcast>', 67))
        finally:
            sock.close()

        # Listen for ACK on the listening socket
        try:
            self.sock.settimeout(2.0)
            data, addr = self.sock.recvfrom(1024)
            pkt = DHCPPacket.unpack(data)

            if pkt.xid != self.xid:
                return False

            msg = pkt.get_option(53)
            if msg and msg[0] == DHCP_ACK:
                lt = pkt.get_option(51)
                if lt:
                    self.lease_time = struct.unpack('!I', lt)[0]
                    self.lease_expiry = time.time() + self.lease_time
                return True

        except:
            return False


    def release(self):
        if not self.ip or not self.sock:
            return

        self.log(f"Releasing IP: {self.ip}")

        packet = DHCPPacket()
        packet.xid = self.xid
        packet.ciaddr = self.ip
        packet.chaddr = self.mac + b'\x00' * 10

        # DHCP Message Type: RELEASE
        packet.options.append(struct.pack('!BBB', 53, 1, DHCP_RELEASE))
        # Server Identifier
        if self.server_ip:
            packet.options.append(struct.pack('!BB', 54, 4) + socket.inet_aton(self.server_ip))

        try:
            self.sock.sendto(packet.pack(), (self.server_ip, 67))
        except Exception as e:
            self.log(f"Failed to send RELEASE: {e}")

        # stop renewal thread and close socket
        self.stop_renewal_thread()
        try:
            self.sock.close()
        except:
            pass
        self.sock = None
        self.ip = None
        self.server_ip = None
        self.subnet_mask = None
        self.gateway = None
        self.dns = None
        self.lease_time = None
        self.lease_expiry = None
        self.renewal_count = 0

class DHCPApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DHCP Server & Client")
        self.root.geometry("900x700")

        self.server = None
        self.server_thread = None
        self.client = None

        self.create_widgets()

    def create_widgets(self):
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Server tab
        server_frame = ttk.Frame(notebook)
        notebook.add(server_frame, text='DHCP Server')
        self.create_server_tab(server_frame)

        # Client tab
        client_frame = ttk.Frame(notebook)
        notebook.add(client_frame, text='DHCP Client')
        self.create_client_tab(client_frame)

    def create_server_tab(self, parent):
        # Configuration frame
        config_frame = ttk.LabelFrame(parent, text="Server Configuration", padding=10)
        config_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(config_frame, text="Server IP:").grid(row=0, column=0, sticky='w', pady=2)
        self.server_ip_entry = ttk.Entry(config_frame, width=20)
        self.server_ip_entry.insert(0, "192.168.1.1")
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(config_frame, text="Pool Start:").grid(row=1, column=0, sticky='w', pady=2)
        self.pool_start_entry = ttk.Entry(config_frame, width=20)
        self.pool_start_entry.insert(0, "192.168.1.100")
        self.pool_start_entry.grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(config_frame, text="Pool End:").grid(row=2, column=0, sticky='w', pady=2)
        self.pool_end_entry = ttk.Entry(config_frame, width=20)
        self.pool_end_entry.insert(0, "192.168.1.200")
        self.pool_end_entry.grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(config_frame, text="Subnet Mask:").grid(row=0, column=2, sticky='w', padx=(20,0), pady=2)
        self.subnet_entry = ttk.Entry(config_frame, width=20)
        self.subnet_entry.insert(0, "255.255.255.0")
        self.subnet_entry.grid(row=0, column=3, padx=5, pady=2)

        ttk.Label(config_frame, text="Gateway:").grid(row=1, column=2, sticky='w', padx=(20,0), pady=2)
        self.gateway_entry = ttk.Entry(config_frame, width=20)
        self.gateway_entry.insert(0, "192.168.1.1")
        self.gateway_entry.grid(row=1, column=3, padx=5, pady=2)

        ttk.Label(config_frame, text="DNS:").grid(row=2, column=2, sticky='w', padx=(20,0), pady=2)
        self.dns_entry = ttk.Entry(config_frame, width=20)
        self.dns_entry.insert(0, "8.8.8.8")
        self.dns_entry.grid(row=2, column=3, padx=5, pady=2)

        # Control frame
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill='x', padx=5, pady=5)

        self.start_server_btn = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_server_btn.pack(side='left', padx=5)

        self.stop_server_btn = ttk.Button(control_frame, text="Stop Server", command=self.stop_server, state='disabled')
        self.stop_server_btn.pack(side='left', padx=5)

        # Log frame
        log_frame = ttk.LabelFrame(parent, text="Server Log", padding=5)
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.server_log = scrolledtext.ScrolledText(log_frame, height=20)
        self.server_log.pack(fill='both', expand=True)

    def create_client_tab(self, parent):
        # Control frame
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(control_frame, text="Request IP", command=self.request_ip).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Release IP", command=self.release_ip).pack(side='left', padx=5)

        # Info frame
        info_frame = ttk.LabelFrame(parent, text="Network Configuration", padding=10)
        info_frame.pack(fill='x', padx=5, pady=5)

        self.client_info = {}
        labels = ["MAC Address", "IP Address", "Server IP", "Subnet Mask", "Gateway", "DNS", "Lease Time", "Lease Expires At", "Renewals"]
        for i, label in enumerate(labels):
            ttk.Label(info_frame, text=f"{label}:").grid(row=i, column=0, sticky='w', pady=2)
            self.client_info[label] = ttk.Label(info_frame, text="N/A", foreground="gray")
            self.client_info[label].grid(row=i, column=1, sticky='w', padx=10, pady=2)

        # Log frame
        log_frame = ttk.LabelFrame(parent, text="Client Log", padding=5)
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.client_log = scrolledtext.ScrolledText(log_frame, height=15)
        self.client_log.pack(fill='both', expand=True)

    def start_server(self):
        self.server = DHCPServer(
            server_ip=self.server_ip_entry.get(),
            pool_start=self.pool_start_entry.get(),
            pool_end=self.pool_end_entry.get(),
            subnet_mask=self.subnet_entry.get(),
            gateway=self.gateway_entry.get(),
            dns=self.dns_entry.get()
        )
        self.server.log_callback = self.log_server

        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()

        self.start_server_btn.config(state='disabled')
        self.stop_server_btn.config(state='normal')

    def stop_server(self):
        if self.server:
            self.server.stop()

        self.start_server_btn.config(state='normal')
        self.stop_server_btn.config(state='disabled')

    def request_ip(self):
        self.client = DHCPClient()
        self.client.log_callback = self.log_client

        thread = threading.Thread(target=self._request_ip_thread, daemon=True)
        thread.start()

    def _request_ip_thread(self):
        success = self.client.discover()
        if success:
            self.root.after(0, self.update_client_info)

    def release_ip(self):
        if self.client:
            self.client.release()
            self.client = None
            self.root.after(0, self.clear_client_info)

    def update_client_info(self):
        if not self.client:
            return

        c = self.client
        self.client_info["MAC Address"].config(text=c.mac.hex(':'), foreground="black")
        self.client_info["IP Address"].config(text=c.ip or "N/A", foreground="black" if c.ip else "gray")
        self.client_info["Server IP"].config(text=c.server_ip or "N/A", foreground="black" if c.server_ip else "gray")
        self.client_info["Subnet Mask"].config(text=c.subnet_mask or "N/A", foreground="black" if c.subnet_mask else "gray")
        self.client_info["Gateway"].config(text=c.gateway or "N/A", foreground="black" if c.gateway else "gray")
        self.client_info["DNS"].config(text=c.dns or "N/A", foreground="black" if c.dns else "gray")
        self.client_info["Lease Time"].config(
            text=f"{c.lease_time}s" if c.lease_time else "N/A",
            foreground="black" if c.lease_time else "gray"
        )
        if c.lease_expiry:
            expires_at = datetime.fromtimestamp(c.lease_expiry).strftime('%H:%M:%S')
            self.client_info["Lease Expires At"].config(text=expires_at, foreground="black")
        else:
            self.client_info["Lease Expires At"].config(text="N/A", foreground="gray")
        self.client_info["Renewals"].config(text=str(c.renewal_count), foreground="black" if c.renewal_count else "gray")

        # schedule next UI update while client exists
        if self.client:
            self.root.after(1000, self.update_client_info)

    def clear_client_info(self):
        for label in self.client_info.values():
            label.config(text="N/A", foreground="gray")

    def log_server(self, message):
        self.root.after(0, lambda: self._log(self.server_log, message))

    def log_client(self, message):
        self.root.after(0, lambda: self._log(self.client_log, message))

    def _log(self, widget, message):
        widget.insert(tk.END, message + '\n')
        widget.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = DHCPApp(root)
    root.mainloop()
