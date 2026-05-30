import sys
from abc import ABC, abstractmethod
from utils.logger import log_info, log_error, log_warn
from scapy.all import IP, TCP, Raw

class PacketWrapper(ABC):
    @property
    @abstractmethod
    def is_inbound(self) -> bool:
        pass

    @property
    @abstractmethod
    def is_outbound(self) -> bool:
        pass

    @property
    @abstractmethod
    def ip_src(self) -> str:
        pass

    @property
    @abstractmethod
    def ip_dst(self) -> str:
        pass

    @property
    @abstractmethod
    def tcp_src_port(self) -> int:
        pass

    @property
    @abstractmethod
    def tcp_dst_port(self) -> int:
        pass

    @property
    @abstractmethod
    def tcp_seq(self) -> int:
        pass

    @tcp_seq.setter
    @abstractmethod
    def tcp_seq(self, value: int):
        pass

    @property
    @abstractmethod
    def tcp_ack_num(self) -> int:
        pass

    @property
    @abstractmethod
    def tcp_flags(self):
        pass

    @property
    @abstractmethod
    def tcp_payload_len(self) -> int:
        pass

    @abstractmethod
    def set_tcp_payload(self, payload: bytes):
        pass

    @abstractmethod
    def set_ip_ident(self, ident: int):
        pass

    @abstractmethod
    def send(self, modify: bool = False):
        pass

class WinDivertPacket(PacketWrapper):
    def __init__(self, packet, windivert_obj):
        self.p = packet
        self.w = windivert_obj

    @property
    def is_inbound(self) -> bool:
        return self.p.is_inbound

    @property
    def is_outbound(self) -> bool:
        return self.p.is_outbound

    @property
    def ip_src(self) -> str:
        return self.p.ip.src_addr

    @property
    def ip_dst(self) -> str:
        return self.p.ip.dst_addr

    @property
    def tcp_src_port(self) -> int:
        return self.p.tcp.src_port

    @property
    def tcp_dst_port(self) -> int:
        return self.p.tcp.dst_port

    @property
    def tcp_seq(self) -> int:
        return self.p.tcp.seq_num

    @tcp_seq.setter
    def tcp_seq(self, value: int):
        self.p.tcp.seq_num = value

    @property
    def tcp_ack_num(self) -> int:
        return self.p.tcp.ack_num

    @property
    def tcp_flags(self):
        class Flags:
            def __init__(self, p):
                self.syn = p.tcp.syn
                self.ack = p.tcp.ack
                self.rst = p.tcp.rst
                self.fin = p.tcp.fin
                self.psh = p.tcp.psh
        return Flags(self.p)

    @property
    def tcp_payload_len(self) -> int:
        return len(self.p.tcp.payload)

    def set_tcp_payload(self, payload: bytes):
        self.p.tcp.payload = payload
        # pydivert handles packet length and checksums automatically.
        # Manual modification of ip.packet_len might be causing the [WinError 122].
        self.p.tcp.psh = True

    def set_ip_ident(self, ident: int):
        if self.p.ipv4:
            self.p.ipv4.ident = ident

    def send(self, modify: bool = False):
        self.w.send(self.p, modify)

class ScapyPacket(PacketWrapper):
    def __init__(self, nfpacket, interface_ip):
        self.nfpacket = nfpacket
        self.p = IP(nfpacket.get_payload())
        self.interface_ip = interface_ip

    @property
    def is_inbound(self) -> bool:
        return self.p.dst == self.interface_ip

    @property
    def is_outbound(self) -> bool:
        return self.p.src == self.interface_ip

    @property
    def ip_src(self) -> str:
        return self.p.src

    @property
    def ip_dst(self) -> str:
        return self.p.dst

    @property
    def tcp_src_port(self) -> int:
        return self.p[TCP].sport

    @property
    def tcp_dst_port(self) -> int:
        return self.p[TCP].dport

    @property
    def tcp_seq(self) -> int:
        return self.p[TCP].seq

    @tcp_seq.setter
    def tcp_seq(self, value: int):
        self.p[TCP].seq = value

    @property
    def tcp_ack_num(self) -> int:
        return self.p[TCP].ack

    @property
    def tcp_flags(self):
        class Flags:
            def __init__(self, p):
                f = p['TCP'].flags
                self.syn = 'S' in f
                self.ack = 'A' in f
                self.rst = 'R' in f
                self.fin = 'F' in f
                self.psh = 'P' in f
        return Flags(self.p)

    @property
    def tcp_payload_len(self) -> int:
        from scapy.all import Raw
        if self.p.haslayer(Raw):
            return len(self.p[Raw].load)
        return 0

    def set_tcp_payload(self, payload: bytes):
        from scapy.packet import Raw
        from scapy.layers.inet import TCP
        if self.p.haslayer(Raw):
            self.p[Raw].load = payload
        else:
            self.p = self.p / Raw(load=payload)
        self.p[TCP].flags = "PA"
        # Scapy recalculates checksums and lengths automatically when sending if deleted
        del self.p.len
        del self.p.chksum
        del self.p[TCP].chksum

    def set_ip_ident(self, ident: int):
        self.p.id = ident

    def send(self, modify: bool = False):
        if modify:
            from scapy.sendrecv import send
            # For modified packets (injections), we send via raw socket
            # and then we must also decide what to do with the original nfpacket.
            # In this project's logic, we usually 'accept' the original later or earlier.
            send(self.p, verbose=False)
        else:
            self.nfpacket.accept()

class TcpInjector(ABC):
    def __init__(self, w_filter: str, interface_ip: str = None):
        self.w_filter = w_filter
        self.interface_ip = interface_ip
        self.is_windows = sys.platform == "win32"
        if self.is_windows:
            from pydivert import WinDivert
            self.w = WinDivert(w_filter)
        else:
            from netfilterqueue import NetfilterQueue
            import os
            self.nfqueue = NetfilterQueue()
            # We will setup iptables in run()

    @abstractmethod
    def inject(self, packet: PacketWrapper):
        pass

    def run(self, connect_ip=None):
        if self.is_windows:
            log_info("Starting WinDivert injector...")
            with self.w:
                while True:
                    try:
                        p = self.w.recv(65575)
                        self.inject(WinDivertPacket(p, self.w))
                    except Exception as e:
                        log_error(f"Error in WinDivert loop: {e}")
        else:
            log_info("Starting NFQueue injector...")
            import os

            # Narrow down iptables rules if connect_ip is provided
            ip_filter = ""
            if connect_ip:
                ip_filter = f"-d {connect_ip}"
                ip_filter_in = f"-s {connect_ip}"
            else:
                ip_filter = ""
                ip_filter_in = ""

            os.system(f"iptables -I OUTPUT -p tcp {ip_filter} -j NFQUEUE --queue-num 1")
            os.system(f"iptables -I INPUT -p tcp {ip_filter_in} -j NFQUEUE --queue-num 1")

            def callback(nfpacket):
                try:
                    self.inject(ScapyPacket(nfpacket, self.interface_ip))
                except Exception as e:
                    log_error(f"Error in NFQueue callback: {e}")
                    nfpacket.accept()

            self.nfqueue.bind(1, callback)
            try:
                self.nfqueue.run()
            except Exception as e:
                log_error(f"NFQueue run error: {e}")
            finally:
                log_warn("Cleaning up iptables...")
                os.system(f"iptables -D OUTPUT -p tcp {ip_filter} -j NFQUEUE --queue-num 1")
                os.system(f"iptables -D INPUT -p tcp {ip_filter_in} -j NFQUEUE --queue-num 1")
                self.nfqueue.unbind()
