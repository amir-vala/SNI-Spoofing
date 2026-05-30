import asyncio
import socket
import sys
import threading
import time

from monitor_connection import MonitorConnection
from injecter import TcpInjector, PacketWrapper
from utils.logger import log_info, log_error, log_warn


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


class FakeTcpInjector(TcpInjector):

    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection], interface_ip: str = None):
        super().__init__(w_filter, interface_ip)
        self.connections = connections

    def fake_send_thread(self, packet: PacketWrapper, connection: FakeInjectiveConnection):
        time.sleep(0.001)
        try:
            with connection.thread_lock:
                if not connection.monitor:
                    return

                if connection.bypass_method == "wrong_seq":
                    packet.tcp_seq = (connection.syn_seq + 1 - len(connection.fake_data)) & 0xffffffff
                    packet.set_tcp_payload(connection.fake_data)
                    packet.set_ip_ident((connection.syn_seq + 1) & 0xffff)
                    connection.fake_sent = True
                    packet.send(modify=True)
                else:
                    log_error(f"Bypass method {connection.bypass_method} not implemented!")
        except Exception as e:
            log_error(f"Error in fake_send_thread: {e}")

    def on_unexpected_packet(self, packet: PacketWrapper, connection: FakeInjectiveConnection, info_m: str):
        log_warn(f"{info_m} | Packet: {packet.ip_src}:{packet.tcp_src_port} -> {packet.ip_dst}:{packet.tcp_dst_port}")
        try:
            connection.sock.close()
            connection.peer_sock.close()
        except:
            pass
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        try:
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        except:
            pass
        packet.send(modify=False)

    def on_inbound_packet(self, packet: PacketWrapper, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
            return

        flags = packet.tcp_flags
        if flags.ack and flags.syn and (not flags.rst) and (not flags.fin) and (packet.tcp_payload_len == 0):
            seq_num = packet.tcp_seq
            ack_num = packet.tcp_ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound syn-ack packet, seq change! {seq_num} {connection.syn_ack_seq}")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound syn-ack packet, ack not matched! {ack_num} {connection.syn_seq}")
                return
            connection.syn_ack_seq = seq_num
            packet.send(modify=False)
            return

        if flags.ack and (not flags.syn) and (not flags.rst) and (not flags.fin) and (packet.tcp_payload_len == 0) and connection.fake_sent:
            seq_num = packet.tcp_seq
            ack_num = packet.tcp_ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound ack packet, seq not matched! {seq_num} {connection.syn_ack_seq}")
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected inbound ack packet, ack not matched! {ack_num} {connection.syn_seq}")
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            try:
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            except:
                pass
            return

        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")

    def on_outbound_packet(self, packet: PacketWrapper, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
            return

        flags = packet.tcp_flags
        if flags.syn and (not flags.ack) and (not flags.rst) and (not flags.fin) and (packet.tcp_payload_len == 0):
            seq_num = packet.tcp_seq
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, f"unexpected outbound syn packet, seq not matched! {seq_num} {connection.syn_seq}")
                return
            connection.syn_seq = seq_num
            packet.send(modify=False)
            return

        if flags.ack and (not flags.syn) and (not flags.rst) and (not flags.fin) and (packet.tcp_payload_len == 0):
            seq_num = packet.tcp_seq
            ack_num = packet.tcp_ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected outbound ack packet, seq not matched! {seq_num} {connection.syn_seq}")
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          f"unexpected outbound ack packet, ack not matched! {ack_num} {connection.syn_ack_seq}")
                return

            packet.send(modify=False)
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return

        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")

    def inject(self, packet: PacketWrapper):
        if packet.is_inbound:
            c_id = (packet.ip_dst, packet.tcp_dst_port, packet.ip_src, packet.tcp_src_port)
            connection = self.connections.get(c_id)
            if not connection:
                packet.send(modify=False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        packet.send(modify=False)
                        return
                    self.on_inbound_packet(packet, connection)
        elif packet.is_outbound:
            c_id = (packet.ip_src, packet.tcp_src_port, packet.ip_dst, packet.tcp_dst_port)
            connection = self.connections.get(c_id)
            if not connection:
                packet.send(modify=False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        packet.send(modify=False)
                        return
                    self.on_outbound_packet(packet, connection)
        else:
            log_error("impossible direction!")
