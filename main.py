import asyncio
import os
import socket
import sys
import traceback
import threading
import json
from utils.logger import log_info, log_error, log_warn, log_success
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

# Build the path to config.json
config_path = os.path.join(get_exe_dir(), 'config.json')

try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except Exception as e:
    log_error(f"Failed to load config: {e}")
    sys.exit(1)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}

async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    break
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                await loop.sock_sendall(sock_2, data)
            except Exception as e:
                # log_error(f"Relay error: {e}")
                break
    except Exception as e:
        log_error(f"Relay main loop fatal error: {e}")
    finally:
        try:
            sock_1.close()
            sock_2.close()
            if not peer_task.done():
                peer_task.cancel()
        except:
            pass

async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    fake_injective_conn = None
    outgoing_sock = None
    try:
        loop = asyncio.get_running_loop()
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            log_error(f"Unsupported data mode: {DATA_MODE}")
            incoming_sock.close()
            return

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        src_port = outgoing_sock.getsockname()[1]

        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn

        try:
            await asyncio.wait_for(loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT)), timeout=5)
        except Exception as e:
            log_error(f"Connection to {CONNECT_IP}:{CONNECT_PORT} failed: {e}")
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 5)
                if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    log_warn(f"Handshake failed or unexpected message: {fake_injective_conn.t2a_msg}")
                    return
            except asyncio.TimeoutError:
                log_warn("Handshake timed out")
                return
        else:
            log_error(f"Unknown bypass method: {BYPASS_METHOD}")
            return

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception as e:
        log_error(f"Handle exception: {e}")
    finally:
        if fake_injective_conn:
            fake_injective_conn.monitor = False
            fake_injective_connections.pop(fake_injective_conn.id, None)
        if outgoing_sock:
            outgoing_sock.close()
        if incoming_sock:
            incoming_sock.close()

async def main():
    try:
        mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mother_sock.setblocking(False)
        mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
        mother_sock.listen()
        log_success(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    except Exception as e:
        log_error(f"Failed to start server: {e}")
        return

    loop = asyncio.get_running_loop()
    while True:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            asyncio.create_task(handle(incoming_sock, addr))
        except Exception as e:
            log_error(f"Accept error: {e}")
            await asyncio.sleep(0.1)

if __name__ == "__main__":
    log_info("Starting SNI-Spoofing...")

    w_filter = "tcp and " + "(" + "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP + ")" + " or " + "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4 + ")" + ")"

    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections, INTERFACE_IPV4)
    threading.Thread(target=fake_tcp_injector.run, args=(CONNECT_IP,), daemon=True).start()

    log_info("Program started.")
    log_info("Telegram: @patterniha")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log_info("Shutting down...")
    except Exception as e:
        log_error(f"Fatal error: {e}")
