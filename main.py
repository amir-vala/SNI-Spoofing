import asyncio
import os
import socket
import sys
import threading
import json

from utils.logger import logger
# from utils.proxy_protocols import parse_vless_protocol
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


# Build the path to config.json
config_path = os.path.join(get_exe_dir(), 'config.json')

# Load the config
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    logger.error(f"Config file not found at {config_path}")
    sys.exit(1)
except json.JSONDecodeError:
    logger.error(f"Failed to parse config.json")
    sys.exit(1)
except Exception as e:
    logger.error(f"Unexpected error loading config: {e}")
    sys.exit(1)

LISTEN_HOST = config.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = config.get("LISTEN_PORT", 40443)
FAKE_SNI = config.get("FAKE_SNI", "google.com").encode()
CONNECT_IP = config.get("CONNECT_IP", "1.1.1.1")
CONNECT_PORT = config.get("CONNECT_PORT", 443)
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections = {}


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
                logger.debug(f"Relay loop exception: {e}")
                break
    except Exception as e:
        logger.error(f"Relay main loop fatal error: {e}")
    finally:
        try:
            sock_1.close()
            sock_2.close()
        except:
            pass
        if not peer_task.done():
            peer_task.cancel()


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    try:
        loop = asyncio.get_running_loop()
        # try:
        #     data = await loop.sock_recv(incoming_sock, 65575)
        #     if not data:
        #         raise ValueError("eof")
        # except Exception:
        #     incoming_sock.close()
        #     return
        # try:
        #     version, uuid_bytes, transport_protocol, remote_address_type, remote_address, remote_port, payload_index = parse_vless_protocol(
        #         data)
        # except Exception as e:
        #     print("No Vless Request!, Connection Closed", repr(e), data)
        #     incoming_sock.close()
        #     return
        # if transport_protocol != "tcp":
        #     print("Transport Protocol Error!, Connection Closed", transport_protocol, data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "hostname":
        #     print("hostname address not implemented yet!", data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "ipv4":
        #     if not INTERFACE_IPV4:
        #         print("no interface ipv4!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET
        #     src_ip = INTERFACE_IPV4
        #
        # elif remote_address_type == "ipv6":
        #     if not INTERFACE_IPV6:
        #         print("no interface ipv6!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET6
        #     src_ip = INTERFACE_IPV6
        #
        # else:
        #     print(data)
        #     sys.exit("impossible address type!")

        # try:
        #     fake_sni_host, data_mode, bypass_method = UUID_FAKE_MAP[uuid_bytes]
        # except KeyError:
        #     print("unmatched uuid", uuid_bytes)
        #     incoming_sock.close()
        #     return

        # if data_mode == "http":
        #     ...
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            sys.exit("impossible mode!")
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        src_port = outgoing_sock.getsockname()[1]

        if sys.platform == "win32":
            from fake_tcp import FakeInjectiveConnection
            fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                          fake_data,
                                                          BYPASS_METHOD, incoming_sock)
            fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        else:
            # Placeholder for Linux connection monitoring
            class LinuxFakeConn:
                def __init__(self):
                    self.id = (INTERFACE_IPV4, src_port, CONNECT_IP, CONNECT_PORT)
                    self.monitor = True
                    self.t2a_event = asyncio.Event()
                    self.t2a_msg = "fake_data_ack_recv" # skip for now
            fake_injective_conn = LinuxFakeConn()
            fake_injective_conn.t2a_event.set()
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
            outgoing_sock.close()
            incoming_sock.close()
            return

        # if bypass_method == "wrong_checksum":
        #     ...

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
                else:
                    sys.exit("impossible t2a msg!")
            except Exception:
                fake_injective_conn.monitor = False
                del fake_injective_connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False
        del fake_injective_connections[fake_injective_conn.id]

        # early_data = data[payload_index:]
        # if early_data:
        #     try:
        #         sent_len = await loop.sock_sendall(outgoing_sock, early_data)
        #         if sent_len != len(early_data):
        #             raise ValueError("incomplete send")
        #     except Exception:
        #         outgoing_sock.close()
        #         incoming_sock.close()
        #         return

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))  # bytes([version, 0])
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")



    except Exception as e:
        logger.error(f"Handle exception: {e}")


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        asyncio.create_task(handle(incoming_sock, addr))


if __name__ == "__main__":
    if sys.platform == "win32":
        from fake_tcp import FakeTcpInjector
        w_filter = "tcp and " + "(" + "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP + ")" + " or " + "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4 + ")" + ")"
        try:
            fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
            threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
        except Exception as e:
            logger.error(f"Failed to start Windows Injector: {e}")
    else:
        from linux_injector import LinuxTcpInjector
        logger.info("Initializing Linux Packet Injector...")
        try:
            l_filter = f"tcp and (src host {INTERFACE_IPV4} or dst host {INTERFACE_IPV4})"
            linux_injector = LinuxTcpInjector(l_filter)
            threading.Thread(target=linux_injector.run, args=(), daemon=True).start()
        except Exception as e:
            logger.error(f"Failed to start Linux Injector: {e}")

    banner = """
    \033[95m███████╗███╗   ██╗██╗      ███████╗██████╗  ██████╗  ██████╗ ███████╗██╗███╗   ██╗ ██████╗
    ██╔════╝████╗  ██║██║      ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██║████╗  ██║██╔════╝
    ███████╗██╔██╗ ██║██║█████╗███████╗██████╔╝██║   ██║██║   ██║█████╗  ██║██╔██╗ ██║██║  ███╗
    ╚════██║██║╚██╗██║██║╚════╝╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██║██║╚██╗██║██║   ██║
    ███████║██║ ╚████║██║      ███████║██║     ╚██████╔╝╚██████╔╝██║     ██║██║ ╚████║╚██████╔╝
    ╚══════╝╚═╝  ╚═══╝╚═╝      ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ \033[0m
    """
    print(banner)
    print("\033[92m" + "  [+] هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا" + "\033[0m")
    print("\033[92m" + "  [+] دراد امش تیامح هب زاین هک مراد رظن رد دازآ تنرتنیا هب ناریا مدرم مامت یسرتسد یارب یدایز یاه همانرب و اه هژورپ" + "\033[0m")
    print("\n")
    print("\033[93m" + "  [*] USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424" + "\033[0m")
    print("\033[96m" + "  [*] Channel: @patterniha" + "\033[0m")
    print("-" * 80)
    logger.info(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")
    logger.info(f"Targeting {CONNECT_IP}:{CONNECT_PORT} with SNI: {FAKE_SNI.decode()}")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Application stopped by user.")
    except Exception as e:
        logger.critical(f"Main loop crashed: {e}")
