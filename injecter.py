import sys
from injector_base import BaseTcpInjector
from utils.logger import logger

try:
    from pydivert import WinDivert, Packet
except ImportError:
    # Not on Windows or pydivert not installed
    WinDivert = None
    Packet = None

class TcpInjector(BaseTcpInjector):
    def __init__(self, w_filter: str):
        super().__init__(w_filter)
        if WinDivert is None:
            raise RuntimeError("WinDivert/pydivert is required for Windows Injector but not available.")
        self.w: WinDivert = WinDivert(w_filter)

    def inject(self, packet):
        raise NotImplementedError("Subclasses must implement inject")

    def send_packet(self, packet, inject: bool):
        self.w.send(packet, inject)

    def run(self):
        if not self.w:
            logger.error("WinDivert not initialized.")
            return
        with self.w:
            while True:
                try:
                    packet = self.w.recv(65575)
                    self.inject(packet)
                except Exception as e:
                    logger.error(f"Error in Windows Injector loop: {e}")
