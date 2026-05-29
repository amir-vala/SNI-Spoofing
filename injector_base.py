import socket
import sys
from abc import ABC, abstractmethod
from utils.logger import logger

class BaseTcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.filter = w_filter

    @abstractmethod
    def inject(self, packet):
        pass

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def send_packet(self, packet, inject: bool):
        pass
