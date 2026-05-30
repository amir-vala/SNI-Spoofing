# SNI-Spoofing

SNI-Spoofing is a tool designed to bypass Deep Packet Inspection (DPI) by manipulating IP and TCP headers. It supports both Windows and Linux platforms.

## Features

- **Cross-Platform Support**: Works on Windows (using WinDivert) and Linux (using NFQueue and Scapy).
- **DPI Bypass**: Uses TCP sequence number manipulation to confuse DPI middleboxes.
- **Robust Error Handling**: Designed to stay running even when encountering network errors or unexpected packets.
- **Enhanced Logging**: Clear and visually appealing console output using the `rich` library.
- **Async Architecture**: High-performance relaying using Python's `asyncio`.

## Requirements

### Windows
- [WinDivert](https://reqrypt.org/windivert.html) (Included with `pydivert`)

### Linux
- Root privileges (for `iptables` and packet interception)
- System packages: `libnetfilter-queue-dev`, `python3-dev`, `gcc`
- Python libraries: `NetfilterQueue`, `scapy`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/SNI-Spoofing.git
   cd SNI-Spoofing
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Linux Only) Install system dependencies:
   ```bash
   sudo apt-get update
   sudo apt-get install -y libnetfilter-queue-dev python3-dev gcc
   ```

## Usage

1. Configure the tool by editing `config.json`:
   ```json
   {
     "LISTEN_HOST": "127.0.0.1",
     "LISTEN_PORT": 8080,
     "FAKE_SNI": "google.com",
     "CONNECT_IP": "1.1.1.1",
     "CONNECT_PORT": 443
   }
   ```

2. Run the program:
   ```bash
   # Windows
   python main.py

   # Linux
   sudo python3 main.py
   ```

## Disclaimer

This tool is for educational purposes only. Use it responsibly and at your own risk.
