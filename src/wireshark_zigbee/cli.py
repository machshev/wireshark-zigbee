# SPDX-FileCopyrightText: 2025 David James McCorrie <djmccorrie@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0
"""Zigbee wireshark extcap."""

import argparse
import asyncio
import glob
import json
import os
import struct
import sys
import time

import serial_asyncio
from scapy.config import conf
from scapy.packet import Raw
from scapy.utils import PcapNgWriter

# Extcap version
EXTCAP_VERSION = "1.0"

# PCAPNG constants
LINKTYPE_IEEE802_15_4 = 230


def extcap_interfaces():
    ports = []
    for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*"]:
        ports.extend(glob.glob(pattern))

    for port in sorted(ports):
        if os.access(port, os.R_OK | os.W_OK):
            display = f"Sonoff 802.15.4 Sniffer - {port}"
            iface = {
                "value": port,
                "display": display,
                "help": "Sonoff Zigbee USB Dongle Plus-E Sniffer",
            }

            print(
                "interface {{value={}}}{{display={}}}{{help={}}}".format(
                    iface["value"],
                    iface["display"],
                    iface["help"],
                )
            )


def extcap_config(interface: str) -> None:
    """Print config."""
    print(
        "arg {number=11}{call=--channel}{display=Channel}{tooltip=Zigbee channel}"
        "{type=unsigned}{range=11,26}{default=11}"
    )


def extcap_dlts(interface: str):
    print(
        "dlt {number=%d}{name=IEEE802_15_4}{display=IEEE 802.15.4}"
        % LINKTYPE_IEEE802_15_4
    )


class SnifferCapture:
    def __init__(self, fifo_path, port, channel):
        self.fifo_path = fifo_path
        self.port = port
        self.channel = int(channel)
        self.running = False
        self.packet_queue = asyncio.Queue()

        conf.l2types.register_layer2num(LINKTYPE_IEEE802_15_4, Raw)

    async def start(self):
        try:
            ser_reader, ser_writer = await serial_asyncio.open_serial_connection(
                url=self.port, baudrate=1000000
            )

            pcap_writer = PcapNgWriter(self.fifo_path)

            self.running = True
            await asyncio.gather(
                self._reader(reader=ser_reader),
                self._writer(writer=pcap_writer),
            )

            while self.running:
                time.sleep(0.1)

        finally:
            self.running = False
            if pcap_writer:
                pcap_writer.close()

    async def _reader(self, reader):
        while self.running:
            try:
                line = await reader.readline()
                line = line.decode("utf-8", errors="ignore").rstrip()
                if not line:
                    continue

                data = json.loads(line)
                if "S" not in data:
                    continue

                hex_str = data["S"].replace(" ", "").replace(":", "")
                packet = bytes.fromhex(hex_str)
                rssi = data.get("R", 0)
                lqi = data.get("Q", 0)
                ts = time.time()
                sec = int(ts)
                usec = int((ts - sec) * 1000000)

                await self.packet_queue.put((sec, usec, packet, rssi, lqi))

            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON parse error: {e}", file=sys.stderr)

            await asyncio.sleep(0)  # Yield control

    async def _writer(self, writer: PcapNgWriter):
        """Write packets to fifo for wireshark."""
        while self.running or not self.packet_queue.empty():
            try:
                sec, usec, packet, rssi, lqi = await asyncio.wait_for(
                    self.packet_queue.get(), timeout=1.0
                )

                raw_packet = Raw(packet)
                raw_packet.comments = [
                    struct.pack("<b", rssi),  # RSSI: int8
                    struct.pack("<B", lqi),  # LQI: uint8
                ]

                writer.write(raw_packet)
                writer.flush()

                self.packet_queue.task_done()

            except TimeoutError:
                pass

            await asyncio.sleep(0)  # Yield control


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--extcap-version")
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-interface")
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--fifo")
    parser.add_argument("--channel", type=int, default=11)
    args = parser.parse_args()

    print("extcap {version=%s}" % EXTCAP_VERSION)

    if args.extcap_interfaces:
        extcap_interfaces()
    if args.extcap_config and args.extcap_interface:
        extcap_config(args.extcap_interface)
    if args.extcap_dlts and args.extcap_interface:
        extcap_dlts(args.extcap_interface)

    if args.capture:
        if args.fifo and args.extcap_interface:
            sniffer = SnifferCapture(args.fifo, args.extcap_interface, args.channel)
            asyncio.run(sniffer.start())
        else:
            print("Error: Missing --fifo or --extcap-interface", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
