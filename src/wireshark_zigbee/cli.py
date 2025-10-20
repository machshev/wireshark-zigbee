# SPDX-FileCopyrightText: 2025 David James McCorrie <djmccorrie@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0
"""Zigbee wireshark extcap."""

import struct
import time
from json import JSONDecodeError, loads
from pathlib import Path

import click
import serial

version = "0.1.0"
url = "https://github.com/machshev/wireshark-zigbee"


def print_interfaces(
    extcap_version: str = "",
) -> None:
    """Print the available interfaces."""
    print(f"extcap {{{version}}}{{help={url}}}")

    for d in Path("/dev").glob("ttyUSB*"):
        print(f"interface {{value={d}}}{{display={d.name}}}")


def print_dlts(
    extcap_interface: str = "",
) -> None:
    """Print the available Diagnostic Log and Trace (DLT) for the interface."""


def print_config(
    extcap_interface: str = "",
) -> None:
    """Print the available interfaces."""


def pcap_header() -> bytearray:
    """Generate header."""
    header = bytearray()
    header.extend(struct.pack("<L", int("a1b2c3d4", 16)))
    header.extend(struct.pack("<H", 2))  # Pcap Major Version
    header.extend(struct.pack("<H", 4))  # Pcap Minor Version
    header.extend(struct.pack("<I", 0))  # Timezone
    header.extend(struct.pack("<I", 0))  # Accurancy of timestamps
    header.extend(struct.pack("<L", int("0000ffff", 16)))  # Max Length of capture frame
    header.extend(struct.pack("<L", 1))  # Ethernet
    return header


def pcap_package(message) -> bytearray:
    pcap = bytearray()
    # length = 14 bytes [ eth ] + 20 bytes [ ip ] + messagelength

    caplength = len(message) + 14 + 20
    timestamp = int(time.time())

    pcap.extend(struct.pack("<L", timestamp))
    pcap.extend(struct.pack("<L", 0x00))  # timestamp nanoseconds
    pcap.extend(struct.pack("<L", caplength))  # length captured
    pcap.extend(struct.pack("<L", caplength))  # length in frame

    # ETH
    pcap.extend(struct.pack("h", 0))  # source mac
    pcap.extend(struct.pack("h", 0))  # source mac
    pcap.extend(struct.pack("h", 0))  # source mac
    pcap.extend(struct.pack("h", 0))  # dest mac
    pcap.extend(struct.pack("h", 0))  # dest mac
    pcap.extend(struct.pack("h", 0))  # dest mac
    pcap.extend(struct.pack("<h", 8))  # protocol (ip)

    # IP
    pcap.extend(struct.pack("b", int("45", 16)))  # IP version
    pcap.extend(struct.pack("b", int("0", 16)))
    pcap.extend(struct.pack(">H", len(message) + 20))  # length of data + payload
    pcap.extend(struct.pack("<H", int("0", 16)))  # Identification
    pcap.extend(struct.pack("b", int("40", 16)))  # Don't fragment
    pcap.extend(struct.pack("b", int("0", 16)))  # Fragment Offset
    pcap.extend(struct.pack("b", int("40", 16)))
    pcap.extend(struct.pack("B", 0xFE))  # Protocol (2 = unspecified)
    pcap.extend(struct.pack("<H", int("0000", 16)))  # Checksum
    pcap.extend(struct.pack(">L", int("7F000001", 16)))  # Source IP
    pcap.extend(struct.pack(">L", int("7F000001", 16)))  # Dest IP

    pcap.extend(message)
    return pcap


def capture(extcap_interface: str, fifo: str) -> None:
    """Capture packets from sniffer."""
    with (
        Path(fifo).open(mode="w+b") as f,
        serial.Serial(extcap_interface, 1000000, timeout=1) as ser,
    ):
        f.write(pcap_header())

        while True:
            try:
                data = loads(ser.readline())
            except JSONDecodeError:
                continue

            f.write(pcap_package(data["S"]))
            print(data)


@click.command()
@click.option("--extcap-interfaces", is_flag=True)
@click.option("--extcap-dlts", is_flag=True)
@click.option("--extcap-config", is_flag=True)
@click.option("--capture", is_flag=True)
@click.option("--extcap-version", default="")
@click.option("--extcap-interface", default="")
@click.option("--extcap-capture-filter", default="")
@click.option("--fifo", default="")
def main(
    extcap_interfaces: bool = False,
    extcap_dlts: bool = False,
    extcap_config: bool = False,
    capture: bool = False,
    extcap_version: str = "",
    extcap_interface: str = "",
    extcap_capture_filter: str = "",
    fifo: str = "",
) -> None:
    """Zigbee wireshark extcap."""
    if extcap_interfaces:
        print_interfaces(extcap_version=extcap_version)

    if extcap_dlts:
        print_dlts(extcap_interface=extcap_interface)

    if extcap_config:
        print_config(extcap_interface=extcap_interface)

    if capture:
        capture(extcap_interface=extcap_interface, fifo=fifo)
