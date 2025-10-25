# Wireshark ExtCap for the Sonoff USB ZigBee Dongle Plus-E

Wireshark ExtCap which converts JSON messages sent over serial port from a
"SONOFF Zigbee 3.0 USB Dongle Plus".

This was written to use the [802.15.4 Sniffer for SONOFF Zigbee 3.0 USB DONGLE
Plus-E][1] firmware on Linux. There is a Windows only ExtCap binary in this
repository, which is no use on Linux. The source is available for the firmware,
but doesn't appear to be available for the ExtCap.

There are two versions of the ExtCap in this repository, a Python version that
uses the `LINKTYPE_IEEE802_15_4`(230) which just provides the raw packets.
However the Rust version provides a full `LINKTYPE_IEEE802_15_4_TAP`(283) with
RSSI (abusing the RSS field), LQI, and Channel Assignment as a TAP header.

## Flash your dongle

First flash the firmware [Sniffer_802.15.4_SONOFF_USB_Dongle_Plus_E.gbl][2] to
your ZBDongle-E so that it becomes a packet sniffer. The easiest way of flashing
the firmware is to use the [Sonoff online flasher][3] (using a browser that
supports web serial i.e Chrome). Just plug the dongle in (no need to dismantle
and put it in bootloader mode) and upload the `.gbl` file.

Once flashed test the dongle is working as expected (serial interface uses 1M
baud).

```bash screen /dev/ttyUSB0 1000000 ```

To exit `screen` use `Ctrl-a Ctrl-\` and `y` for yes.

If everything is working as expected, and there is some ZigBee traffic, then you
should see something like this in your terminal.

```
{"L":12,"Q":255,"R":-82,"C":11,"S":"638884621AE1DC595A04B62F"}
{"L":12,"Q":255,"R":-82,"C":11,"S":"638885621AE1DC595A0409AE"}
{"L":12,"Q":255,"R":-84,"C":11,"S":"638886621AE1DC595A04D924"}
{"L":12,"Q":255,"R":-79,"C":11,"S":"6388A8621A1B956AAE045CEC"}
{"L":12,"Q":0,"R":-88,"C":11,"S":"6388B6621A1B95DD59046EB0"}
{"L":12,"Q":255,"R":-79,"C":11,"S":"6388A9621A1B956AAE04E36D"}
{"L":12,"Q":255,"R":-78,"C":11,"S":"6388AA621A1B956AAE0433E7"}
{"L":12,"Q":50,"R":-85,"C":11,"S":"63887C621AB7068E9E047D85"}
```

Where each line is a received packet as JSON:

* L = length
* Q = LQI
* R = RSSI
* C = channel
* S = string of hexadecimal representation of 802.15.4 packet

## Wireshark

Make sure you have the latest version of `wireshark` installed. Then build the
rust binary and copy it over to `~/.local/lib/wireshark/extcap/`. After plugging
in your `ZBDongle-E` then you should be able to start Wireshark and see it as an
interface.

## Further work

At the moment all packets from all ZigBee channels are captured. It's easy
enough to filter in wireshark, but the firmware also claims to support filtering
by channel on the dongle itself. This might be a useful feature to add at some
point.

I'm also curious to see if the firmware can be ported to Rust as well and
potentially pull out other packet meta data as well.

[1]: https://github.com/ErkSponge/Sniffer_802.15.4_SONOFF_USB_Dongle_Plus_E/tree/main
[2]: https://github.com/ErkSponge/Sniffer_802.15.4_SONOFF_USB_Dongle_Plus_E/tree/main/Output/Sniffer_802.15.4_SONOFF_USB_Dongle_Plus_E
[3]: https://dongle.sonoff.tech/sonoff-dongle-flasher/
