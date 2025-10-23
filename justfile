install-dev:
    rm ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap.py
    ln -s $PWD/sonoff_zigbee_extcap.py ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap.py

install:
    rm ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap.py
    cp $PWD/sonoff_zigbee_extcap.py ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap.py
