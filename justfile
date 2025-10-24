default: install-dev 


build:
    cargo build

build-release:
    cargo build --release

plugin-dir-create:
    mkdir -p "$HOME/.local/lib/wireshark/extcap/"

plugin-dir-clean: plugin-dir-create
    rm -f ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap
    rm -f ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap.py


install-dev: build plugin-dir-create
    ln -s $PWD/target/debug/sonoff_zigbee_extcap ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap

    # Python version
    ln -s $PWD/sonoff_zigbee_extcap.py ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap.py

install-rust: build plugin-dir-create
    cp $PWD/target/debug/sonoff_zigbee_extcap ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap

install-py: plugin-dir-create
    cp $PWD/sonoff_zigbee_extcap.py ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap.py

install: build-release plugin-dir-clean 
    cp $PWD/target/release/sonoff_zigbee_extcap ~/.local/lib/wireshark/extcap/sonoff_zigbee_extcap
