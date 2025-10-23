use std::{
    io::{BufRead, BufReader},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use pcap_file::{
    DataLink,
    pcap::{PcapHeader, PcapPacket, PcapWriter},
};
use r_extcap::{
    ExtcapArgs, ExtcapStep, cargo_metadata,
    controls::ControlCommand,
    interface::{Dlt, Interface},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_serial::{SerialPortType, available_ports};

#[derive(Debug, Parser)]
struct AppArgs {
    #[command(flatten)]
    extcap: ExtcapArgs,
}

#[derive(Serialize, Deserialize)]
pub enum FCS {
    None,
    CRC16,
    CRC32,
}

impl FCS {
    pub fn to_u16(&self) -> u16 {
        match self {
            FCS::None => 0,
            FCS::CRC16 => 1,
            FCS::CRC32 => 2,
        }
    }
}

fn type_length(t: u16, l: u16) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&t.to_le_bytes());
    bytes.extend_from_slice(&l.to_le_bytes());
    bytes
}

#[derive(Serialize, Deserialize)]
pub enum TLV {
    FCSType(FCS),
    RSS(f32),
    Bitrate(u32),                  // bits per second
    ChannelAssignment(u16, u8),    // channel number, channel page
    SunPhyInformation(u8, u8, u8), // band, type, mode
    SOFTimestamp(u64),             // start of frame nanoseconds
    EOFTimestamp(u64),             // end of frame nanoseconds
    ASN(u64),                      // Absolute slot number
    SlotTimestamp(u64),            // Start of slot timestamp - nanoseconds
    TimeslotLength(u64),           // microseconds
    LQI(u8),                       // Link Quality Indicator
    ChannelFrequency(f32),         // Channel center freq kHz
}

impl TLV {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            TLV::FCSType(fcs) => {
                let mut bytes = type_length(0, 1);
                bytes.extend_from_slice(&fcs.to_u16().to_le_bytes());
                bytes.extend_from_slice(&[0, 0, 0]); // padding
                bytes
            }
            TLV::RSS(rss) => {
                let mut bytes = type_length(1, 4);
                bytes.extend_from_slice(&rss.to_le_bytes());
                bytes
            }
            TLV::Bitrate(rate) => {
                let mut bytes = type_length(2, 4);
                bytes.extend_from_slice(&rate.to_le_bytes());
                bytes
            }
            TLV::ChannelAssignment(num, page) => {
                let mut bytes = type_length(3, 3);
                bytes.extend_from_slice(&num.to_le_bytes());
                bytes.extend_from_slice(&page.to_le_bytes());
                bytes.push(0); // padding
                bytes
            }
            TLV::SunPhyInformation(band, mod_type, mode) => {
                let mut bytes = type_length(4, 3);
                bytes.extend_from_slice(&band.to_le_bytes());
                bytes.extend_from_slice(&mod_type.to_le_bytes());
                bytes.extend_from_slice(&mode.to_le_bytes());
                bytes.push(0); // padding
                bytes
            }
            TLV::SOFTimestamp(ts) => {
                let mut bytes = type_length(5, 8);
                bytes.extend_from_slice(&ts.to_le_bytes());
                bytes
            }
            TLV::EOFTimestamp(ts) => {
                let mut bytes = type_length(6, 8);
                bytes.extend_from_slice(&ts.to_le_bytes());
                bytes
            }
            TLV::ASN(num) => {
                let mut bytes = type_length(7, 8);
                bytes.extend_from_slice(&num.to_le_bytes());
                bytes
            }
            TLV::SlotTimestamp(ts) => {
                let mut bytes = type_length(8, 8);
                bytes.extend_from_slice(&ts.to_le_bytes());
                bytes
            }
            TLV::TimeslotLength(t) => {
                let mut bytes = type_length(9, 8);
                bytes.extend_from_slice(&t.to_le_bytes());
                bytes
            }
            TLV::LQI(lqi) => {
                let mut bytes = type_length(10, 1);
                bytes.extend_from_slice(&lqi.to_le_bytes());
                bytes.extend_from_slice(&[0, 0, 0]); // padding
                bytes
            }
            TLV::ChannelFrequency(freq) => {
                let mut bytes = type_length(11, 4);
                bytes.extend_from_slice(&freq.to_le_bytes());
                bytes
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TapHeader {
    tlvs: Vec<TLV>,
}

impl TapHeader {
    pub fn new(tlvs: Vec<TLV>) -> Self {
        Self { tlvs }
    }

    pub fn as_bytes(self) -> Vec<u8> {
        let mut bytes = vec![0, 0]; // version, reserved
        // Initial header length version, reserved, header and length
        let mut header_length: u16 = 4;

        let tlv_bytes: Vec<u8> = self
            .tlvs
            .iter()
            .flat_map(|tlv| {
                let b = tlv.as_bytes();
                header_length += b.len() as u16;
                b
            })
            .collect();

        bytes.extend_from_slice(&header_length.to_le_bytes());
        bytes.extend_from_slice(&tlv_bytes);

        bytes
    }
}

pub struct ZigbeePacket {
    timestamp: Duration,
    lqi: u8,
    rssi: f32,
    channel: u8,
    payload: Vec<u8>,
}

impl ZigbeePacket {
    pub fn new(timestamp: Duration, lqi: u8, rssi: f32, channel: u8, payload: &[u8]) -> Self {
        Self {
            timestamp,
            lqi,
            rssi,
            channel,
            payload: payload.into(),
        }
    }

    pub fn from_json(line: &str) -> anyhow::Result<Self> {
        let json: Value = serde_json::from_str(line.trim())?;

        Ok(Self {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?,
            lqi: json["Q"]
                .as_u64()
                .unwrap_or(0)
                .try_into()
                .expect("LQI malformed"),
            rssi: json["R"].as_f64().unwrap_or(0.0) as f32,
            channel: json["C"]
                .as_u64()
                .unwrap_or(0)
                .try_into()
                .expect("Channel malformed"),
            payload: hex::decode(json["S"].as_str().expect("payload missing"))
                .expect("payload is not a valid hex string"),
        })
    }

    pub fn as_pcap_packet(&self) -> anyhow::Result<PcapPacket<'_>> {
        let tlvs = vec![
            TLV::RSS(self.rssi),
            TLV::LQI(self.lqi),
            TLV::ChannelAssignment(self.channel as u16, 0),
        ];
        let mut data = TapHeader::new(tlvs).as_bytes();
        data.extend_from_slice(&self.payload);

        let packet = PcapPacket {
            timestamp: self.timestamp,
            orig_len: data.len().try_into()?,
            data: data.into(),
        };

        Ok(packet)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = AppArgs::parse();

    let ports = available_ports()?;

    let interfaces: Vec<Interface> = ports
        .iter()
        .filter_map(|p| match &p.port_type {
            SerialPortType::UsbPort(t) => Some(Interface {
                value: p.port_name.clone().into(),
                display: t.product.clone().unwrap_or("Unknown".to_string()).into(),
                dlt: Dlt {
                    data_link_type: DataLink::IEEE802_15_4_TAP,
                    name: "IEEE802_15_4_TAP".into(),
                    display: "IEEE 802.15.4".into(),
                },
            }),
            _ => None,
        })
        .collect();
    let interface_refs: Vec<&Interface> = interfaces.iter().collect();

    match args.extcap.run()? {
        ExtcapStep::Interfaces(interfaces_step) => {
            interfaces_step.list_interfaces(&cargo_metadata!(), &interface_refs, &[]);
        }
        ExtcapStep::Dlts(dlts_step) => {
            dlts_step.print_from_interfaces(&interface_refs)?;
        }
        ExtcapStep::Config(config_step) => {
            config_step.list_configs(&[]);
        }
        ExtcapStep::ReloadConfig(reload_config_step) => {
            return Err(anyhow::anyhow!(
                "Unexpected config to reload: {}",
                reload_config_step.config
            ));
        }
        ExtcapStep::Capture(capture_step) => {
            let mut controls = (
                capture_step.spawn_channel_control_reader_async(),
                capture_step.new_control_sender_async().await,
            );

            if let (Some(control_reader), Some(_control_sender)) = &mut controls {
                let packet = control_reader
                    .read_packet()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("Unable to read packet"))?;
                assert_eq!(packet.command, ControlCommand::Initialized);
            }

            let port = tokio_serial::new(capture_step.interface, 1_000_000)
                .timeout(Duration::from_secs(10))
                .open()
                .expect("Failed to open port");

            let reader = BufReader::new(port);

            let pcap_header = PcapHeader {
                datalink: DataLink::IEEE802_15_4_TAP,
                endianness: pcap_file::Endianness::Little,
                ..Default::default()
            };
            let mut pcap_writer = PcapWriter::with_header(capture_step.fifo, pcap_header)?;

            for line in reader.lines() {
                let packet = ZigbeePacket::from_json(&line?)?;

                pcap_writer.write_packet(&packet.as_pcap_packet()?)?;
            }
        }
    }
    Ok(())
}
