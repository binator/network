use binator_base::octet;
use binator_core::{
  Contexting,
  CoreAtom,
  Parse,
  Parsed,
  Streaming,
};
use binator_utils::{
  Utils,
  UtilsAtom,
};

use crate::struct_variants;

struct_variants! {
  EtherType, ether_type, u16:
    /// 802.3 Min data length
    LANMIN => 0x002E,
    /// 802.3 Max data length
    LANMAX => 0x05DC,
    /// Internet Protocol version 4 (IPv4)
    IPV4 => 0x0800,
    /// Address Resolution Protocol (ARP)
    ARP => 0x0806,
    /// Wake-on-LAN
    WOL => 0x0842,
    /// IETF TRILL Protocol
    TRILL => 0x22F3,
    /// DECnet Phase IV
    DECNET => 0x6003,
    /// Reverse Address Resolution Protocol
    RARP => 0x8035,
    /// AppleTalk (Ethertalk)
    APPLE_TALK => 0x809B,
    /// AppleTalk Address Resolution Protocol (AARP)
    AARP => 0x80F3,
    /// VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq
    VLAN => 0x8100,
    /// IPX
    IPX => 0x8137,
    /// QNX Qnet
    QNET => 0x8204,
    /// Internet Protocol Version 6 (IPv6)
    IPV6 => 0x86DD,
    /// Ethernet flow control
    FLOW_CONTROL => 0x8808,
    /// CobraNet
    COBRA_NET => 0x8819,
    /// MPLS unicast
    MPLS_UNI => 0x8847,
    /// MPLS multicast
    MPLS_MUTLI => 0x8848,
    /// PPPoE Discovery Stage
    PPPOE_DISCOVERY => 0x8863,
    /// PPPoE Session Stage
    PPPOE_SESSION => 0x8864,
    /// HomePlug 1.0 MME
    HOME_PLUG => 0x887B,
    /// EAP over LAN (IEEE 802.1X)
    EAPOL => 0x888E,
    /// PROFINET Protocol
    PROFINET => 0x8892,
    /// HyperSCSI (SCSI over Ethernet)
    HYPER_SCSI => 0x889A,
    /// ATA over Ethernet
    ATAOE => 0x88A2,
    /// EtherCAT Protocol
    ETHER_CAT => 0x88A4,
    /// Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq
    QINQ => 0x88A8,
    /// Ethernet Powerlink
    POWER_LINK => 0x88AB,
    /// GOOSE (Generic Object Oriented Substation event)
    GOOSE => 0x88B8,
    /// GSE (Generic Substation Events) Management Services
    GSE => 0x88B9,
    /// Link Layer Discovery Protocol (LLDP)
    LLDP => 0x88CC,
    /// SERCOS III
    SERCOS => 0x88CD,
    /// HomePlug AV MME
    HOME_PLUG_AV => 0x88E1,
    /// Media Redundancy Protocol (IEC62439-2)
    MRP => 0x88E3,
    /// MAC security (IEEE 802.1AE)
    MAC_SEC => 0x88E5,
    /// Provider Backbone Bridges (PBB) (IEEE 802.1ah)
    PBB => 0x88E7,
    /// Precision Time Protocol (PTP) over Ethernet (IEEE 1588)
    PTP => 0x88F7,
    /// Parallel Redundancy Protocol (PRP)
    PRP => 0x88FB,
    /// IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
    CFM => 0x8902,
    /// Fibre Channel over Ethernet (FCoE)
    FCOE => 0x8906,
    /// FCoE Initialization Protocol
    FCOEI => 0x8914,
    /// RDMA over Converged Ethernet (RoCE)
    ROCE => 0x8915,
    /// TTEthernet Protocol Control Frame (TTE)
    TTE => 0x891D,
    /// High-availability Seamless Redundancy (HSR)
    HSR => 0x892F,
    /// Ethernet Configuration Testing Protocol
    CTP => 0x9000,
    /// VLAN-tagged (IEEE 802.1Q) frame with double tagging
    VLAN_DOUBLE => 0x9100,
    /// Veritas Low Latency Transport (LLT)
    LLT => 0xCAFE,
}

pub(crate) fn ether_type<Stream, Context>(stream: Stream) -> Parsed<EtherType, Stream, Context>
where
  Stream: Clone + Eq,
  Stream: Streaming,
  Context: Contexting<CoreAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Stream::Item: Into<u8>,
{
  octet
    .fill()
    .map(u16::from_be_bytes)
    .map(EtherType::new)
    .parse(stream)
}

#[cfg(test)]
mod tests {
  use binator_context::Ignore;
  use binator_core::Parsed;

  use super::EtherType;

  #[test]
  fn ether_type() {
    let tests = [
      ([0x08, 0x00], EtherType::IPV4),
      ([0x08, 0x06], EtherType::ARP),
      ([0x86, 0xDD], EtherType::IPV6),
      ([0x81, 0x00], EtherType::VLAN),
    ];

    for (stream, expected) in tests {
      assert_eq!(
        super::ether_type::<_, Ignore>(&stream[..]),
        Parsed::Success {
          token: expected,
          stream: &[][..],
        }
      );
    }
  }
}
