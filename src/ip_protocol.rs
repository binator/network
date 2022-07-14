//! Handles parsing of Internet Protocol fields (shared between ipv4 and ipv6)

use binator_base::octet;
use binator_core::{
  Contexting,
  CoreAtom,
  Parse,
  Parsed,
  Streaming,
};
use binator_utils::Utils;

use crate::struct_variants;

struct_variants! {
  IPProtocol, protocol, u8:
    /// IPv6 Hop-by-Hop Option
    HOPOPT      => 0x00,
    /// Internet Control Message Protocol
    ICMP        => 0x01,
    /// Internet Group Management Protocol
    IGMP        => 0x02,
    /// Gateway-to-Gateway Protocol
    GGP         => 0x03,
    /// IP in IP
    IP_IN_IP    => 0x04,
    /// Internet Stream Protocol
    ST          => 0x05,
    ///   Transmission Control Protocol
    TCP         => 0x06,
    /// Core-based trees
    CBT         => 0x07,
    /// Exterior Gateway Protocol
    EGP         => 0x08,
    /// Interior Gateway Protocol
    IGP         => 0x09,
    /// BBN RCC Monitoring
    BBN_RCC_MON => 0x0A,
    /// Network Voice Protocol
    NVP_II      => 0x0B,
    /// Xerox PUP
    PUP         => 0x0C,
    /// ARGUS
    ARGUS       => 0x0D,
    /// EMCON
    EMCON       => 0x0E,
    /// Cross Net Debugger
    XNET        => 0x0F,
    /// Chaos
    CHAOS       => 0x10,
    /// User Datagram Protocol
    UDP         => 0x11,
    /// Multiplexing
    MUX         => 0x12,
    /// DCN Measurement Subsystems
    DCN_MEAS    => 0x13,
    /// Host Monitoring Protocol
    HMP         => 0x14,
    /// Packet Radio Measurement
    PRM         => 0x15,
    /// XEROX NS IDP
    XNS_IDP     => 0x16,
    /// Trunk-1
    TRUNK_1     => 0x17,
    /// Trunk-2
    TRUNK_2     => 0x18,
    /// Leaf-1
    LEAF_1      => 0x19,
    /// Leaf-2
    LEAF_2      => 0x1A,
    /// Reliable Data Protocol
    RDP         => 0x1B,
    /// Internet Reliable Transaction Protocol
    IRTP        => 0x1C,
    /// ISO Transport Protocol Class 4
    ISO_TP4     => 0x1D,
    /// Bulk Data Transfer Protocol
    NETBLT      => 0x1E,
    /// MFE Network Services Protocol
    MFE_NSP     => 0x1F,
    /// MERIT Internodal Protocol
    MERIT_INP   => 0x20,
    /// Datagram Congestion Control Protocol
    DCCP        => 0x21,
    /// Third Party Connect Protocol
    PC3         => 0x22,
    /// Inter-Domain Policy Routing Protocol
    IDPR        => 0x23,
    /// Xpress Transport Protocol
    XTP         => 0x24,
    /// Datagram Delivery Protocol
    DDP         => 0x25,
    /// IDPR Control Message Transport Protocol
    IDPR_CMTP   => 0x26,
    /// TP++ Transport Protocol
    TP          => 0x27,
    /// IL Transport Protocol
    IL          => 0x28,
    /// IPv6 Encapsulation
    IPV6        => 0x29,
    /// Source Demand Routing Protocol
    SDRP        => 0x2A,
    /// Routing Header for IPv6
    IPV6_ROUTE  => 0x2B,
    /// Fragment Header for IPv6
    IPV6_FRAG   => 0x2C,
    /// Inter-Domain Routing Protocol
    IDRP        => 0x2D,
    /// Resource Reservation Protocol
    RSVP        => 0x2E,
    /// Generic Routing Encapsulation
    GRE         => 0x2F,
    /// Dynamic Source Routing Protocol
    DSR         => 0x30,
    /// Burroughs Network Architecture
    BNA         => 0x31,
    /// Encapsulating Security Payload
    ESP         => 0x32,
    /// Authentication Header
    AH          => 0x33,
    /// Integrated Net Layer Security Protocol
    I_NLSP      => 0x34,
    /// SwIPe
    SWIPE       => 0x35,
    /// NBMA Address Resolution Protocol
    NARP        => 0x36,
    /// IP Mobility (Min Encap)
    MOBILE      => 0x37,
    /// Transport Layer Security Protocol (using Kryptonet key management)
    TLSP        => 0x38,
    /// Simple Key-Management for Internet Protocol
    SKIP        => 0x39,
    /// ICMP for IPv6
    ICMP_6      => 0x3A,
    /// No Next Header for IPv6
    NO_NXT_6    => 0x3B,
    /// Destination Options for IPv6
    OPTS_6      => 0x3C,
    /// Any host internal protocol
    AHIP        => 0x3D,
    /// CFTP
    CFTP        => 0x3E,
    /// Any local network
    ALN         => 0x3F,
    /// SATNET and Backroom EXPAK
    SAT_EXPAK   => 0x40,
    /// Kryptolan
    KRYPTOLAN   => 0x41,
    /// MIT Remote Virtual Disk Protocol
    RVD         => 0x42,
    /// Internet Pluribus Packet Core
    IPPC        => 0x43,
    /// Any distributed file system
    ADFS        => 0x44,
    /// SATNET Monitoring
    SAT_MON     => 0x45,
    /// VISA Protocol
    VISA        => 0x46,
    /// Internet Packet Core Utility
    IPCU        => 0x47,
    /// Computer Protocol Network Executive
    CPNX        => 0x48,
    /// Computer Protocol Heart Beat
    CPHB        => 0x49,
    /// Wang Span Network
    WSN         => 0x4A,
    /// Packet Video Protocol
    PVP         => 0x4B,
    /// Backroom SATNET Monitoring
    BR_SAT_MON  => 0x4C,
    /// SUN ND PROTOCOL-Temporary
    SUN_ND      => 0x4D,
    /// WIDEBAND Monitoring
    WB_MON      => 0x4E,
    /// WIDEBAND EXPAK
    WB_EXPAK    => 0x4F,
    /// International Organization for Standardization Internet Protocol
    ISO_IP      => 0x50,
    /// Versatile Message Transaction Protocol
    VMTP        => 0x51,
    /// Secure Versatile Message Transaction Protocol
    SECURE_VMTP => 0x52,
    /// VINES
    VINES       => 0x53,
    /// TTP or Internet Protocol Traffic Manager
    TTP_OR_IPTM => 0x54,
    /// NSFNET-IGP
    NSFNET_IGP  => 0x55,
    /// Dissimilar Gateway Protocol
    DGP         => 0x56,
    /// TCF
    TCF         => 0x57,
    /// EIGRP
    EIGRP       => 0x58,
    /// Open Shortest Path First
    OSPF        => 0x59,
    /// Sprite RPC Protocol
    SPRITE_RPC  => 0x5A,
    /// Locus Address Resolution Protocol
    LARP        => 0x5B,
    /// Multicast Transport Protocol
    MTP         => 0x5C,
    /// AX.25
    AX25        => 0x5D,
    /// KA9Q NOS compatible IP over IP tunneling
    OS          => 0x5E,
    /// Mobile Internetworking Control Protocol
    MICP        => 0x5F,
    /// Semaphore Communications Sec. Pro
    SCC_SP      => 0x60,
    /// Ethernet-within-IP Encapsulation
    ETHERIP     => 0x61,
    /// Encapsulation Header
    ENCAP       => 0x62,
    /// Any private encryption scheme
    APES        => 0x63,
    /// GMTP
    GMTP        => 0x64,
    /// Ipsilon Flow Management Protocol
    IFMP        => 0x65,
    /// PNNI over IP
    PNNI        => 0x66,
    /// Protocol Independent Multicast
    PIM         => 0x67,
    /// IBM's ARIS (Aggregate Route IP Switching) Protocol
    ARIS        => 0x68,
    /// SCPS (Space Communications Protocol Standards)
    SCPS        => 0x69,
    /// QNX
    QNX         => 0x6A,
    /// Active Networks
    AN          => 0x6B,
    /// IP Payload Compression Protocol
    IP_COMP     => 0x6C,
    /// Sitara Networks Protocol
    SNP         => 0x6D,
    /// Compaq Peer Protocol
    COMPAQ_PEER => 0x6E,
    /// IPX in IP
    IPX_IN_IP   => 0x6F,
    /// Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned)
    VRRP        => 0x70,
    /// PGM Reliable Transport Protocol
    PGM         => 0x71,
    /// Any 0-hop protocol
    AHP         => 0x72,
    /// Layer Two Tunneling Protocol Version 3
    L2TP        => 0x73,
    /// D-II Data Exchange (DDX)
    DDX         => 0x74,
    /// Interactive Agent Transfer Protocol
    IATP        => 0x75,
    /// Schedule Transfer Protocol
    STP         => 0x76,
    /// SpectraLink Radio Protocol
    SRP         => 0x77,
    /// Universal Transport Interface Protocol
    UTI         => 0x78,
    /// Simple Message Protocol
    SMP         => 0x79,
    /// Simple Multicast Protocol
    SM          => 0x7A,
    /// Performance Transparency Protocol
    PTP         => 0x7B,
    ///  IS-IS over IPv4  Intermediate System to Intermediate System (IS-IS) Protocol over IPv4
    IS_IS       => 0x7C,
    /// Flexible Intra-AS Routing Environment
    FIRE        => 0x7D,
    /// Combat Radio Transport Protocol
    CRTP        => 0x7E,
    /// Combat Radio User Datagram
    CRUDP       => 0x7F,
    /// Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment
    SSCOPMCE    => 0x80,
    /// IPLT
    IPLT        => 0x81,
    /// Secure Packet Shield
    SPS         => 0x82,
    /// Private IP Encapsulation within IP
    PIPE        => 0x83,
    /// Stream Control Transmission Protocol
    SCTP        => 0x84,
    /// Fibre Channel
    FC          => 0x85,
    /// Reservation Protocol (RSVP) End-to-End Ignore
    RSVP_IGNORE => 0x86,
    ///  Mobility Extension Header for IPv6
    MOBILITY_6  => 0x87,
    /// Lightweight User Datagram Protocol
    UDP_LITE    => 0x88,
    /// Multiprotocol Label Switching Encapsulated in IP
    MPLS_IN_IP  => 0x89,
    /// MANET Protocols
    MANET       => 0x8A,
    /// Host Identity Protocol
    HIP         => 0x8B,
    /// Site Multihoming by IPv6 Intermediation
    SHIM_6      => 0x8C,
    /// Wrapped Encapsulating Security Payload
    WESP        => 0x8D,
    ///  Robust Header Compression
    ROHC        => 0x8E,
}

pub(crate) fn ip_protocol<Stream, Context>(stream: Stream) -> Parsed<IPProtocol, Stream, Context>
where
  Stream: Streaming,
  Context: Contexting<CoreAtom<Stream>>,
  Stream::Item: Into<u8>,
{
  octet.map(IPProtocol::new).parse(stream)
}

#[cfg(test)]
mod tests {
  use binator_context::Ignore;
  use binator_core::Parsed;

  use super::IPProtocol;

  #[test]
  fn ip_protocol() {
    let tests = [
      ([1], IPProtocol::ICMP),
      ([6], IPProtocol::TCP),
      ([17], IPProtocol::UDP),
    ];

    for (stream, expected) in tests {
      assert_eq!(
        super::ip_protocol::<_, Ignore>(&stream[..]),
        Parsed::Success {
          stream: &[][..],
          token: expected
        }
      );
    }
  }
}
