//! Handles parsing of IPv4 headers

use std::{
  fmt::{
    Display,
    Formatter,
  },
  net::Ipv4Addr,
};

use binator_base::{
  any,
  nbit,
  octet,
  NBit,
};
use binator_core::{
  Acc,
  Contexting,
  CoreAtom,
  Parse,
  Parsed,
  Streaming,
  Success,
};
use binator_utils::{
  Utils,
  UtilsAtom,
};

use crate::ip_protocol::{
  self,
  IPProtocol,
};

/// <https://en.wikipedia.org/wiki/Internet_Protocol_version_4>
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IPv4Header<Span> {
  /// The first header field in an IP packet is the four-bit version field. For
  /// IPv4, this is always equal to 4.
  pub version: u8,
  /// The IPv4 header is variable in size due to the optional 14th field
  /// (options). The IHL field contains the size of the IPv4 header;
  /// it has 4 bits that specify the number of 32-bit words in the header.
  /// The minimum value for this field is 5, which indicates a length of 5 × 32
  /// bits = 160 bits = 20 bytes. As a 4-bit field, the maximum value is 15;
  /// this means that the maximum size of the IPv4 header is 15 × 32 bits = 480
  /// bits = 60 bytes.
  pub ihl: u8,
  /// Originally defined as the type of service (ToS),
  /// this field specifies differentiated services (DiffServ) per RFC 2474.
  /// Real-time data streaming makes use of the DSCP field.
  /// An example is Voice over IP (VoIP), which is used for interactive voice
  /// services.
  pub tos: u8,
  /// This 16-bit field defines the entire packet size in bytes, including
  /// header and data. The minimum size is 20 bytes (header without data) and
  /// the maximum is 65,535 bytes. All hosts are required to be able to
  /// reassemble datagrams of size up to 576 bytes, but most modern hosts handle
  /// much larger packets. Links may impose further restrictions on the packet
  /// size, in which case datagrams must be fragmented. Fragmentation in IPv4 is
  /// performed in either the sending host or in routers. Reassembly is
  /// performed at the receiving host.
  pub length: u16,
  /// This field is an identification field and is primarily used for uniquely
  /// identifying the group of fragments of a single IP datagram. Some
  /// experimental work has suggested using the ID field for other purposes,
  /// such as for adding packet-tracing information to help trace datagrams with
  /// spoofed source addresses, but RFC 6864 now prohibits any such use.
  pub id: u16,
  /// A three-bit field follows and is used to control or identify
  /// fragments. They are (in order, from most significant to least
  /// significant):
  ///
  ///  bit 0: Reserved; must be zero.
  ///  bit 1: Don't Fragment (DF)
  ///  bit 2: More Fragments (MF)
  ///
  /// If the DF flag is set, and fragmentation is required to route the packet,
  /// then the packet is dropped. This can be used when sending packets to a
  /// host that does not have resources to perform reassembly of fragments. It
  /// can also be used for path MTU discovery, either automatically by the host
  /// IP software, or manually using diagnostic tools such as ping or
  /// traceroute. For unfragmented packets, the MF flag is cleared. For
  /// fragmented packets, all fragments except the last have the MF flag set.
  /// The last fragment has a non-zero Fragment Offset field, differentiating it
  /// from an unfragmented packet.
  pub flags: u8,
  /// This field specifies the offset of a particular fragment relative to the
  /// beginning of the original unfragmented IP datagram. The fragmentation
  /// offset value for the first fragment is always 0. The field is 13 bits
  /// wide, so that the offset can be from 0 to 8191 (from (20  –1) to (213 –
  /// 1)). Fragments are specified in units of 8 bytes, which is why fragment
  /// length must be a multiple of 8. Therefore, the 13-bit field allows a
  /// maximum offset of (213 – 1) × 8 = 65,528 bytes, with the header length
  /// included (65,528 + 20 = 65,548 bytes), supporting fragmentation of packets
  /// exceeding the maximum IP length of 65,535 bytes.
  pub fragment_offset: u16,
  /// An eight-bit time to live field limits a datagram's lifetime to
  /// prevent network failure in the event of a routing loop. It is specified in
  /// seconds, but time intervals less than 1 second are rounded up to 1. In
  /// practice, the field is used as a hop count—when the datagram arrives at a
  /// router, the router decrements the TTL field by one. When the TTL field
  /// hits zero, the router discards the packet and typically sends an ICMP time
  /// exceeded message to the sender.  The program traceroute sends messages
  /// with adjusted TTL values and uses these ICMP time exceeded messages to
  /// identify the routers traversed by packets from the source to the
  /// destination.
  pub ttl: u8,
  /// This field defines the protocol used in the data portion of the IP
  /// datagram. IANA maintains a list of IP protocol numbers as directed by RFC
  /// 790.
  pub protocol: IPProtocol,
  /// The 16-bit IPv4 header checksum field is used for error-checking of
  /// the header. When a packet arrives at a router, the router calculates the
  /// checksum of the header and compares it to the checksum field. If the
  /// values do not match, the router discards the packet. Errors in the data
  /// field must be handled by the encapsulated protocol. Both UDP and TCP have
  /// separate checksums that apply to their data.  When a packet arrives at a
  /// router, the router decreases the TTL field in the header. Consequently,
  /// the router must calculate a new header checksum.  The checksum field is
  /// the 16 bit one's complement of the one's complement sum of all 16 bit
  /// words in the header. For purposes of computing the checksum, the value of
  /// the checksum field is zero.
  pub chksum: u16,
  /// This 32-bit field is the IPv4 address of the sender of the packet. Note
  /// that this address may be changed in transit by a network address
  /// translation device.
  pub source_addr: Ipv4Addr,
  /// This 32-bit field is the IPv4 address of the receiver of the packet. As
  /// with the source address, this may be changed in transit by a network
  /// address translation device.
  pub dest_addr: Ipv4Addr,
  /// The options field is not often used. Packets containing some options may
  /// be considered as dangerous by some routers and be blocked. Note that
  /// the value in the IHL field must include enough extra 32-bit words to hold
  /// all the options plus any padding needed to ensure that the header contains
  /// an integer number of 32-bit words. If IHL is greater than 5 (i.e., it is
  /// from 6 to 15) it means that the options field is present and must be
  /// considered. The list of options may be terminated with an EOOL (End of
  /// Options List, 0x00) option; this is only necessary if the end of the
  /// options would not otherwise coincide with the end of the header.
  pub options: Span,
}

/// Ipv4 failure cause
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Atom {
  /// When version is not 4
  Version(u8),
  /// When IHL is less than 5
  IHL(u8),
}

impl Display for Ipv4Atom {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Ipv4Atom::Version(version) => {
        write!(f, "Ipv4Context: Version field is not 4 found {}", version)
      }
      Ipv4Atom::IHL(ihl) => {
        write!(f, "Ipv4Context: IHL field is less than 5 found {}", ihl)
      }
    }
  }
}

/// Parse ipv4 header.
pub fn ipv4_header<Stream, Context>(
  stream: Stream,
) -> Parsed<IPv4Header<Stream::Span>, Stream, Context>
where
  Stream: Eq,
  Stream: Streaming,
  Stream::Item: Into<u8>,
  Context: Contexting<CoreAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<Ipv4Atom>,
{
  let Success {
    token: (version, ihl),
    stream,
  } = nbit(NBit::FOUR)
    .try_map(|(version, ihl)| {
      if version != 4 {
        Err(Context::new(Ipv4Atom::Version(version)))
      } else if ihl < 5 {
        Err(Context::new(Ipv4Atom::IHL(ihl)))
      } else {
        Ok((version, ihl))
      }
    })
    .parse(stream)?;

  let Success { token: tos, stream } = octet.parse(stream)?;

  let Success {
    token: length,
    stream,
  } = octet.fill().map(u16::from_be_bytes).parse(stream)?;

  let Success { token: id, stream } = octet.fill().map(u16::from_be_bytes).parse(stream)?;

  let Success {
    token: (flags, fragment_offset),
    stream,
  } = nbit(NBit::FIVE)
    .and(octet)
    .map(|((flags, fragment_offset_0), fragment_offset_1)| {
      (
        flags,
        u16::from_be_bytes([fragment_offset_0, fragment_offset_1]),
      )
    })
    .parse(stream)?;

  let Success { token: ttl, stream } = octet.parse(stream)?;

  let Success {
    token: protocol,
    stream,
  } = ip_protocol::ip_protocol.parse(stream)?;

  let Success {
    token: chksum,
    stream,
  } = octet.fill().map(u16::from_be_bytes).parse(stream)?;

  let Success {
    token: source_addr,
    stream,
  } = octet.fill().map(Ipv4Addr::from).parse(stream)?;

  let Success {
    token: dest_addr,
    stream,
  } = octet.fill().map(Ipv4Addr::from).parse(stream)?;

  let Success {
    token: Success {
      stream: options, ..
    },
    stream,
  } = any
    .drop()
    .fold_bounds(usize::from(ihl - 5) * 4, || (), Acc::acc)
    .span()
    .parse(stream)?;

  Parsed::Success {
    token: IPv4Header {
      version,
      ihl,
      tos,
      length,
      id,
      flags,
      fragment_offset,
      ttl,
      protocol,
      chksum,
      source_addr,
      dest_addr,
      options,
    },
    stream,
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use binator_context::Ignore;
  use binator_core::Parsed;

  use super::{
    IPProtocol,
    IPv4Header,
  };

  #[test]
  fn ipv4_header() {
    let data = [
      0x45, 0x00, 0x05, 0xDC, 0x1A, 0xE6, 0x20, 0x00, 0x40, 0x01, 0x22, 0xED, 0x0A, 0x0A, 0x01,
      0x87, 0x0A, 0x0A, 0x01, 0xB4,
    ];

    let expectation = IPv4Header {
      version: 4,
      ihl: 5,
      tos: 0,
      length: 1500,
      id: 0x1AE6,
      flags: 0x01,
      fragment_offset: 0,
      ttl: 64,
      protocol: IPProtocol::ICMP,
      chksum: 0x22ED,
      source_addr: Ipv4Addr::new(10, 10, 1, 135),
      dest_addr: Ipv4Addr::new(10, 10, 1, 180),
      options: "".as_bytes(),
    };
    assert_eq!(
      Parsed::Success {
        token: expectation,
        stream: "".as_bytes(),
      },
      super::ipv4_header::<_, Ignore>(data.as_slice())
    );
  }
}
