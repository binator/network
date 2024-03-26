//! Handles parsing of IPv6 headers

use std::{
  fmt::{
    Display,
    Formatter,
  },
  net::Ipv6Addr,
};

use binator::{
  base::{
    nbit,
    octet,
    NBit,
  },
  utils::{
    Utils,
    UtilsAtom,
  },
  Contexting,
  CoreAtom,
  Parse,
  Parsed,
  Streaming,
  Success,
};

use crate::ip_protocol::{
  self,
  IPProtocol,
};

/// <https://en.wikipedia.org/wiki/IPv6_packet>
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IPv6Header {
  /// The constant 6 (bit sequence 0110).
  pub version: u8,
  /// Differentiated services is a computer networking architecture
  /// that specifies a mechanism for classifying and managing network traffic
  /// and providing quality of service (QoS) on modern IP networks.
  pub ds: u8,
  /// Explicit Congestion Notification (ECN); priority values subdivide into
  /// ranges: traffic where the source provides congestion control and
  /// non-congestion control traffic.
  pub ecn: u8,
  /// A high-entropy identifier of a flow of packets between a source and
  /// destination. A flow is a group of packets, e.g., a TCP session or a media
  /// stream. The special flow label 0 means the packet does not belong to any
  /// flow (using this scheme). An older scheme identifies flow by source
  /// address and port, destination address and port, protocol (value of the
  /// last Next Header field). It has further been suggested that the flow
  /// label be used to help detect spoofed packets.
  pub flow_label: u32,
  /// The size of the payload in octets, including any extension headers. The
  /// length is set to zero when a Hop-by-Hop extension header carries a Jumbo
  /// Payload option.
  pub length: u16,
  /// Specifies the type of the next header. This field usually specifies the
  /// transport layer protocol used by a packet's payload. When extension
  /// headers are present in the packet this field indicates which extension
  /// header follows. The values are shared with those used for the IPv4
  /// protocol field, as both fields have the same function.
  pub next_header: IPProtocol,
  /// Replaces the time to live field in IPv4. This value is decremented by one
  /// at each forwarding node and the packet is discarded if it becomes 0.
  /// However, the destination node should process the packet normally even if
  /// received with a hop limit of 0.
  pub hop_limit: u8,
  /// The unicast IPv6 address of the sending node.
  pub source_addr: Ipv6Addr,
  /// The IPv6 unicast or multicast address of the destination node(s).
  pub dest_addr: Ipv6Addr,
}

/// Aom produced by ipv6_header parser
pub enum Ipv6Atom {
  /// When version is not 6
  Version(u8),
}

impl Display for Ipv6Atom {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Version(version) => {
        write!(f, "Ipv4Context: Version field is not 6 found {}", version)
      }
    }
  }
}

/// Parse IPv6 header
#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
pub fn ipv6_header<Stream, Context>(stream: Stream) -> Parsed<IPv6Header, Stream, Context>
where
  Stream: Clone,
  Stream: Eq,
  Stream: Streaming,
  Stream::Item: Into<u8>,
  Context: Contexting<CoreAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<Ipv6Atom>,
{
  let Success {
    token: (version, tc_0),
    stream,
  } = nbit(NBit::FOUR)
    .try_map(|(version, tc_0)| {
      if version == 6 {
        Ok((version, tc_0))
      } else {
        Err(Context::new(Ipv6Atom::Version(version)))
      }
    })
    .parse(stream)?;

  let Success {
    token: (tc_1, flow_label_0),
    stream,
  } = nbit(NBit::FOUR).parse(stream)?;

  let Success {
    token: flow_label,
    stream,
  } = octet
    .and(octet)
    .map(|(flow_label_1, flow_label_2)| {
      u32::from_be_bytes([0, flow_label_0, flow_label_1, flow_label_2])
    })
    .parse(stream)?;

  let Success {
    token: length,
    stream,
  } = octet.fill().map(u16::from_be_bytes).parse(stream)?;
  let Success {
    token: next_header,
    stream,
  } = ip_protocol::ip_protocol.parse(stream)?;

  let Success {
    token: hop_limit,
    stream,
  } = octet.parse(stream)?;

  let Success {
    token: source_addr,
    stream,
  } = octet.fill().map(Ipv6Addr::from).parse(stream)?;

  let Success {
    token: dest_addr,
    stream,
  } = octet.fill().map(Ipv6Addr::from).parse(stream)?;

  Parsed::Success {
    token: IPv6Header {
      version,
      ds: (tc_0 << 2) + (tc_1 >> 2),
      ecn: tc_1 & 0b11,
      flow_label,
      length,
      next_header,
      hop_limit,
      source_addr,
      dest_addr,
    },
    stream,
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv6Addr;

  use binator::{
    context::Ignore,
    Parsed,
  };
  use pretty_assertions::assert_eq;

  use super::{
    IPProtocol,
    IPv6Header,
  };

  #[test]
  fn ipv6_header() {
    let bytes = [
      0x60, 0x20, 0x01, 0xFF, 0x05, 0x78, 0x3A, 0x05, 0x20, 0x01, 0x0D, 0xB8, 0x5C, 0xF8, 0x1A,
      0xA8, 0x24, 0x81, 0x61, 0xE6, 0x5A, 0xC6, 0x03, 0xE0, 0x20, 0x01, 0x0D, 0xB8, 0x78, 0x90,
      0x2A, 0xE9, 0x90, 0x8F, 0xA9, 0xF4, 0x2F, 0x4A, 0x9B, 0x80,
    ];

    let expectation = IPv6Header {
      version: 6,
      ds: 0,
      ecn: 2,
      flow_label: 511,
      length: 1400,
      next_header: IPProtocol::ICMP_6,
      hop_limit: 5,
      source_addr: Ipv6Addr::new(0x2001, 0xDB8, 0x5CF8, 0x1AA8, 0x2481, 0x61E6, 0x5AC6, 0x3E0),
      dest_addr: Ipv6Addr::new(
        0x2001, 0xDB8, 0x7890, 0x2AE9, 0x908F, 0xA9F4, 0x2F4A, 0x9B80,
      ),
    };
    assert_eq!(
      super::ipv6_header::<_, Ignore>(&bytes[..]),
      Parsed::Success {
        token: expectation,
        stream: "".as_bytes(),
      }
    );
  }
}
