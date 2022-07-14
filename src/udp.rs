//! Handles parsing of UDP header

use binator_core::{
  Contexting,
  CoreAtom,
  Parse,
  Parsed,
  Streaming,
  Success,
};
use binator_number::u16_be;
use binator_utils::UtilsAtom;

/// Data of a UDP Header
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UdpHeader {
  /// This field identifies the sender's port, when used, and should be assumed
  /// to be the port to reply to if needed. If not used, it should be zero. If
  /// the source host is the client, the port number is likely to be an
  /// ephemeral port. If the source host is the server, the port number is
  /// likely to be a well-known port number from 0 to 1023.
  pub source_port: u16,
  /// This field identifies the receiver's port and is required. Similar to
  /// source port number, if the client is the destination host then the port
  /// number will likely be an ephemeral port number and if the destination host
  /// is the server then the port number will likely be a well-known port
  /// number.
  pub dest_port: u16,
  /// This field specifies the length in bytes of the UDP header and UDP data.
  pub length: u16,
  /// The checksum field may be used for error-checking of the header and data.
  /// This field is optional in IPv4, and mandatory in most cases in IPv6. The
  /// field carries all-zeros if unused.
  pub checksum: u16,
}

/// UDP header parser
pub fn udp_header<Stream, Context>(stream: Stream) -> Parsed<UdpHeader, Stream, Context>
where
  Stream: Streaming,
  Stream: Eq,
  Stream::Item: Into<u8>,
  Context: Contexting<CoreAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
{
  let Success {
    token: (source_port, dest_port, length, checksum),
    stream,
  } = (u16_be, u16_be, u16_be, u16_be).parse(stream)?;

  Parsed::Success {
    token: UdpHeader {
      source_port,
      dest_port,
      length,
      checksum,
    },
    stream,
  }
}

#[cfg(test)]
mod tests {
  use binator_context::Ignore;
  use binator_core::Parsed;

  use super::UdpHeader;

  #[test]
  fn udp_header_works() {
    let bytes = [0x00, 0x12, 0x11, 0x11, 0x00, 0x1B, 0x21, 0x0F];
    let expectation = UdpHeader {
      source_port: 0x12,
      dest_port: 0x1111,
      length: 0x1B,
      checksum: 0x210F,
    };
    assert_eq!(
      super::udp_header::<_, Ignore>(&bytes[..]),
      Parsed::Success {
        token: expectation,
        stream: &[][..]
      }
    );
  }
}
