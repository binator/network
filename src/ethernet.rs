//! Handles parsing of Ethernet headers

use binator::{
  base::octet,
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

use crate::ether_type::{
  ether_type,
  EtherType,
};

/// EthernetFrame
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EthernetFrame {
  /// MAC destination
  pub destination: [u8; 6],
  /// MAC source
  pub source: [u8; 6],
  /// EtherType used
  pub ether_type: EtherType,
  /// TCI
  pub tci: Option<u16>,
}

/// Parser that return a ethernet frame on success
/// <https://en.wikipedia.org/wiki/Ethernet_frame>
pub fn ethernet_frame<Stream, Context>(stream: Stream) -> Parsed<EthernetFrame, Stream, Context>
where
  Stream: Clone,
  Stream: Eq,
  Stream: Streaming,
  Stream::Item: Into<u8>,
  Context: Contexting<CoreAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<UtilsAtom<Stream>>,
{
  let Success {
    token: destination,
    stream,
  } = octet.fill().parse(stream)?;
  let Success {
    token: source,
    stream,
  } = octet.fill().parse(stream)?;
  let Success {
    token: (ether_type, tci),
    stream,
  } = ether_type
    .and_then(|tmp_ether_type| {
      move |stream: Stream| {
        if tmp_ether_type == EtherType::VLAN {
          let Success { token: tci, stream } =
            octet.fill().map(u16::from_be_bytes).parse(stream)?;
          let Success {
            token: ether_type,
            stream,
          } = ether_type.parse(stream)?;

          Parsed::Success {
            token: (ether_type, Some(tci)),
            stream,
          }
        } else {
          Parsed::Success {
            token: (tmp_ether_type, None),
            stream,
          }
        }
      }
    })
    .parse(stream)?;

  Parsed::Success {
    token: EthernetFrame {
      destination,
      source,
      ether_type,
      tci,
    },
    stream,
  }
}

#[cfg(test)]
mod tests {
  use binator::{
    context::Ignore,
    Parsed,
  };

  use super::{
    EtherType,
    EthernetFrame,
  };

  #[test]
  fn ethernet_frame() {
    let tests = [
      (
        &[
          0x00, 0x23, 0x54, 0x07, 0x93, 0x6C, 0x00, 0x1B, 0x21, 0x0F, 0x91, 0x9B, 0x08, 0x00,
        ][..],
        EthernetFrame {
          destination: [0x00, 0x23, 0x54, 0x07, 0x93, 0x6C],
          source: [0x00, 0x1B, 0x21, 0x0F, 0x91, 0x9B],
          ether_type: EtherType::IPV4,
          tci: None,
        },
      ),
      (
        &[
          0x00, 0x23, 0x54, 0x07, 0x93, 0x6C, 0x00, 0x1B, 0x21, 0x0F, 0x91, 0x9B, 0x81, 0x00, 0x04,
          0xD2, 0x08, 0x00,
        ][..],
        EthernetFrame {
          destination: [0x00, 0x23, 0x54, 0x07, 0x93, 0x6C],
          source: [0x00, 0x1B, 0x21, 0x0F, 0x91, 0x9B],
          ether_type: EtherType::IPV4,
          tci: Some(1234),
        },
      ),
    ];

    for (stream, expected) in tests {
      assert_eq!(
        super::ethernet_frame::<_, Ignore>(stream),
        Parsed::Success {
          token: expected,
          stream: b"".as_slice(),
        }
      );
    }
  }
}
