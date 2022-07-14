#![doc = include_str!("../readme.md")]
// #![cfg_attr(not(test), no_std)]
#![feature(trait_alias)]
// #![feature(generic_const_exprs)]
#![warn(missing_docs)]
#![deny(clippy::default_numeric_fallback)]

mod ether_type;
pub use ether_type::*;
mod ethernet;
pub use ethernet::*;
mod ip_addr;
pub use ip_addr::*;
mod ip_protocol;
pub use ip_protocol::*;
mod ipv4;
pub use ipv4::*;
mod ipv6;
pub use ipv6::*;
mod tcp;
pub use tcp::*;
mod udp;
pub use udp::*;

macro_rules! pascal_name {
  ($name:ident) => {
    const_format::map_ascii_case!(const_format::Case::Pascal, core::stringify!($name))
  };
}

macro_rules! display_variants {
  ($struct_name:ident, $field_name:ident: $($variant_name:ident,)*) => {
    impl core::fmt::Display for $struct_name {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
          $(&Self::$variant_name => write!(f, "{}: {}", $crate::pascal_name!($variant_name), self.$field_name),)*
          _ => write!(f, "Unknown: {}", self.$field_name()),
        }
      }
    }
  };
}

macro_rules! decl_variants {
  ($($(#[$docs:meta])* $variant_name:ident => $variant_value:expr,)*) => {
    $($(#[$docs])* pub const $variant_name: Self = Self::new($variant_value);)*
  };
}

macro_rules! struct_variants {
  ($struct_name:ident, $field_name:ident, $field_type:ty:
    $($(#[$variant_docs:meta])* $variant_name:ident => $variant_value:expr,)*
  ) => {
    #[doc=stringify!($struct_name)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[repr(transparent)]
    pub struct $struct_name {
      $field_name: $field_type,
    }

    paste::paste! {
      #[allow(non_camel_case_types)]
      #[allow(dead_code)]
      #[allow(clippy::upper_case_acronyms)]
      enum [<Enum $struct_name>] {
        $($variant_name = $variant_value,)*
      }
    }

    impl $struct_name {
      $crate::decl_variants!{$($(#[$variant_docs])* $variant_name => $variant_value,)*}

      /// Return $struct_name from $field_type
      pub const fn new($field_name: $field_type) -> Self {
        Self { $field_name }
      }

      /// Return $field_type
      pub const fn $field_name(&self) -> $field_type {
        self.$field_name
      }
    }

    impl From<$field_type> for $struct_name {
      fn from($field_name: $field_type) -> Self {
        Self::new($field_name)
      }
    }

    impl From<$struct_name> for $field_type {
      fn from(this: $struct_name) -> Self {
        this.$field_name
      }
    }

    impl core::str::FromStr for $struct_name {
      type Err = ();
      fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
          $(core::stringify!($crate::pascal_name!($variant_name)) => Ok(Self::$variant_name),)*
          _ => Err(()),
        }
      }
    }

    $crate::display_variants!{
      $struct_name, $field_name:
        $($variant_name,)*
    }
  };
}

pub(crate) use decl_variants;
pub(crate) use display_variants;
pub(crate) use pascal_name;
pub(crate) use struct_variants;

#[cfg(test)]
mod tests {
  use core::fmt::Debug;

  use binator_base::{
    all,
    BaseAtom,
  };
  use binator_context::Tree;
  use binator_core::{
    CoreAtom,
    Parse,
    Streaming,
    Success,
  };
  use binator_number::IntRadixAtom;
  use binator_utils::UtilsAtom;
  use derive_more::{
    Display,
    From,
  };
  use pretty_assertions::assert_eq;
  use test_log::test;

  use crate::{
    ipv4_header,
    tcp_header,
    tcp_options,
    Ipv4Atom,
    TcpAtom,
    TcpOption,
  };

  #[derive(Display, Debug, Clone, PartialEq, From)]
  enum FromAtom<
    Stream: Streaming + Debug,
    Item: 'static = <Stream as Streaming>::Item,
    Error = <Stream as Streaming>::Error,
  > {
    Core(CoreAtom<Stream, Error>),
    Utils(UtilsAtom<Stream>),
    Base(BaseAtom<Item>),
    U8Radix(IntRadixAtom<u8>),
    U16Radix(IntRadixAtom<u16>),
    Tcp(TcpAtom),
    Ipv4(Ipv4Atom),
  }

  type HandleAtom<Stream> = Tree<FromAtom<Stream>>;

  #[test]
  fn parse_tcp_packet() {
    let bytes = [
      0x45, 0x00, 0x00, 0x38, 0x76, 0xF4, 0x40, 0x00, 0x40, 0x06, 0x80, 0xD9, 0xC0, 0xA8, 0x00,
      0x6C, 0xD0, 0x61, 0xB1, 0x7C, 0xB0, 0xC2, 0x00, 0x50, 0xB0, 0xEE, 0x32, 0xA6, 0x04, 0x39,
      0xAE, 0xE6, 0x50, 0x18, 0x00, 0xE5, 0x76, 0x92, 0x00, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2F,
      0x69, 0x6E, 0x64, 0x65, 0x78, 0x2E, 0x68, 0x74, 0x6D, 0x6C, 0x0A,
    ];

    let Success {
      token: (_ipv4_header, tcp_header, data),
      stream: _,
    } = (ipv4_header::<_, HandleAtom<_>>, tcp_header, all)
      .parse(bytes.as_slice())
      .unwrap();

    assert_eq!(tcp_header.source_port, 45250);
    assert_eq!(tcp_header.dest_port, 80);
    assert_eq!(data, b"GET /index.html\x0a");
  }

  #[test]
  fn parse_tcp_packet_with_options() {
    let bytes = [
      0x45, 0x20, 0x00, 0x34, 0x78, 0xD6, 0x40, 0x00, 0x35, 0x06, 0x7E, 0x77, 0x45, 0xA4, 0x10,
      0x00, 0xC0, 0xA8, 0x38, 0x0A, 0x00, 0x50, 0xC2, 0x27, 0x48, 0xF3, 0x02, 0xC2, 0x61, 0xD3,
      0x16, 0xA8, 0x80, 0x12, 0xFF, 0xFF, 0x9B, 0x80, 0x00, 0x00, 0x02, 0x04, 0x05, 0x3A, 0x01,
      0x03, 0x03, 0x04, 0x04, 0x02, 0x00, 0x00,
    ];

    let Success {
      token: (_ipv4_header, tcp_header),
      stream,
    } = (ipv4_header::<_, HandleAtom<_>>, tcp_header)
      .parse(bytes.as_slice())
      .unwrap();

    assert_eq!(tcp_header.source_port, 80);
    assert_eq!(tcp_header.dest_port, 49703);

    assert_eq!(stream, b"");

    let Success {
      token: options,
      stream,
    } = tcp_options::<_, HandleAtom<_>>
      .parse(tcp_header.options)
      .unwrap();

    // println!("{ipv4_header:#?}");
    // println!("{tcp_header:#?}");
    // println!("{options:#?}");

    assert_eq!(options[0], TcpOption::MaximumSegmentSize(1338));
    assert_eq!(options[1], TcpOption::Noop);
    assert_eq!(options[2], TcpOption::WindowScale(4));
    assert_eq!(options[3], TcpOption::SackPermitted);
    assert_eq!(options[4], TcpOption::EndOfOption);
    assert_eq!(options[5], TcpOption::EndOfOption);

    assert_eq!(options.len(), 6);
    assert_eq!(stream, b"");
  }
}
