//! Handles parsing of TCP headers

use std::fmt::{
  Debug,
  Display,
  Formatter,
};

use binator::{
  base::{
    any,
    is,
    octet,
    primitive::{
      u16_be,
      u32_be,
    },
    BaseAtom,
    IntRadixAtom,
  },
  utils::{
    Acc,
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

/// Meta trait for tcp combinator
pub trait TcpParse<Stream, Context> = where
  Stream: Streaming + Clone + Eq,
  <Stream as Streaming>::Item: Into<u8> + Clone,
  <Stream as Streaming>::Item: PartialEq<<Stream as Streaming>::Item>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<BaseAtom<u8>>,
  Context: Contexting<IntRadixAtom<u8>>,
  //  Context: Context<IntRadixAtom<u16>>,
  Context: Contexting<CoreAtom<Stream>>,
  Context: Contexting<TcpAtom>,
  u8: Into<<Stream as Streaming>::Item>;

/// Contains TCP flags
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, PartialEq, Eq, Default)]
pub struct TcpFlags {
  raw: u16,
}

macro_rules! tcp_flags {
  ($($name:ident => $pos:expr,)*) => {
    impl TcpFlags {
      $(paste::paste! {
        /// Return true if option is set
        pub const fn [<get_ $name>](&self) -> bool {
          self.raw & 1 << $pos != 0
        }

        /// Set option to bool value
        pub fn [<set_ $name>](&mut self, state: bool) -> bool {
          if state {
            self.raw |= 1 << $pos;
          }
          else {
            self.raw &= !(1 << $pos);
          }
          state
        }
      })*

      /// Return data offset
      pub const fn get_data_offset(&self) -> u8 {
        (self.raw >> 12) as u8
      }

      /// Set data offset value, error if 4 < N < 16 is not true
      pub fn set_data_offset(&mut self, n: usize) -> Result<usize, usize> {
        if n > 4 && n < 16 {
          self.raw &= u16::MAX >> 4; // reset to 0
          self.raw |= (n as u16) << 12; // set to n
          Ok(n)
        }
        else {
          Err(n)
        }
      }
    }

    paste::paste! {
      impl Debug for TcpFlags {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
          f.debug_struct("TcpFlags")
            .field("data_offset", &self.get_data_offset())
            $(.field(stringify!($name), &self.[<get_ $name>]()))*
            .finish()
        }
      }
    }
  };
}

tcp_flags! {
  reserved_0 => 11u16,
  reserved_1 => 10u16,
  reserved_2 => 9u16,
  ns => 8u16,
  cwr => 7u16,
  ece => 6u16,
  urg => 5u16,
  ack => 4u16,
  psh => 3u16,
  rst => 2u16,
  syn => 1u16,
  fin => 0u16,
}

impl From<u16> for TcpFlags {
  fn from(raw: u16) -> Self {
    Self { raw }
  }
}

/// TcpHeader
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpHeader<Span> {
  /// Identifies the sending port.
  pub source_port: u16,
  /// Identifies the receiving port.
  pub dest_port: u16,
  /// Has a dual role:
  /// * If the SYN flag is set (1), then this is the initial sequence number.
  ///   The sequence number of the actual first data byte and the acknowledged
  ///   number in the corresponding ACK are then this sequence number plus 1.
  /// * If the SYN flag is clear (0), then this is the accumulated sequence
  ///   number of the first data byte of this segment for the current session.
  pub sequence_no: u32,
  /// If the ACK flag is set then the value of this field is the next sequence
  /// number that the sender of the ACK is expecting. This acknowledges receipt
  /// of all prior bytes (if any). The first ACK sent by each end acknowledges
  /// the other end's initial sequence number itself, but no data.
  pub ack_no: u32,
  /// Contains 8 1-bit flags (control bits)
  pub flags: TcpFlags,
  /// The size of the receive window, which specifies the number of window size
  /// units that the sender of this segment is currently willing to
  /// receive. (See § Flow control and § Window scaling.)
  pub window: u16,
  /// The 16-bit checksum field is used for error-checking of the TCP header,
  /// the payload and an IP pseudo-header. The pseudo-header consists of the
  /// source IP address, the destination IP address, the protocol number for the
  /// TCP protocol (6) and the length of the TCP headers and payload (in bytes).
  pub checksum: u16,
  /// If the URG flag is set, then this 16-bit field is an offset from the
  /// sequence number indicating the last urgent data byte.
  pub urgent_pointer: u16,
  /// Options use tcp_options with the Span to parse Options to a Vec
  // TODO could be custom type that impl iterator
  pub options: Span,
}

impl<Span> TcpHeader<Span> {}

/// Atom produced by TCP
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpAtom {
  /// When Data off Set is less than 5
  DataOffSet,
  /// When Maximum len option size not 4
  MssLen,
  /// When Maximum len option size not 3
  WindowScaleLen,
  /// When Maximum len option size not 3
  SackPermittedLen,
  /// When SackLen size length is invalid
  SackLen(u8),
  /// When Maximum len option size not 10
  TimestampsLen,
}

impl Display for TcpAtom {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      TcpAtom::DataOffSet => write!(f, "DataOffSet: data_offset is less than 5"),

      TcpAtom::MssLen => {
        write!(f, "MssLen: Maximun len size is not 4")
      }
      TcpAtom::WindowScaleLen => {
        write!(f, "WindowScaleLen: Maximun len size is not 3")
      }
      TcpAtom::SackPermittedLen => {
        write!(f, "SackPermittedLen: Maximun len size is not 3")
      }
      TcpAtom::SackLen(len) => {
        write!(f, "SackLen: sack length is invalid found {}", len)
      }
      TcpAtom::TimestampsLen => {
        write!(f, "TimestampsLen: Maximun len size is not 10")
      }
    }
  }
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn tcp_flags<Stream, Context>(stream: Stream) -> Parsed<TcpFlags, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  u16_be
    .map(TcpFlags::from)
    .try_map(|flags| {
      if flags.get_data_offset() >= 5 {
        Ok(flags)
      } else {
        Err(Contexting::new(TcpAtom::DataOffSet))
      }
    })
    .parse(stream)
}

/// Parse tcp header
#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
pub fn tcp_header<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpHeader<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  let Success {
    token: (source_port, dest_port, sequence_no, ack_no, flags, window, checksum, urgent_pointer),
    stream,
  } = (
    u16_be, u16_be, u32_be, u32_be, tcp_flags, u16_be, u16_be, u16_be,
  )
    .parse(stream)?;

  let Success {
    token: options,
    stream,
  } = any
    .drop()
    .fold_bounds(
      (usize::from(flags.get_data_offset()) - 5) * 4,
      || (),
      Acc::acc,
    )
    .span()
    .map(Success::into_stream)
    .parse(stream)?;

  Parsed::Success {
    stream,
    token: TcpHeader {
      source_port,
      dest_port,
      sequence_no,
      ack_no,
      flags,
      window,
      checksum,
      urgent_pointer,
      options,
    },
  }
}

/// Sack
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sack {
  /// Sack with 2 u32
  A([u32; 2]),
  /// Sack with 4 u32
  B([u32; 4]),
  /// Sack with 6 u32
  C([u32; 6]),
  /// Sack with 8 u32
  D([u32; 8]),
}

/// Tcp Option
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpOption<Span> {
  /// End of Option
  EndOfOption,
  /// No Operation
  Noop,
  /// The largest amount of data, specified in bytes, that TCP is willing to
  /// receive in a single segment
  MaximumSegmentSize(u16),
  /// The window scale value represents the number of bits to left-shift the
  /// 16-bit window size field when interpreting it
  WindowScale(u8),
  /// Selective acknowledgments is permited or not.
  SackPermitted,
  /// Sack data
  Sack(Sack),
  /// Timestamps of paquet
  Timestamps((u32, u32)),
  /// Unknown option
  Unknown((u8, Span)),
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn noop<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  Parsed::Success {
    token: TcpOption::Noop,
    stream,
  }
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn mss<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  is(4)
    .add_atom(|| TcpAtom::MssLen)
    .drop_and(u16_be)
    .map(TcpOption::MaximumSegmentSize)
    .parse(stream)
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn window_scale<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  is(3)
    .add_atom(|| TcpAtom::WindowScaleLen)
    .drop_and(octet)
    .map(TcpOption::WindowScale)
    .parse(stream)
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn sack_permitted<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  is(2)
    .add_atom(|| TcpAtom::SackPermittedLen)
    .map(|_| TcpOption::SackPermitted)
    .parse(stream)
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn sack<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  octet
    .and_then(|len| {
      move |stream: Stream| match len {
        10 => u32_be.fill().map(Sack::A).parse(stream),
        18 => u32_be.fill().map(Sack::B).parse(stream),
        26 => u32_be.fill().map(Sack::C).parse(stream),
        34 => u32_be.fill().map(Sack::D).parse(stream),
        len => Parsed::Failure(Context::new(TcpAtom::SackLen(len))),
      }
    })
    .map(TcpOption::Sack)
    .parse(stream)
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn tipestamps<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  is(10)
    .add_atom(|| TcpAtom::TimestampsLen)
    .drop_and((u32_be, u32_be))
    .map(TcpOption::Timestamps)
    .parse(stream)
}

struct Unknown {
  op: u8,
}

fn unknown<Stream, Context>(
  op: u8,
) -> impl Parse<Stream, Context, Token = TcpOption<<Stream as Streaming>::Span>>
where
  (): TcpParse<Stream, Context>,
{
  Unknown { op }
}

impl<Stream, Context> Parse<Stream, Context> for Unknown
where
  (): TcpParse<Stream, Context>,
{
  type Token = TcpOption<<Stream as Streaming>::Span>;

  #[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "trace", name = "unknown", skip_all, ret(Display))
  )]
  fn parse(
    &mut self, stream: Stream,
  ) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context> {
    octet
      .and_then(|len| {
        any
          .drop()
          .fold_bounds(usize::from(len), || (), Acc::acc)
          .span()
      })
      .map(|span| TcpOption::Unknown((self.op, span.stream)))
      .parse(stream)
  }
}

#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
fn tcp_option<Stream, Context>(
  stream: Stream,
) -> Parsed<TcpOption<<Stream as Streaming>::Span>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  octet
    .and_then(|op| {
      move |stream| match op {
        0 => Parsed::Success {
          token: TcpOption::EndOfOption,
          stream,
        },
        1 => noop.parse(stream),
        2 => mss.parse(stream),
        3 => window_scale.parse(stream),
        4 => sack_permitted.parse(stream),
        5 => sack.parse(stream),
        8 => tipestamps.parse(stream),
        op => unknown(op).parse(stream),
      }
    })
    .parse(stream)
}

/// Parse tcp option this can be used on the Stream Span.
#[cfg_attr(
  feature = "tracing",
  tracing::instrument(level = "trace", skip_all, ret(Display))
)]
pub fn tcp_options<Stream, Context>(
  stream: Stream,
) -> Parsed<Vec<TcpOption<<Stream as Streaming>::Span>>, Stream, Context>
where
  (): TcpParse<Stream, Context>,
{
  tcp_option.fold_bounds(.., Vec::new, Acc::acc).parse(stream)
}

#[cfg(test)]
mod tests {
  use core::fmt::Debug;

  use binator::{
    base::{
      BaseAtom,
      IntRadixAtom,
    },
    context::Tree,
    utils::UtilsAtom,
    CoreAtom,
    Parse,
    Parsed,
    Streaming,
  };
  use derive_more::{
    Display,
    From,
  };
  use pretty_assertions::assert_eq;
  use test_log::test;

  use crate::{
    tcp_header,
    TcpAtom,
    TcpFlags,
    TcpHeader,
  };

  //  use super::*;

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
  }

  type HandleAtom<Stream> = Tree<FromAtom<Stream>>;

  #[test]
  fn test_tcp_parse() {
    let stream = [
      0xC2, 0x1F, 0x00, 0x50, 0x0F, 0xD8, 0x7F, 0x4C, 0xEB, 0x2F, 0x05, 0xC8, 0x50, 0x18, 0x01,
      0x00, 0x7C, 0x29, 0x00, 0x00,
    ];

    let mut flags = TcpFlags::default();
    flags.set_ack(true);
    flags.set_psh(true);
    flags.set_data_offset(5).unwrap();
    let expect = TcpHeader {
      source_port: 49695,
      dest_port: 80,
      sequence_no: 0x0FD87F4C,
      ack_no: 0xEB2F05C8,
      flags,
      window: 256,
      checksum: 0x7C29,
      urgent_pointer: 0,
      options: "".as_bytes(),
    };

    let result: Parsed<_, _, HandleAtom<_>> = tcp_header.parse(stream.as_slice());
    let expected = Parsed::Success {
      token: expect,
      stream: "".as_bytes(),
    };

    assert_eq!(result, expected);
  }
}
