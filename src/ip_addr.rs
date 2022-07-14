use core::fmt::{
  self,
  Display,
  Formatter,
};
use std::net::{
  Ipv4Addr,
  Ipv6Addr,
};

use binator_base::*;
use binator_core::*;
use binator_number::*;
use binator_utils::*;

/// Atom of ip_addr parser
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddrAtom {
  /// When value in IPv4 would overflow an octet (u8)
  NotAnOctet,
  /// When value in IPv4 have leading zero
  LeadingZero,
}

impl Display for IpAddrAtom {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::NotAnOctet => write!(f, "IpAddr: NotAnOctet"),
      Self::LeadingZero => write!(f, "IpAddr: LeadingZero"),
    }
  }
}

/// Meta trait for ip_addr combinator
pub trait IpAddrParse<Stream, Context> = where
  Stream: Streaming,
  <Stream as Streaming>::Item: Into<u8> + Clone,
  <Stream as Streaming>::Item: PartialEq<<Stream as Streaming>::Item>,
  Context: Contexting<BaseAtom<u8>>,
  Context: Contexting<UtilsAtom<Stream>>,
  Context: Contexting<IntRadixAtom<u8>>,
  Context: Contexting<IntRadixAtom<u16>>,
  Context: Contexting<CoreAtom<Stream>>,
  Context: Contexting<IpAddrAtom>,
  Context: Contexting<UtilsAtom<Stream>>;

/// IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
pub fn ipv4_address<Stream, Context>(stream: Stream) -> Parsed<Ipv4Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    dec_octet,
    is(b'.'),
    dec_octet,
    is(b'.'),
    dec_octet,
    is(b'.'),
    dec_octet,
  )
    .map(|(a, _, b, _, c, _, d)| Ipv4Addr::new(a, b, c, d))
    .parse(stream)
}

// dec-octet = DIGIT             ; 0-9
//           / %x31-39 DIGIT     ; 10-99
//           / "1" 2DIGIT        ; 100-199
//           / "2" %x30-34 DIGIT ; 200-249
//           / "25" %x30-35      ; 250-255
fn dec_octet<Stream, Context>(stream: Stream) -> Parsed<u8, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  [
    dec_octet_0,
    dec_octet_1,
    dec_octet_2,
    dec_octet_3,
    dec_octet_4,
  ]
  .parse(stream)
}

fn dec_octet_0<Stream, Context>(stream: Stream) -> Parsed<u8, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (is(b'2'), is(b'5'), to_digit)
    .try_map(|(_, _, c)| {
      250u8
        .checked_add(u8::from(c))
        .ok_or_else(|| Context::new(IpAddrAtom::NotAnOctet))
    })
    .parse(stream)
}

fn dec_octet_1<Stream, Context>(stream: Stream) -> Parsed<u8, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (is(b'2'), to_digit, to_digit)
    .try_map(|(_, b, c)| {
      200u8
        .checked_add(u8::from(b) * 10 + u8::from(c))
        .ok_or_else(|| Context::new(IpAddrAtom::NotAnOctet))
    })
    .parse(stream)
}

fn dec_octet_2<Stream, Context>(stream: Stream) -> Parsed<u8, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (is(b'1'), to_digit, to_digit)
    .try_map(|(_, b, c)| {
      100u8
        .checked_add(u8::from(b) * 10 + u8::from(c))
        .ok_or_else(|| Context::new(IpAddrAtom::NotAnOctet))
    })
    .parse(stream)
}

fn dec_octet_3<Stream, Context>(stream: Stream) -> Parsed<u8, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (to_digit, to_digit)
    .try_map(|(a, b)| {
      let a = u8::from(a);
      let b = u8::from(b);
      if a == 0 {
        Err(Context::new(IpAddrAtom::LeadingZero))
      } else {
        Ok(a * 10 + b)
      }
    })
    .parse(stream)
}

fn dec_octet_4<Stream, Context>(stream: Stream) -> Parsed<u8, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  to_digit.map(u8::from).parse(stream)
}

/// Ipv6Reference
#[derive(Clone, Copy, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub struct Ipv6Reference {
  /// ipv6
  pub ipv6: Ipv6Addr,
}

impl Display for Ipv6Reference {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "[{}]", self.ipv6)
  }
}

/// IPv6reference = "[" IPv6address "]"
pub fn ipv6_reference<Stream, Context>(stream: Stream) -> Parsed<Ipv6Reference, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (is(b'['), ipv6_address, is(b']'))
    .map(|(_, ipv6, _)| Ipv6Reference { ipv6 })
    .parse(stream)
}

#[allow(rustdoc::private_intra_doc_links)]
/// IPv6address =                            6( h16 ":" ) ls32
///             /                       "::" 5( h16 ":" ) ls32
///             / [               h16 ] "::" 4( h16 ":" ) ls32
///             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
///             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
///             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
///             / [ *4( h16 ":" ) h16 ] "::"              ls32
///             / [ *5( h16 ":" ) h16 ] "::"    h16
///             / [ *6( h16 ":" ) h16 ] "::"
pub fn ipv6_address<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  [
    ipv6_address_0,
    ipv6_address_1,
    ipv6_address_2,
    ipv6_address_3,
    ipv6_address_4,
    ipv6_address_5,
    ipv6_address_6,
    ipv6_address_7,
    ipv6_address_8,
  ]
  .parse(stream)
}

fn ipv6_address_0<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16_colon, h16_colon, h16_colon, h16_colon, h16_colon, h16_colon, ls32,
  )
    .map(|(a, b, c, d, e, f, (g, h))| Ipv6Addr::new(a, b, c, d, e, f, g, h))
    .parse(stream)
}

fn ipv6_address_1<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    double_colon,
    h16_colon,
    h16_colon,
    h16_colon,
    h16_colon,
    h16_colon,
    ls32,
  )
    .map(|(_, b, c, d, e, f, (g, h))| Ipv6Addr::new(0, b, c, d, e, f, g, h))
    .parse(stream)
}

fn ipv6_address_2<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16.opt(),
    double_colon,
    h16_colon,
    h16_colon,
    h16_colon,
    h16_colon,
    ls32,
  )
    .map(|(a, _, c, d, e, f, (g, h))| Ipv6Addr::new(a.unwrap_or(0), 0, c, d, e, f, g, h))
    .parse(stream)
}

fn ipv6_address_3<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16.opt(),
    colon_h16.opt(),
    double_colon,
    h16_colon,
    h16_colon,
    h16_colon,
    ls32,
  )
    .map(|(a, b, _, d, e, f, (g, h))| {
      Ipv6Addr::new(a.unwrap_or(0), b.unwrap_or(0), 0, d, e, f, g, h)
    })
    .parse(stream)
}

fn ipv6_address_4<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    double_colon,
    h16_colon,
    h16_colon,
    ls32,
  )
    .map(|(a, b, c, _, e, f, (g, h))| {
      Ipv6Addr::new(
        a.unwrap_or(0),
        b.unwrap_or(0),
        c.unwrap_or(0),
        0,
        e,
        f,
        g,
        h,
      )
    })
    .parse(stream)
}

fn ipv6_address_5<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    double_colon,
    h16_colon,
    ls32,
  )
    .map(|(a, b, c, d, _, f, (g, h))| {
      Ipv6Addr::new(
        a.unwrap_or(0),
        b.unwrap_or(0),
        c.unwrap_or(0),
        d.unwrap_or(0),
        0,
        f,
        g,
        h,
      )
    })
    .parse(stream)
}

fn ipv6_address_6<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    double_colon,
    ls32,
  )
    .map(|(a, b, c, d, e, _, (g, h))| {
      Ipv6Addr::new(
        a.unwrap_or(0),
        b.unwrap_or(0),
        c.unwrap_or(0),
        d.unwrap_or(0),
        e.unwrap_or(0),
        0,
        g,
        h,
      )
    })
    .parse(stream)
}

fn ipv6_address_7<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    double_colon,
    h16,
  )
    .map(|(a, b, c, d, e, f, _, h)| {
      Ipv6Addr::new(
        a.unwrap_or(0),
        b.unwrap_or(0),
        c.unwrap_or(0),
        d.unwrap_or(0),
        e.unwrap_or(0),
        f.unwrap_or(0),
        0,
        h,
      )
    })
    .parse(stream)
}

fn ipv6_address_8<Stream, Context>(stream: Stream) -> Parsed<Ipv6Addr, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  (
    h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    colon_h16.opt(),
    double_colon,
  )
    .map(|(a, b, c, d, e, f, g, _)| {
      Ipv6Addr::new(
        a.unwrap_or(0),
        b.unwrap_or(0),
        c.unwrap_or(0),
        d.unwrap_or(0),
        e.unwrap_or(0),
        f.unwrap_or(0),
        g.unwrap_or(0),
        0,
      )
    })
    .parse(stream)
}

// custom rule
// h16colon = h16 ":"
fn h16_colon<Stream, Context>(stream: Stream) -> Parsed<u16, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  h16.and_drop(is(b':')).parse(stream)
}

fn colon_h16<Stream, Context>(stream: Stream) -> Parsed<u16, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  is(b':').drop_and(h16).parse(stream)
}

fn double_colon<Stream, Context>(stream: Stream) -> Parsed<(), Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  is(b':').and(is(b':')).drop().parse(stream)
}

// // ls32 = ( h16 ":" h16 ) / IPv4address
fn ls32<Stream, Context>(stream: Stream) -> Parsed<(u16, u16), Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  h16
    .and(colon_h16)
    .or(ipv4_address.map(|ipv4| {
      let [a, b, c, d] = ipv4.octets();
      ((a as u16) << 8 | (b as u16), (c as u16) << 8 | (d as u16))
    }))
    .parse(stream)
}

// h16 = 1*4HEXDIG
fn h16<Stream, Context>(stream: Stream) -> Parsed<u16, Stream, Context>
where
  (): IpAddrParse<Stream, Context>,
{
  uint_radix(1..4, Radix::HEX).parse(stream)
}

#[cfg(test)]
mod tests {
  use core::{
    fmt::Debug,
    str::FromStr,
  };

  use binator_base::*;
  use binator_context::Tree;
  use binator_core::*;
  use derive_more::{
    Display,
    From,
  };

  use super::*;

  #[derive(Display, Debug, Clone, PartialEq, From)]
  enum FromAtom<Stream: Streaming + Debug, Error = <Stream as Streaming>::Error> {
    Any(CoreAtom<Stream, Error>),
    Is(BaseAtom<u8>),
    Utils(UtilsAtom<Stream>),
    U8Radix(IntRadixAtom<u8>),
    U16Radix(IntRadixAtom<u16>),
    IpAddr(IpAddrAtom),
  }

  type HandleAtom<Stream> = Tree<FromAtom<Stream>>;

  #[test]
  fn test_ipv4_address() {
    // 012.15.65.12 0x12.222.012.111

    let ipv4s = ["", "m", "127.0.0.1", "256.256.256.256", "255.255.255.255"];

    for ipv4 in ipv4s.iter() {
      println!("test: {}", ipv4);
      match (
        ipv4_address::<_, HandleAtom<_>>(ipv4.as_bytes()),
        Ipv4Addr::from_str(ipv4),
      ) {
        (Parsed::Success { token, stream }, Ok(expected)) => {
          assert_eq!((token, stream), (expected, b"".as_slice()))
        }
        (Parsed::Failure(_) | Parsed::Error(_), Err(_)) => {} // no need compare error
        (Parsed::Success { token, stream }, Err(e)) => {
          panic!("We ok on {:?} {:?} but std error on {}", token, stream, e)
        }
        (Parsed::Failure(failure) | Parsed::Error(failure), Ok(expected)) => {
          panic!("We error on {:?} but std ok on {}", failure, expected)
        }
      }
    }
  }

  #[test]
  fn test_h16() {
    let h16s = [
      "2001", "DB8", "0", "8", "800", "200C", "417A", "FF01", "101", "1", "13", "68", "3", "FFFF",
      "129", "144", "52", "38", "0DB8", "CD30", "123", "4567", "89AB", "CDEF",
    ];

    for h in &h16s {
      println!("test: {}", h);
      match (
        h16::<_, HandleAtom<_>>(h.as_bytes()),
        u16::from_str_radix(h, 16),
      ) {
        (Parsed::Success { token, stream }, Ok(expected)) => {
          assert_eq!((token, stream), (expected, b"".as_slice()))
        }
        (Parsed::Failure(_) | Parsed::Error(_), Err(_)) => {} // no need compare error
        (Parsed::Success { token, stream }, Err(e)) => {
          panic!("We ok on {:?} {:?} but std error on {}", token, stream, e)
        }
        (Parsed::Failure(failure) | Parsed::Error(failure), Ok(expected)) => {
          panic!("We error on {:?} but std ok on {}", failure, expected)
        }
      }
    }
  }

  #[test]
  fn test_ipv6_address() {
    use std::str::FromStr;

    let ipv6s = [
      "2001:DB8:0:0:8:800:200C:417A",
      "2001:DB8::8:800:200C:417A",
      "FF01:0:0:0:0:0:0:101",
      "FF01::101",
      "0:0:0:0:0:0:0:1",
      "::1",
      "0:0:0:0:0:0:0:0",
      "::",
      "0:0:0:0:0:0:13.1.68.3",
      "::13.1.68.3",
      "0:0:0:0:0:FFFF:129.144.52.38",
      "::FFFF:129.144.52.38",
      "2001:0DB8:0000:CD30:0000:0000:0000:0000",
      "2001:0DB8::CD30:0:0:0:0",
      "2001:0DB8:0:CD30::",
      "2001:0DB8:0:CD30:123:4567:89AB:CDEF",
      "2001:db8:0:0:1:0:0:1",
      "2001:0db8:0:0:1:0:0:1",
      "2001:db8::1:0:0:1",
      "2001:db8::0:1:0:0:1",
      "2001:0db8::1:0:0:1",
      "2001:db8:0:0:1::1",
      "2001:db8:0000:0:1::1",
      "2001:DB8:0:0:1::1",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:001",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:01",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
      "2001:db8:aaaa:bbbb:cccc:dddd::1",
      "2001:db8:aaaa:bbbb:cccc:dddd:0:1",
      "2001:db8:0:0:0::1",
      "2001:db8:0:0::1",
      "2001:db8:0::1",
      "2001:db8::1",
      "2001:db8::aaaa:0:0:1",
      "2001:db8:0:0:aaaa::1",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA",
      "2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa",
    ];

    for &ipv6 in ipv6s.iter() {
      println!("test: {}", ipv6);
      match (
        ipv6_address::<_, HandleAtom<_>>(ipv6.as_bytes()),
        Ipv6Addr::from_str(ipv6),
      ) {
        (Parsed::Success { token, stream }, Ok(expected)) => {
          assert_eq!((token, stream), (expected, "".as_bytes()))
        }
        (Parsed::Failure(_) | Parsed::Error(_), Err(_)) => {} // no need compare error
        (Parsed::Success { token, stream }, Err(e)) => {
          panic!("We ok on {:?} {:?} but std error on {}", token, stream, e)
        }
        (Parsed::Failure(failure) | Parsed::Error(failure), Ok(expected)) => {
          panic!("We error on {:?} but std ok on {}", failure, expected)
        }
      }
    }
  }
}
