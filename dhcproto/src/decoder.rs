//! Decodable trait & Decoder
use hickory_proto::{
    rr::Name,
    serialize::binary::{BinDecodable, BinDecoder},
};

use crate::error::{DecodeError, DecodeResult};

use std::{
    array::TryFromSliceError,
    convert::TryInto,
    ffi::{CStr, CString},
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

/// A trait for types which are serializable to and from DHCP binary formats
pub trait Decodable: Sized {
    /// Read the type from the stream
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self>;

    /// Returns the object in binary form
    fn from_bytes(bytes: &[u8]) -> DecodeResult<Self> {
        let mut decoder = Decoder::new(bytes);
        Self::decode(&mut decoder)
    }
}

/// Decoder type. Wraps a buffer which only contains bytes that have not been read yet
#[derive(Debug)]
pub struct Decoder<'a> {
    buffer: &'a [u8],
}

impl<'a> Decoder<'a> {
    /// Create a new Decoder
    pub fn new(buffer: &'a [u8]) -> Self {
        Decoder { buffer }
    }

    /// peek at the next byte without advancing the internal pointer
    pub fn peek_u8(&self) -> DecodeResult<u8> {
        Ok(u8::from_be_bytes(self.peek::<{ mem::size_of::<u8>() }>()?))
    }

    /// read a u8
    pub fn read_u8(&mut self) -> DecodeResult<u8> {
        Ok(u8::from_be_bytes(self.read::<{ mem::size_of::<u8>() }>()?))
    }

    /// read a u32
    pub fn read_u32(&mut self) -> DecodeResult<u32> {
        Ok(u32::from_be_bytes(
            self.read::<{ mem::size_of::<u32>() }>()?,
        ))
    }

    /// read a i32
    pub fn read_i32(&mut self) -> DecodeResult<i32> {
        Ok(i32::from_be_bytes(
            self.read::<{ mem::size_of::<i32>() }>()?,
        ))
    }

    /// read a u16
    pub fn read_u16(&mut self) -> DecodeResult<u16> {
        Ok(u16::from_be_bytes(
            self.read::<{ mem::size_of::<u16>() }>()?,
        ))
    }

    /// read a u64
    pub fn read_u64(&mut self) -> DecodeResult<u64> {
        Ok(u64::from_be_bytes(
            self.read::<{ mem::size_of::<u64>() }>()?,
        ))
    }

    /// read a `N` bytes into slice
    pub fn read<const N: usize>(&mut self) -> DecodeResult<[u8; N]> {
        if N > self.buffer.len() {
            return Err(DecodeError::NotEnoughBytes);
        }
        let (slice, remaining) = self.buffer.split_at(N);
        self.buffer = remaining;
        // can't panic-- condition checked above
        Ok(slice.try_into().unwrap())
    }

    /// peek a `N` bytes into slice
    pub fn peek<const N: usize>(&self) -> DecodeResult<[u8; N]> {
        if N > self.buffer.len() {
            return Err(DecodeError::NotEnoughBytes);
        }
        // can't panic-- condition checked above
        Ok(self.buffer[..N].try_into().unwrap())
    }

    /// read a `MAX` length bytes into nul terminated `CString`
    pub fn read_cstring<const MAX: usize>(&mut self) -> DecodeResult<Option<CString>> {
        let bytes = self.read::<MAX>()?;
        let nul_idx = bytes.iter().position(|&b| b == 0);
        match nul_idx {
            Some(0) => Ok(None),
            Some(n) => Ok(Some(CStr::from_bytes_with_nul(&bytes[..=n])?.to_owned())),
            // TODO: error?
            None => Ok(None),
        }
    }

    pub fn read_nul_bytes<const MAX: usize>(&mut self) -> DecodeResult<Option<Vec<u8>>> {
        let bytes = self.read::<MAX>()?;
        let nul_idx = bytes.iter().position(|&b| b == 0);
        match nul_idx {
            Some(0) => Ok(None),
            Some(n) => Ok(Some(bytes[..=n].to_vec())),
            // TODO: error?
            None => Ok(None),
        }
    }

    /// read `MAX` length bytes and read into utf-8 encoded `String`
    pub fn read_nul_string<const MAX: usize>(&mut self) -> DecodeResult<Option<String>> {
        Ok(self
            .read_nul_bytes::<MAX>()?
            .map(|ref bytes| str::from_utf8(bytes).map(|s| s.to_owned()))
            .transpose()?)
    }

    /// read a slice of bytes determined at runtime
    pub fn read_slice(&mut self, len: usize) -> DecodeResult<&'a [u8]> {
        if len > self.buffer.len() {
            return Err(DecodeError::NotEnoughBytes);
        }
        let (slice, remaining) = self.buffer.split_at(len);
        self.buffer = remaining;
        Ok(slice)
    }

    /// Read a utf-8 encoded String
    pub fn read_string(&mut self, len: usize) -> DecodeResult<String> {
        Ok(self.read_str(len)?.to_owned())
    }

    /// Read a utf-8 encoded String
    pub fn read_str(&mut self, len: usize) -> DecodeResult<&str> {
        Ok(str::from_utf8(self.read_slice(len)?)?)
    }

    /// Read an ipv4 addr
    pub fn read_ipv4(&mut self, length: usize) -> DecodeResult<Ipv4Addr> {
        if length != 4 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let bytes = self.read::<4>()?;
        Ok(bytes.into())
    }

    /// Read a list of ipv4 addrs
    pub fn read_ipv4s(&mut self, length: usize) -> DecodeResult<Vec<Ipv4Addr>> {
        // must be multiple of 4
        if length % 4 != 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let ips = self.read_slice(length)?;
        Ok(ips
            .chunks(4)
            .map(|bytes| [bytes[0], bytes[1], bytes[2], bytes[3]].into())
            .collect())
    }

    /// Read a list of ipv6 addrs
    pub fn read_ipv6s(&mut self, length: usize) -> DecodeResult<Vec<Ipv6Addr>> {
        // must be multiple of 16
        if length % 16 != 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let ips = self.read_slice(length)?;
        // type annotations needed below
        Ok(ips
            .chunks(16)
            .map(|bytes| Ok::<_, TryFromSliceError>(TryInto::<[u8; 16]>::try_into(bytes)?.into()))
            .collect::<Result<Vec<Ipv6Addr>, _>>()?)
    }

    /// Read a list of ipv4 pairs
    pub fn read_pair_ipv4s(&mut self, length: usize) -> DecodeResult<Vec<(Ipv4Addr, Ipv4Addr)>> {
        // must be multiple of 8
        if length % 8 != 0 {
            return Err(DecodeError::NotEnoughBytes);
        }
        let ips = self.read_slice(length)?;
        Ok(ips
            .chunks(8)
            .map(|bytes| {
                (
                    [bytes[0], bytes[1], bytes[2], bytes[3]].into(),
                    [bytes[4], bytes[5], bytes[6], bytes[7]].into(),
                )
            })
            .collect())
    }

    /// Read a list of domain `Name`s
    pub fn read_domains(&mut self, length: usize) -> DecodeResult<Vec<Name>> {
        let mut name_decoder = BinDecoder::new(self.read_slice(length)?);
        let mut names = Vec::new();
        // 🔐 编号 72：原来是 `while let Ok(name) = Name::read(...)` —— 把**任何错误**都当成
        // "读完了"，包括真正的解码错误。畸形报文里前几个域名合法、后面损坏时，
        // 损坏点之后的域名被**静默丢弃**，调用方拿到"看起来正常但少了几项"的列表。
        // 改为区分"正常结束（无剩余字节）"与"解码失败"。
        loop {
            // 没有剩余字节：正常结束
            if name_decoder.is_empty() {
                break;
            }
            match Name::read(&mut name_decoder) {
                Ok(name) => names.push(name),
                Err(e) => {
                    // 有剩余字节却读不出域名 ⇒ 真正的解码失败，如实上报
                    return Err(e.into());
                }
            }
        }
        Ok(names)
    }

    /// Read a bool
    pub fn read_bool(&mut self) -> DecodeResult<bool> {
        Ok(self.read_u8()? == 1)
    }

    /// return slice of buffer start at index of unread data
    pub fn buffer(&self) -> &[u8] {
        self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_domains_reports_a_decode_error_instead_of_silently_stopping() {
        // 一个合法的域名（example.com）后面跟一个非法长度字节
        let mut buf = Vec::new();
        // 合法域名：7example3com0
        buf.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        buf.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        // 非法：0x40 的高两位是 01，既不是标签长度也不是压缩指针
        buf.push(0x40);

        let mut dec = Decoder::new(&buf);
        let result = dec.read_domains(buf.len());
        assert!(
            result.is_err(),
            "损坏的域名必须报错，不能静默丢弃（实际 {result:?}）"
        );
    }
}
