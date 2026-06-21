#![allow(dead_code)]
use either::Either;
use std::{
    ffi::CString,
    net::IpAddr,
    os::raw::{c_int, c_ulong},
};

// 🌟 极客优化：抛弃了旧代码的手工移位计算，直接利用底层寄存器进行内存零开销直拷！
fn to_c_addr(ip_addr: IpAddr) -> Either<[u8; 4], [u8; 16]> {
    match ip_addr {
        IpAddr::V4(ip) => Either::Left(ip.octets()),
        IpAddr::V6(ip) => Either::Right(ip.octets()),
    }
}

pub fn add(
    family_name: &str,
    table_name: &str,
    set_name: &str,
    addr: IpAddr,
    timeout: u64,
) -> anyhow::Result<i32> {
    let family_name = CString::new(family_name)?;
    let table_name = CString::new(table_name)?;
    let set_name = CString::new(set_name)?;

    let addr = to_c_addr(addr);
    let addr = match addr.as_ref() {
        Either::Left(v) => v.as_slice(),
        Either::Right(v) => v.as_slice(),
    };
    let addr_len = addr.len();
    let addr = addr.as_ptr();

    unsafe {
        Ok(super::nftset_sys::nftset_add(
            family_name.as_ptr(),
            table_name.as_ptr(),
            set_name.as_ptr(),
            addr,
            addr_len as c_int,
            timeout as c_ulong,
        ) as i32)
    }
}

pub fn del(
    family_name: &str,
    table_name: &str,
    set_name: &str,
    addr: IpAddr,
) -> anyhow::Result<i32> {
    let family_name = CString::new(family_name)?;
    let table_name = CString::new(table_name)?;
    let set_name = CString::new(set_name)?;

    let addr = to_c_addr(addr);
    let addr = match addr.as_ref() {
        Either::Left(v) => v.as_slice(),
        Either::Right(v) => v.as_slice(),
    };
    let addr_len = addr.len();
    let addr = addr.as_ptr();

    unsafe {
        Ok(super::nftset_sys::nftset_del(
            family_name.as_ptr(),
            table_name.as_ptr(),
            set_name.as_ptr(),
            addr,
            addr_len as c_int,
        ) as i32)
    }
}

// 🌟 暴露给上层的强力外挂：批量插入 API
pub fn add_batch(
    family_name: &str,
    table_name: &str,
    set_name: &str,
    addrs: &[IpAddr],
    timeout: u64,
) -> anyhow::Result<i32> {
    if addrs.is_empty() {
        return Ok(0);
    }

    let family_name = CString::new(family_name)?;
    let table_name = CString::new(table_name)?;
    let set_name = CString::new(set_name)?;

    let is_v4 = addrs[0].is_ipv4();
    let addr_len = if is_v4 { 4 } else { 16 };

    // 🌟 在 Rust 内存中将所有独立的 IP 连续拍平（Flatten）为一个巨型字节流
    let mut raw_addrs = Vec::with_capacity(addrs.len() * addr_len);
    for ip in addrs {
        match ip {
            IpAddr::V4(v4) => {
                if !is_v4 {
                    return Err(anyhow::anyhow!("Mixed IP families"));
                }
                raw_addrs.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                if is_v4 {
                    return Err(anyhow::anyhow!("Mixed IP families"));
                }
                raw_addrs.extend_from_slice(&v6.octets());
            }
        }
    }

    let addr_ptr = raw_addrs.as_ptr();

    // 突破次元壁：一根指针，携带成百上千个 IP，一次性杀入 Linux 内核！
    unsafe {
        Ok(super::nftset_sys::nftset_add_batch(
            family_name.as_ptr(),
            table_name.as_ptr(),
            set_name.as_ptr(),
            addr_ptr,
            addr_len as c_int,
            addrs.len() as c_int,
            timeout as c_ulong,
        ) as i32)
    }
}