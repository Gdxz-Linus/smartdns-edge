use num_traits::Num;

pub trait FromStrOrHex<T: Num> {
    fn from_str_or_hex(s: &str) -> Result<T, T::FromStrRadixErr>;
}

impl<T: Num> FromStrOrHex<T> for T {
    fn from_str_or_hex(s: &str) -> Result<T, T::FromStrRadixErr> {
        // 🌟 修复：同时兼容小写 0x 和大写 0X 的十六进制前缀！
        if let Some(s) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            T::from_str_radix(s, 16)
        } else {
            T::from_str_radix(s, 10)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn num_parse_from_str() {
        let x = u32::from_str_or_hex("32").unwrap();
        assert_eq!(x, 32);
    }

    #[test]
    fn num_parse_from_hex() {
        let x = u32::from_str_or_hex("0xff").unwrap();
        assert_eq!(x, 255);
    }
}
