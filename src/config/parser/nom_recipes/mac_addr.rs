use nom::{
    IResult, Parser,
    branch::alt,                     // 🌟 新增 alt 用于匹配多种分隔符
    bytes::complete::take_while_m_n,
    character::complete::char,
    combinator::{recognize, verify},
    error::context,
    multi::separated_list1,
};

pub fn mac_addr(input: &str) -> IResult<&str, &str> {
    // 🌟 核心修复 1：直接精准截取 2 位十六进制，去掉无用的 verify
    let hextal = take_while_m_n(2, 2, |c: char| c.is_ascii_hexdigit());

    // 🌟 核心修复 2：同时兼容冒号 (:) 和横杠 (-) 两种 MAC 地址格式
    let parts = separated_list1(alt((char(':'), char('-'))), hextal);
    
    // 必须有 6 段
    let parts = verify(parts, |s: &Vec<&str>| s.len() == 6);
    let parts = recognize(parts);
    
    context("MacAddr", parts).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr() {
        assert_eq!(mac_addr("01:23:45:67:89:ab"), Ok(("", "01:23:45:67:89:ab")));
        assert_eq!(
            mac_addr("01-23-45-67-89-ab "), // 🌟 现在测试可以通过了！
            Ok((" ", "01-23-45-67-89-ab"))
        );

        assert!(mac_addr("01:23:45:67:89").is_err());
    }
}
