use std::net::Ipv4Addr;

use nom::{
    IResult, Parser,
    bytes::complete::take_while_m_n, // 🌟 引入正确的高性能截取器
    character::complete::char,
    combinator::{map, map_res},      // 删除了无用的 recognize
    error::context,
    sequence::preceded,
};

pub fn ipv4(input: &str) -> IResult<&str, Ipv4Addr> {
    fn octal(input: &str) -> IResult<&str, u8> {
        // 🌟 核心修复：精准且零开销地截取 1~3 位数字，无需任何多余的嵌套组合子
        map_res(take_while_m_n(1, 3, |c: char| c.is_ascii_digit()), |s: &str| s.parse()).parse(input)
    }

    context(
        "Ipv4Addr",
        map(
            (
                octal,
                preceded(char('.'), octal),
                preceded(char('.'), octal),
                preceded(char('.'), octal),
            ),
            |(a, b, c, d)| Ipv4Addr::new(a, b, c, d),
        ),
    )
    .parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        assert_eq!(ipv4("127.0.0.1"), Ok(("", Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(
            ipv4("255.255.255.255"),
            Ok(("", Ipv4Addr::new(255, 255, 255, 255)))
        );
        assert_eq!(ipv4("0.0.0.0"), Ok(("", Ipv4Addr::new(0, 0, 0, 0))));
        assert_eq!(ipv4("1.2.3.4"), Ok(("", Ipv4Addr::new(1, 2, 3, 4))));
        assert!(ipv4("256.0.0.0").is_err());
        assert!(ipv4("0.0 .0.256").is_err());
        assert!(ipv4("0.0.0").is_err());
    }
}
