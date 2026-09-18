use super::IpsetConfig;
use super::*;

impl NomParser for IpsetConfig {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        // ipset 的集合名就是普通名字（内核上限 31 字节）。
        // 这里只做"字符集"的基本约束；长度在真正写集合时校验并把原因报到日志里
        // （C 版是在写的时候静默失败，用户看不到自己名字写长了）。
        let mut name = take_while1(|c: char| {
            c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
        });

        let (input, name) = name.parse(input)?;
        Ok((
            input,
            IpsetConfig {
                name: name.to_string(),
            },
        ))
    }
}

impl NomParser for ConfigForIP<IpsetConfig> {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        // C 版文档里的写法：`#4:dns4` / `#6:dns6`，写 `-` 表示"这一族不写集合"
        // （例如 `#4:dns4,#6:-` = 只把 IPv4 结果写进 dns4）
        let v4 = preceded(
            tag("#4:"),
            alt((map(char('-'), |_| ConfigForIP::None), map(IpsetConfig::parse, ConfigForIP::V4))),
        );
        let v6 = preceded(
            tag("#6:"),
            alt((map(char('-'), |_| ConfigForIP::None), map(IpsetConfig::parse, ConfigForIP::V6))),
        );

        alt((map(char('-'), |_| ConfigForIP::None), v4, v6)).parse(input)
    }
}

impl NomParser for Vec<ConfigForIP<IpsetConfig>> {
    fn parse(input: &str) -> IResult<&str, Self> {
        separated_list1(
            (space0, char(','), space0),
            ConfigForIP::<IpsetConfig>::parse,
        )
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipset_name() {
        assert_eq!(
            IpsetConfig::parse("dns4").unwrap(),
            (
                "",
                IpsetConfig {
                    name: "dns4".to_string()
                }
            )
        );

        // 带下划线/点/横杠的名字也认（C 版的集合名允许这些）
        assert_eq!(
            IpsetConfig::parse("dns_4.v6-test").unwrap(),
            (
                "",
                IpsetConfig {
                    name: "dns_4.v6-test".to_string()
                }
            )
        );
    }

    #[test]
    fn test_config_for_ip() {
        // C 版文档里的写法：ipset /www.example.com/#4:dns4,#6:-
        assert_eq!(
            ConfigForIP::<IpsetConfig>::parse("#4:dns4").unwrap(),
            (
                "",
                ConfigForIP::V4(IpsetConfig {
                    name: "dns4".to_string()
                })
            )
        );

        assert_eq!(
            ConfigForIP::<IpsetConfig>::parse("#6:dns6").unwrap(),
            (
                "",
                ConfigForIP::V6(IpsetConfig {
                    name: "dns6".to_string()
                })
            )
        );

        assert_eq!(
            ConfigForIP::<IpsetConfig>::parse("-").unwrap(),
            ("", ConfigForIP::None)
        );
    }

    #[test]
    fn test_ipset_list() {
        assert_eq!(
            Vec::<ConfigForIP<IpsetConfig>>::parse("#4:dns4,#6:-").unwrap(),
            (
                "",
                vec![
                    ConfigForIP::V4(IpsetConfig {
                        name: "dns4".to_string()
                    }),
                    ConfigForIP::None
                ]
            )
        );
    }
}
