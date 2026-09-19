use super::*;

/// 一组 IP 列表（`-ip-alias` 的值）：`1.2.3.4, ::5, 6.7.8.9`
fn ip_list(input: &str) -> IResult<&str, Arc<[IpAddr]>> {
    map(
        separated_list1((space0, char(','), space0), nom_recipes::ip),
        |list| list.into(),
    )
    .parse(input)
}

impl NomParser for IpRules {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, _) = preceded(tag_no_case("ip-rules"), space1).parse(input)?;
        let (input, key) = IpOrSet::parse(input)?;

        let mut rules = IpRules {
            key,
            blacklist: false,
            whitelist: false,
            bogus: false,
            ignore: false,
            alias: None,
        };

        let (input, options) = opt(preceded(space1, options::parse)).parse(input)?;

        for (k, v) in options.unwrap_or_default() {
            match k.to_lowercase().as_str() {
                "blacklist-ip" | "b" => rules.blacklist = true,
                "whitelist-ip" | "w" => rules.whitelist = true,
                "bogus-nxdomain" | "n" => rules.bogus = true,
                "ignore-ip" | "i" => rules.ignore = true,
                "ip-alias" | "a" => match v {
                    Some(value) => match ip_list(value) {
                        Ok((_, list)) => rules.alias = Some(list),
                        Err(err) => crate::log::error!(
                            "invalid `ip-rules ... -ip-alias` value; ignored: {value} ({err:?})"
                        ),
                    },
                    None => crate::log::warn!("`ip-rules ... -ip-alias` has no value; ignored"),
                },
                other => crate::log::warn!("unknown option on ip-rules: -{other} (ignored)"),
            }
        }

        Ok((input, rules))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_rules() {
        // 一个开关
        let (_, rules) = IpRules::parse("ip-rules 1.2.3.0/24 -whitelist-ip").unwrap();
        assert_eq!(rules.key, IpOrSet::Net("1.2.3.0/24".parse().unwrap()));
        assert!(rules.whitelist && !rules.blacklist);

        // 多个开关 + 别名
        let (_, rules) = IpRules::parse(
            "ip-rules 5.6.7.8 -blacklist-ip -bogus-nxdomain -ip-alias 9.9.9.9,8.8.8.8",
        )
        .unwrap();
        assert_eq!(rules.key, IpOrSet::Net("5.6.7.8/32".parse().unwrap()));
        assert!(rules.blacklist && rules.bogus && !rules.whitelist && !rules.ignore);
        assert_eq!(
            rules.alias,
            Some(
                ["9.9.9.9", "8.8.8.8"]
                    .map(|x| x.parse::<IpAddr>().unwrap())
                    .to_vec()
                    .into()
            )
        );

        // 命名集合也能当 key（与顶层指令一致）
        let (_, rules) = IpRules::parse("ip-rules ip-set:cn -ignore-ip").unwrap();
        assert_eq!(rules.key, IpOrSet::Set("cn".to_string()));
        assert!(rules.ignore);

        // 值不合法 → 忽略别名但不炸
        let (_, rules) = IpRules::parse("ip-rules 1.1.1.1 -ip-alias 这不是IP").unwrap();
        assert_eq!(rules.alias, None);
    }
}
