use super::*;

impl NomParser for GroupMatch {
    fn parse(input: &str) -> IResult<&str, Self> {
        // 注意：每个选项捕获各自的局部变量，避免多个闭包同时可变借用同一个结构体
        // （这是本项目其它多处选项解析器的统一写法）。
        let mut group: Option<String> = None;
        let mut clients: Vec<Client> = Vec::new();
        let mut domains: Vec<String> = Vec::new();

        let one = alt((
            // -g | --group | -group <名称>
            map(
                options::parse_value(alt((tag_no_case("group"), tag("g"))), NomParser::parse),
                |v| group = Some(v),
            ),
            // -c | --client-ip <ip|cidr|mac>，可重复
            map(
                options::parse_value(alt((tag_no_case("client-ip"), tag("c"))), NomParser::parse),
                |v| clients.push(v),
            ),
            // -d | --domain <域名>，可重复
            map(
                options::parse_value(alt((tag_no_case("domain"), tag("d"))), NomParser::parse),
                |v| domains.push(v),
            ),
        ));

        // ⚠️ 这里不能写 `preceded(space1, ...)`：调用方的 `config()` 助手已经吃掉了
        // 「指令名 + 一个空格」，所以第一个选项前面没有空格。
        let (rest_input, _) = separated_list1(space1, one).parse(input)?;

        // 严格性检查：除了空白或 # 开头的注释，不应有剩余内容。
        // 否则拼错的选项名会被静默丢掉，让这一行变成"没有任何条件"的空指令——
        // 这里让它解析失败，上层就会按「未知配置」打警告（拒绝静默吞错）。
        let trailing = rest_input.trim_start();
        if !trailing.is_empty() && !trailing.starts_with('#') {
            return Err(nom::Err::Error(nom::error::Error::new(
                rest_input,
                nom::error::ErrorKind::Verify,
            )));
        }

        Ok((
            rest_input,
            GroupMatch {
                group,
                clients,
                domains,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_group_match_client_ip() {
        // 不带 -g：由调用方决定用当前所在组
        assert_eq!(
            GroupMatch::parse("-client-ip 192.168.100.0/24"),
            Ok((
                "",
                GroupMatch {
                    group: None,
                    clients: vec![Client::IpAddr("192.168.100.0/24".parse().unwrap())],
                    domains: vec![],
                }
            ))
        );
    }

    #[test]
    fn test_parse_group_match_explicit_group_and_bare_ip() {
        // 同时给 -g 与裸 IP（C 版文档的例子就是裸 IP，应自动补成 /32）
        assert_eq!(
            GroupMatch::parse("-g group-b -client-ip 10.0.0.1"),
            Ok((
                "",
                GroupMatch {
                    group: Some("group-b".to_string()),
                    clients: vec![Client::IpAddr("10.0.0.1/32".parse().unwrap())],
                    domains: vec![],
                }
            ))
        );
    }

    #[test]
    fn test_parse_group_match_mac_and_multi() {
        assert_eq!(
            GroupMatch::parse("-client-ip 01:02:03:04:05:06 -client-ip 192.168.1.1"),
            Ok((
                "",
                GroupMatch {
                    group: None,
                    clients: vec![
                        Client::Mac("01:02:03:04:05:06".to_string()),
                        Client::IpAddr("192.168.1.1/32".parse().unwrap()),
                    ],
                    domains: vec![],
                }
            ))
        );
    }

    #[test]
    fn test_parse_group_match_domain() {
        assert_eq!(
            GroupMatch::parse("-domain a.com"),
            Ok((
                "",
                GroupMatch {
                    group: None,
                    clients: vec![],
                    domains: vec!["a.com".to_string()],
                }
            ))
        );
    }

    #[test]
    fn test_parse_group_match_long_option_names() {
        // --client-ip / --group 的长写法同样支持
        assert_eq!(
            GroupMatch::parse("--group office --client-ip 192.168.1.0/24"),
            Ok((
                "",
                GroupMatch {
                    group: Some("office".to_string()),
                    clients: vec![Client::IpAddr("192.168.1.0/24".parse().unwrap())],
                    domains: vec![],
                }
            ))
        );
    }

    #[test]
    fn test_parse_group_match_allows_trailing_comment() {
        // 行尾注释是合法的：剩下的 " #..." 部分由上层行解析器处理
        assert_eq!(
            GroupMatch::parse("-client-ip 192.168.1.1 # 办公室网络"),
            Ok((
                " # 办公室网络",
                GroupMatch {
                    group: None,
                    clients: vec![Client::IpAddr("192.168.1.1/32".parse().unwrap())],
                    domains: vec![],
                }
            ))
        );
    }

    #[test]
    fn test_parse_group_match_rejects_unknown_option() {
        // 拼错的选项名必须报错，不能静默变成「没有条件」的空指令
        assert!(GroupMatch::parse("-clientip 192.168.1.1").is_err());
        assert!(GroupMatch::parse("-client-ip 192.168.1.1 -bogus x").is_err());
        // 完全没有选项也判为错误
        assert!(GroupMatch::parse("").is_err());
    }
}
