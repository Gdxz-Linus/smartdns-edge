use url::Url;

use super::*;

///
/// domain-set -type list -file /path/to/list
/// domain-set -type list -url https://example.com/list
impl NomParser for DomainSetProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        use DomainSetProvider::*;
        alt((map(NomParser::parse, File), map(NomParser::parse, Http))).parse(input)
    }
}

/// domain-set -type list -file /path/to/list
/// domain-set -type list -f /path/to/list
impl NomParser for DomainSetFileProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut file = None;
        let mut interval = None;
        let mut content_type = Default::default();

        let one = alt((
            map(
                // 显式写 `String::parse`：不写的话，下面 `&name`（要 `&str`）会把推断带偏，
                // 编译器会把 name 推成 `str` 然后报一堆 "the size for values of type str"。
                options::parse_value(alt((tag_no_case("name"), tag_no_case("n"))), String::parse),
                |v| {
                    name = Some(v);
                },
            ),
            map(
                options::parse_value(alt((tag_no_case("file"), tag_no_case("f"))), PathBuf::parse),
                |v| {
                    file = Some(v);
                },
            ),
            // 🔐 P2：本地文件名单同样支持 `-interval` —— 文件内容也是在配置构建时展开进
            // 规则树的，所以"文件改了要生效"和远程名单一样需要定期重建配置。
            map(
                options::parse_value(
                    alt((tag_no_case("interval"), tag_no_case("i"))),
                    NomParser::parse,
                ),
                |v: usize| interval = Some(v),
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("type"), tag_no_case("t"))),
                    DomainSetContentType::parse,
                ),
                |t| {
                    content_type = t;
                },
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one).parse(input)?;

        if let (Some(name), Some(file)) = (name, file) {
            super::warn_if_interval_too_short("domain-set", &name, interval);

            return Ok((
                rest_input,
                DomainSetFileProvider {
                    name,
                    file,
                    interval,
                    content_type,
                },
            ));
        }

        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

/// domain-set -type list -url https://example.com/list
/// domain-set -type list -u https://example.com/list
impl NomParser for DomainSetHttpProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut url = None;
        let mut interval = None;
        let mut content_type = Default::default();
        let mut proxy = None; // 🌟 增加 proxy 变量

        let one = alt((
            map(
                options::parse_value(alt((tag_no_case("name"), tag_no_case("n"))), String::parse),
                |v| name = Some(v),
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("url"), tag_no_case("u"))),
                    map_res(is_not(" \t\r\n"), Url::parse),
                ),
                |v| url = Some(v),
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("interval"), tag_no_case("i"))),
                    NomParser::parse,
                ),
                |v: usize| interval = Some(v),
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("type"), tag_no_case("t"))),
                    DomainSetContentType::parse,
                ),
                |t| content_type = t,
            ),
            // 🌟 教解析器认识 -proxy 和 -p 参数
            map(
                options::parse_value(alt((tag_no_case("proxy"), tag_no_case("p"))), String::parse),
                |v| proxy = Some(v),
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one).parse(input)?;

        if let (Some(name), Some(url)) = (name, url) {
            // 🔐 `-interval` 现在真的生效了 —— `App` 里的定时任务会按它重建配置，
            // 把新名单展开进规则树；未到自己周期的名单用内存缓存，不会被顺带重下。
            // （原来这里只告警说"不生效"，因为当时确实没有消费者。）
            super::warn_if_interval_too_short("domain-set", &name, interval);

            return Ok((
                rest_input,
                DomainSetHttpProvider {
                    name,
                    url,
                    interval,
                    content_type,
                    proxy, // 🌟 装填进结构体
                },
            ));
        }

        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

impl NomParser for DomainSetContentType {
    fn parse(input: &str) -> IResult<&str, Self> {
        use DomainSetContentType::*;
        alt((value(List, tag_no_case("list")),)).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_file_provider() {
        assert_eq!(
            DomainSetProvider::parse("-n proxy-server -f proxy-server-list.txt"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "proxy-server".to_string(),
                    file: PathBuf::from("proxy-server-list.txt"),
                    interval: None,
                    content_type: Default::default(),
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse("-name set -file /path/to/list"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    interval: None,
                    content_type: Default::default(),
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse("-type list -name set -file /path/to/list"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    interval: None,
                    content_type: Default::default(),
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse("-type list -name set -f /path/to/list"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    interval: None,
                    content_type: Default::default(),
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse("-t list -name set -f /path/to/list"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    interval: None,
                    content_type: Default::default(),
                })
            ))
        );
    }

    #[test]
    fn test_parse_http_provider() {
        assert_eq!(
            DomainSetProvider::parse("-type list -name set -url https://example.com/ads.txt"),
            Ok((
                "",
                DomainSetProvider::Http(DomainSetHttpProvider {
                    name: "set".to_string(),
                    url: Url::parse("https://example.com/ads.txt").unwrap(),
                    interval: None,
                    content_type: Default::default(),
                    proxy: None, // 🌟 修复：补上 proxy 字段，满足 Rust 结构体完整性检查
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse("-name set -url https://example.com/ads.txt -i 3600"),
            Ok((
                "",
                DomainSetProvider::Http(DomainSetHttpProvider {
                    name: "set".to_string(),
                    url: Url::parse("https://example.com/ads.txt").unwrap(),
                    interval: Some(3600),
                    content_type: Default::default(),
                    proxy: None, // 🌟 修复
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse(
                "-type list -name set -u https://example.com/ads.txt --interval 3600"
            ),
            Ok((
                "",
                DomainSetProvider::Http(DomainSetHttpProvider {
                    name: "set".to_string(),
                    url: Url::parse("https://example.com/ads.txt").unwrap(),
                    interval: Some(3600),
                    content_type: Default::default(),
                    proxy: None, // 🌟 修复
                })
            ))
        );
    }
}
