use url::Url;

use super::*;

/// ip-set -type list -file /path/to/list
/// ip-set -type list -url https://example.com/list
///
/// 🔐 与 `domain-set` 同款：`alt` 里本地文件在前、远程在后；
/// 写了 `-url` 的行本地文件分支匹配不上，自然落到远程分支。
impl NomParser for IpSetProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        use IpSetProvider::*;
        alt((map(NomParser::parse, File), map(NomParser::parse, Http))).parse(input)
    }
}

/// ip-set -type list -file /path/to/list
/// ip-set -type list -f /path/to/list
/// ip-set -type list -file /path/to/list -interval 3600
impl NomParser for IpSetFileProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut file = None;
        let mut interval = None;

        let one = alt((
            map(
                // 显式写 `String::parse`：靠推断的话，下面 `&name`（要 `&str`）会把推断带偏
                options::parse_value(alt((tag_no_case("name"), tag_no_case("n"))), String::parse),
                |v| name = Some(v),
            ),
            map(
                options::parse_value(alt((tag_no_case("file"), tag_no_case("f"))), PathBuf::parse),
                |v| file = Some(v),
            ),
            // 本地文件名单同样支持 `-interval`：文件内容也是在构建配置时展开进规则树的
            map(
                options::parse_value(
                    alt((tag_no_case("interval"), tag_no_case("i"))),
                    NomParser::parse,
                ),
                |v: usize| interval = Some(v),
            ),
            options::parse_value(
                alt((tag_no_case("type"), tag_no_case("t"))),
                value((), tag_no_case("list")),
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one).parse(input)?;

        if let (Some(name), Some(file)) = (name, file) {
            super::warn_if_interval_too_short("ip-set", &name, interval);

            return Ok((
                rest_input,
                IpSetFileProvider {
                    name,
                    file,
                    interval,
                },
            ));
        }

        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

/// ip-set -type list -url https://example.com/list
/// ip-set -type list -u https://example.com/list -interval 3600 -proxy clash
impl NomParser for IpSetHttpProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut url = None;
        let mut interval = None;
        let mut proxy = None;

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
                options::parse_value(alt((tag_no_case("proxy"), tag_no_case("p"))), String::parse),
                |v| proxy = Some(v),
            ),
            options::parse_value(
                alt((tag_no_case("type"), tag_no_case("t"))),
                value((), tag_no_case("list")),
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one).parse(input)?;

        if let (Some(name), Some(url)) = (name, url) {
            super::warn_if_interval_too_short("ip-set", &name, interval);

            return Ok((
                rest_input,
                IpSetHttpProvider {
                    name,
                    url,
                    interval,
                    proxy,
                },
            ));
        }

        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_provider(name: &str, path: &str, interval: Option<usize>) -> IpSetProvider {
        IpSetProvider::File(IpSetFileProvider {
            name: name.to_string(),
            file: PathBuf::from(path),
            interval,
        })
    }

    fn http_provider(
        name: &str,
        url: &str,
        interval: Option<usize>,
        proxy: Option<&str>,
    ) -> IpSetProvider {
        IpSetProvider::Http(IpSetHttpProvider {
            name: name.to_string(),
            url: Url::parse(url).unwrap(),
            interval,
            proxy: proxy.map(|s| s.to_string()),
        })
    }

    #[test]
    fn test_parse_file_provider() {
        assert_eq!(
            IpSetProvider::parse("-n name -f file.txt"),
            Ok(("", file_provider("name", "file.txt", None)))
        );
        assert_eq!(
            IpSetProvider::parse("-name set -file /path/to/list"),
            Ok(("", file_provider("set", "/path/to/list", None)))
        );
        assert_eq!(
            IpSetProvider::parse("-type list -name set -file /path/to/list"),
            Ok(("", file_provider("set", "/path/to/list", None)))
        );
        // 新增：本地文件也支持自动刷新周期
        assert_eq!(
            IpSetProvider::parse("-name set -file /path/to/list -interval 3600"),
            Ok(("", file_provider("set", "/path/to/list", Some(3600))))
        );
        assert_eq!(
            IpSetProvider::parse("-n set -f list.txt -i 60"),
            Ok(("", file_provider("set", "list.txt", Some(60))))
        );
        // 缺 name 或 file 都不成立
        assert!(IpSetProvider::parse("-name set").is_err());
        assert!(IpSetProvider::parse("-file list.txt").is_err());
    }

    /// Windows 反斜杠路径 + 后续选项：路径在空白处结束，`-interval` 必须真的被解析出来
    /// （曾经反斜杠分支会把 " -interval 3600" 一起吞进路径，导致 `-interval` 静默失效）。
    #[test]
    fn test_parse_file_provider_windows_path() {
        assert_eq!(
            IpSetProvider::parse(r"-name set -file C:\lists\cn.txt -interval 3600"),
            Ok(("", file_provider("set", r"C:\lists\cn.txt", Some(3600))))
        );
        assert_eq!(
            IpSetProvider::parse(r#"-name set -file "D:\a b\list.txt" -interval 60"#),
            Ok(("", file_provider("set", r"D:\a b\list.txt", Some(60)))),
            "含空格的反斜杠路径加引号后应当照常解析"
        );
    }

    #[test]
    fn test_parse_http_provider() {
        assert_eq!(
            IpSetProvider::parse("-name set -url https://example.com/list"),
            Ok((
                "",
                http_provider("set", "https://example.com/list", None, None)
            ))
        );
        assert_eq!(
            IpSetProvider::parse("-n set -u http://example.com/list -i 3600 -p clash"),
            Ok((
                "",
                http_provider("set", "http://example.com/list", Some(3600), Some("clash"))
            ))
        );
        assert_eq!(
            IpSetProvider::parse("-type list -name set -url https://example.com/list -proxy 代理A"),
            Ok((
                "",
                http_provider("set", "https://example.com/list", None, Some("代理A"))
            ))
        );
        // 远程名单必须给 URL（只有 -file 的行走不到这个分支）
        assert!(
            IpSetProvider::parse("-name set -file /path/to/list")
                .unwrap()
                .1
                .name()
                == "set"
        );
    }
}
