use super::*;

/// conf-file /path/to/extra.conf
/// conf-file /etc/smartdns/conf.d/*.conf
/// conf-file /path/to/extra.conf -g office
/// conf-file -g office /path/to/extra.conf
///
/// 🔐 两个参数顺序任意（与 C 版 getopt 的"参数可前置"行为一致）。
/// `-g` 分支必须排在路径分支**前面**：否则路径解析会把 `-g` 当成一个路径名吃掉。
impl NomParser for ConfFileItem {
    fn parse(input: &str) -> IResult<&str, Self> {
        #[derive(Debug, Clone)]
        enum Arg {
            Group(String),
            Path(PathBuf),
        }

        let one = alt((
            map(
                options::parse_value(
                    alt((tag_no_case("group"), tag_no_case("g"))),
                    String::parse,
                ),
                Arg::Group,
            ),
            map(PathBuf::parse, Arg::Path),
        ));

        let (rest_input, args) = separated_list1(space1, one).parse(input)?;

        let mut path = None;
        let mut group = None;
        for arg in args {
            match arg {
                Arg::Group(name) => group = Some(name),
                // 一行里给了两个路径无法消歧（到底要包含哪个？）。这里直接判为"这行不合法"，
                // 让用户按每个 `conf-file` 一行写清楚 —— 静默只取其中一个会埋下"我配了却没生效"。
                Arg::Path(_) if path.is_some() => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
                Arg::Path(value) => path = Some(value),
            }
        }

        match path {
            Some(path) => Ok((rest_input, ConfFileItem { path, group })),
            None => Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(path: &str, group: Option<&str>) -> ConfFileItem {
        ConfFileItem {
            path: PathBuf::from(path),
            group: group.map(|g| g.to_string()),
        }
    }

    #[test]
    fn test_parse_path_only() {
        assert_eq!(
            ConfFileItem::parse("/etc/smartdns/extra.conf"),
            Ok(("", item("/etc/smartdns/extra.conf", None)))
        );
        // 通配符是路径的一部分，解析层不该把它拆开
        assert_eq!(
            ConfFileItem::parse("/etc/smartdns/conf.d/*.conf"),
            Ok(("", item("/etc/smartdns/conf.d/*.conf", None)))
        );
        assert_eq!(
            ConfFileItem::parse("./relative/extra.conf"),
            Ok(("", item("./relative/extra.conf", None)))
        );
    }

    #[test]
    fn test_parse_group_both_orders() {
        assert_eq!(
            ConfFileItem::parse("/etc/smartdns/extra.conf -g office"),
            Ok(("", item("/etc/smartdns/extra.conf", Some("office"))))
        );
        assert_eq!(
            ConfFileItem::parse("/etc/smartdns/extra.conf -group office"),
            Ok(("", item("/etc/smartdns/extra.conf", Some("office"))))
        );
        // 前置写法（C 版 getopt 允许，用户照抄也不会踩空）
        assert_eq!(
            ConfFileItem::parse("-g office /etc/smartdns/extra.conf"),
            Ok(("", item("/etc/smartdns/extra.conf", Some("office"))))
        );
        assert_eq!(
            ConfFileItem::parse("-group office /etc/smartdns/conf.d/*.conf"),
            Ok(("", item("/etc/smartdns/conf.d/*.conf", Some("office"))))
        );
        // Windows 反斜杠路径同样不能把选项吞进路径里（曾经会）
        assert_eq!(
            ConfFileItem::parse(r"D:\conf.d\*.conf -g office"),
            Ok(("", item(r"D:\conf.d\*.conf", Some("office"))))
        );
    }

    #[test]
    fn test_parse_invalid() {
        // 没有路径：这行不成立
        assert!(ConfFileItem::parse("-g office").is_err());
        // 两个路径：无法消歧，判为不合法（由调用方报"这行没认出来"）
        assert!(ConfFileItem::parse("/a.conf /b.conf").is_err());
    }
}
