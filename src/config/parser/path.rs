use super::*;

impl NomParser for PathBuf {
    fn parse(input: &str) -> IResult<&str, Self> {
        let delimited_path = delimited(char('"'), is_not("\""), char('"'));
        let unix_path = recognize((
            opt(char('/')),
            separated_list1(char('/'), escaped(is_not("\n \t\\"), '\\', one_of(r#" \""#))),
            opt(char('/')),
        ));
        // 反斜杠路径（Windows 原生写法）。注意每个路径段都用 `is_not(" \t\\")` —— **不许含空白**。
        //
        // 曾经这里写的是 `is_not("\\")`（允许空白），后果是：
        // `ip-set -name x -file C:\lists\cn.txt -interval 3600` 会把 " -interval 3600"
        // 一起当成路径的一部分 —— 文件当然找不到（报"系统找不到指定的文件"），
        // 而后面的选项被静默吞掉（用户完全看不出为什么 `-interval` 不生效）。
        //
        // 为什么反斜杠路径会走到这个分支：`unix_path` 里的 `escaped()` 碰到反斜杠时，
        // 只有紧跟 `空格 / 反斜杠 / 引号`（可转义字符）才算成功，否则整个分支返回 Err
        // （实测 code = OneOf），于是 `alt` 落到 windows 分支。所以这两个分支的
        // "哪里算路径结束"必须一致 —— 都在空白处结束；路径里有空格就加引号
        // （`"C:\Program Files\x.list"`，由 delimited_path 处理）。
        let windows_path = recognize((
            opt(pair(alpha1, tag(":\\"))),
            separated_list1(char('\\'), is_not(" \t\\")),
            opt(char('\\')),
        ));
        map(alt((delimited_path, unix_path, windows_path)), Into::into).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows 反斜杠路径：**路径在空白处结束**，后面的选项不能被吞进路径里。
    ///
    /// 曾经的实现在这个分支用 `is_not("\\")`（允许空白），于是
    /// `-file C:\lists\cn.txt -interval 3600` 会把 " -interval 3600" 一起当成路径：
    /// 文件报"找不到"、`-interval` 静默失效。这里把它钉死。
    #[test]
    fn test_windows_path_stops_at_whitespace() {
        assert_eq!(
            PathBuf::parse(r"C:\lists\cn.txt -interval 3600"),
            Ok((" -interval 3600", r"C:\lists\cn.txt".into()))
        );
        assert_eq!(
            PathBuf::parse(r"D:\conf.d\*.conf -g office"),
            Ok((" -g office", r"D:\conf.d\*.conf".into()))
        );
        // 反斜杠路径里的空格必须加引号（与正斜杠路径的规则一致）
        assert_eq!(
            PathBuf::parse(r#""C:\Program Files\x.list""#),
            Ok(("", r"C:\Program Files\x.list".into()))
        );
        assert_eq!(
            PathBuf::parse(r"C:\Program Files\x.list"),
            Ok((r" Files\x.list", r"C:\Program".into()))
        );
    }

    #[test]
    fn test_parse() {
        assert_eq!(PathBuf::parse("a"), Ok(("", "a".into())));
        assert_eq!(PathBuf::parse("/"), Ok(("", "/".into())));
        assert_eq!(PathBuf::parse("a/b😁/c"), Ok(("", "a/b😁/c".into())));
        assert_eq!(PathBuf::parse("a/ b/c"), Ok((" b/c", "a/".into())));
        assert_eq!(PathBuf::parse("/a/b/c"), Ok(("", "/a/b/c".into())));
        assert_eq!(PathBuf::parse("/a/b/c/"), Ok(("", "/a/b/c/".into())));
        assert_eq!(PathBuf::parse("a/b/c/"), Ok(("", "a/b/c/".into())));
    }

    #[test]
    fn test_backslash_escaping_parse() {
        assert_eq!(PathBuf::parse(r#"a/\ b/c"#), Ok(("", r#"a/\ b/c"#.into())));
        assert_eq!(PathBuf::parse(r#"a/\\b/c"#), Ok(("", r#"a/\\b/c"#.into())));
    }

    #[test]
    fn test_delimited_path_parse() {
        assert_eq!(PathBuf::parse(r#""a/ b/c""#), Ok(("", "a/ b/c".into())));
    }

    #[test]
    fn test_windows_path_parse() {
        assert_eq!(
            PathBuf::parse(r#"C:\Users\Administrator\Desktop\smartdns\smartdns.log"#),
            Ok((
                "",
                r#"C:\Users\Administrator\Desktop\smartdns\smartdns.log"#.into()
            ))
        );
        assert_eq!(
            PathBuf::parse(r#"C:/Users/Administrator/Desktop/smartdns/smartdns.log"#),
            Ok((
                "",
                r#"C:/Users/Administrator/Desktop/smartdns/smartdns.log"#.into()
            ))
        );
        assert_eq!(
            PathBuf::parse(r#".\smartdns\smartdns.log"#),
            Ok(("", r#".\smartdns\smartdns.log"#.into()))
        );
        assert_eq!(
            PathBuf::parse(r#".\smartdns\"#),
            Ok(("", r#".\smartdns\"#.into()))
        );
    }
}
