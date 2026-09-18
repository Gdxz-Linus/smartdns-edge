use super::*;

fn name<
    'a,
    O,
    E: nom::error::ParseError<&'a str>,
    P: nom::Parser<&'a str, Output = O, Error = E>,
>(
    parser: P,
) -> impl Parser<&'a str, Output = O, Error = E> {
    preceded(take_while_m_n(1, 2, |c| c == '-'), parser)
}

fn any_name(input: &str) -> IResult<&str, &str> {
    name(recognize(pair(
        alpha1,
        take_while(|c: char| c == '-' || c.is_alphanumeric()),
    )))
    .parse(input)
}

pub fn parse_value<
    'a,
    ON,
    OV,
    E: nom::error::ParseError<&'a str>,
    N: nom::Parser<&'a str, Output = ON, Error = E>,
    V: nom::Parser<&'a str, Output = OV, Error = E>,
>(
    name: N,
    value: V,
) -> impl Parser<&'a str, Output = OV, Error = E> {
    preceded(
        (
            take_while_m_n(1, 2, |c| c == '-'),
            name,
            alt((tag("="), recognize(pair(opt(char(':')), space1)))),
        ),
        value,
    )
}

pub fn parse_flag<
    'a,
    O,
    E: nom::error::ParseError<&'a str>,
    N: nom::Parser<&'a str, Output = O, Error = E>,
>(
    name: N,
) -> impl Parser<&'a str, Output = bool, Error = E> {
    value(true, preceded(take_while_m_n(1, 2, |c| c == '-'), name))
}

pub fn unkown_value(input: &str) -> IResult<&str, &str> {
    alt((
        // 🌟 核心修复情况 A：当用户明确使用 "=" 赋值时，彻底解除首字符 "-" 的防线！
        // 完美放行如 `-group=-cn_nodes` 或 `-cert=--base64--` 等合法但极端的配置值。
        preceded(
            tag("="),
            is_not(" \t\r\n#")
        ),
        // 🌟 核心修复情况 B：当使用空格分隔时，依然保持对首字符 "-" 的拦截（防吞噬下一个 Flag），
        // 但保留“孤立减号”的特权通行证（专门用于 -host-name - 等关闭场景）。
        preceded(
            recognize(pair(opt(char(':')), space1)),
            alt((
                terminated(tag("-"), peek(alt((space1, eof)))),
                recognize(pair(
                    // 仅拦截减号开头，保障参数边界安全
                    is_not("- \t\r\n#"),
                    take_till(|c: char| c.is_whitespace() || c == '#'),
                ))
            ))
        )
    ))
    .parse(input)
}

/// 以 `#` 开头的值（`#4:name`、`#4:family#table#set`）：吃到下一个空白为止，中间的 `#` 都算值。
///
/// 🔐 Q19/Q20/Q21 为什么需要它：C 版的注释规则是"**整行**以 `#` 开头才算注释"
/// （`src/lib/conf.c:545`），所以 `-nftset #4:...` 里的 `#` 是值的一部分。
/// 我们的词法更宽松（`#` 出现在哪儿都当注释，支持"行尾注释"这种写法），
/// 于是 `-nftset #4:...` 的值会被当成注释吃掉、用户看到的是"配了像没配"。
/// 这里只为这两个选项开这个口子，既兼容 C 版的写法，也不影响行尾注释。
fn hash_prefixed_value(input: &str) -> IResult<&str, &str> {
    preceded(
        space1,
        recognize((
            tag("#"),
            take_till(|c: char| c.is_whitespace()),
        )),
    )
    .parse(input)
}

pub fn unkown_options(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let (input, key) = any_name(input)?;

    if matches!(key, "ipset" | "nftset") {
        let (input, value) = opt(alt((unkown_value, hash_prefixed_value))).parse(input)?;
        return Ok((input, (key, value)));
    }

    let (input, value) = opt(unkown_value).parse(input)?;
    Ok((input, (key, value)))
}

pub fn parse(input: &str) -> IResult<&str, Options<'_>> {
    let (input, options) = separated_list0(space1, unkown_options).parse(input)?;

    Ok((input, options))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_options() {
        assert_eq!(
            parse("-a a1 --b b0 -w").unwrap(),
            ("", vec![("a", Some("a1")), ("b", Some("b0")), ("w", None)])
        );

        assert_eq!(parse("---a").unwrap(), ("---a", vec![]));

        assert_eq!(parse("-w123").unwrap(), ("", vec![("w123", None)]));
    }

    #[test]
    fn test_parse_options1() {
        assert_eq!(
            parse("-group bootstrap -exclude-default-group").unwrap(),
            (
                "",
                vec![
                    ("group", Some("bootstrap")),
                    ("exclude-default-group", None)
                ]
            )
        );
    }

    /// 🔐 Q19-21：`-ipset` / `-nftset` 的值以 `#` 开头时不能被当成注释
    #[test]
    fn test_hash_prefixed_set_values() {
        assert_eq!(
            parse("-nftset #4:inet#filter#set4 -ipset #6:dns6").unwrap(),
            (
                "",
                vec![
                    ("nftset", Some("#4:inet#filter#set4")),
                    ("ipset", Some("#6:dns6")),
                ]
            )
        );

        // 行尾注释照旧（后面那个 `#` 不属于任何选项的值）
        assert_eq!(
            parse("-nftset #4:t#s#n # 这是注释").unwrap().1[0],
            ("nftset", Some("#4:t#s#n"))
        );

        // 别的选项不受影响：`-group #x` 仍然没有值（`#x` 当注释）
        // （剩下的 ` #x` 留给上层当注释处理）
        assert_eq!(parse("-group #x").unwrap(), (" #x", vec![("group", None)]));
    }

    #[test]
    fn test_parse_options2() {
        assert_eq!(
            parse("-group bootstrap # -exclude-default-group").unwrap(),
            (
                " # -exclude-default-group",
                vec![("group", Some("bootstrap"))]
            )
        );
    }
}
