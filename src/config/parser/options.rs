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

pub fn unkown_options(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let key = any_name;
    let value = unkown_value;
    pair(key, opt(value)).parse(input)
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
