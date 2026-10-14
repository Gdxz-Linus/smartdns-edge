use super::*;

impl NomParser for bool {
    fn parse(input: &str) -> IResult<&str, Self> {
        let t = value(
            true,
            alt((
                tag_no_case("True"),
                tag_no_case("T"),
                tag_no_case("Yes"),
                tag_no_case("Y"),
                tag("1"),
            )),
        );

        let f = value(
            false,
            alt((
                tag_no_case("False"),
                tag_no_case("F"),
                tag_no_case("No"),
                tag_no_case("N"),
                tag("0"),
            )),
        );
        alt((t, f)).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(bool::parse("true"), Ok(("", true)));
        assert_eq!(bool::parse("0"), Ok(("", false)));
        assert_eq!(bool::parse("n"), Ok(("", false)));
    }
}


/// 三态布尔（auto/yes/no）：`auto` 解析为 None，yes/no 解析为 Some(true/false)。
/// 供 `bind-cert-generate` 这类“用户未表态时按智能默认走”的配置项使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YesNoAuto(pub Option<bool>);

impl NomParser for YesNoAuto {
    fn parse(input: &str) -> IResult<&str, Self> {
        let auto = value(YesNoAuto(None), tag_no_case("auto"));
        let yes = value(YesNoAuto(Some(true)), tag_no_case("yes"));
        let no = value(YesNoAuto(Some(false)), tag_no_case("no"));
        auto.or(yes).or(no).parse(input)
    }
}

impl NomParser for Option<bool> {
    fn parse(input: &str) -> IResult<&str, Self> {
        YesNoAuto::parse(input).map(|(rest, YesNoAuto(v))| (rest, v))
    }
}
