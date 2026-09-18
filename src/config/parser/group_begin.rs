use super::*;

impl NomParser for GroupBegin {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, _) = preceded(
            alt((tag_no_case("group-begin"), tag_no_case("group_begin"))),
            // 认空格写法，也认 `group-begin=名字`（少数人这么写）
            alt((space1, preceded(char('='), space0))),
        )
        .parse(input)?;

        // 组名：到空白为止
        let (input, name) = map(is_not(" \t\r\n"), |s: &str| s.to_string()).parse(input)?;

        let mut group = GroupBegin {
            name,
            inherit: None,
        };

        if let Ok((rest, options)) = opt(preceded(space1, options::parse)).parse(input)
            && let Some(options) = options
        {
            for (k, v) in options {
                match k.to_lowercase().as_str() {
                    // 🔐 Q18：-inherit <组|none|parent|default>
                    "inherit" | "h" => match v {
                        Some(value) => group.inherit = Some(value.to_string()),
                        None => crate::log::warn!("`group-begin ... -inherit` 后面缺组名，已忽略"),
                    },
                    other => crate::log::warn!("group-begin 上不认识的选项：-{other}（已忽略）"),
                }
            }

            return Ok((rest, group));
        }

        Ok((input, group))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_group_begin() {
        assert_eq!(
            GroupBegin::parse("group-begin lan").unwrap().1,
            GroupBegin {
                name: "lan".to_string(),
                inherit: None
            }
        );

        assert_eq!(
            GroupBegin::parse("group-begin lan -inherit base")
                .unwrap()
                .1,
            GroupBegin {
                name: "lan".to_string(),
                inherit: Some("base".to_string())
            }
        );

        // 特殊值原样带着走（解释在处理器里做，与 C 版一致）
        assert_eq!(
            GroupBegin::parse("group-begin lan -inherit none")
                .unwrap()
                .1
                .inherit,
            Some("none".to_string())
        );
    }
}
