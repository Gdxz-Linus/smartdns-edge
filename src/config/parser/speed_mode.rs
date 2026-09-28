use super::*;

impl NomParser for Option<SpeedCheckModeList> {
    fn parse(input: &str) -> IResult<&str, Self> {
        // 🔐 问题 24：`none` **不能再折叠成 `Option::None`**。
        //
        // 原来是 `alt((value(None, tag_no_case("none")), map(SpeedCheckModeList::parse, Some)))`，
        // 于是 `speed-check-mode none` 解析成 `None` —— 与"**根本没写这一行**"**完全同形**。
        // 这一处折叠是问题 24 的**病根**：下游任何"读不到就用默认值"的写法
        // （双栈那边原来正是 `.unwrap_or_default()`）都会把用户的 `none`
        // 当成"没配置"，转而**拿默认的 ping+tcp:443 去探测** —— 与用户意图正好相反。
        //
        // 改法：`none` 交给 `SpeedCheckModeList::parse` 正常解析，得到一个**含
        // `SpeedCheckMode::None` 元素**的列表（`Some([None])`）。这样：
        //   · "没配置"        → `None`（`Config` 字段的 `Default`）
        //   · "配了 `none`"    → `Some([None])`
        // 两者从此**可区分**，`none` 才可能真正生效。
        //
        // ⚠️ 上游选 IP 那条路径（`dns_mw_ns.rs`）**不受影响**：它本来就会对
        // `speed_check_mode.iter().any(|m| m.is_none())` 做"不测速"处理，
        // 也就是说它早已**同时**覆盖了"`None`"与"含 `None` 元素"两种情况。
        map(SpeedCheckModeList::parse, Some).parse(input)
    }
}

impl NomParser for SpeedCheckModeList {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(
            separated_list1(delimited(space0, char(','), space0), NomParser::parse),
            SpeedCheckModeList,
        )
        .parse(input)
    }
}

impl NomParser for SpeedCheckMode {
    fn parse(input: &str) -> IResult<&str, Self> {
        use SpeedCheckMode::*;

        let none = value(None, tag_no_case("none"));
        let ping = value(Ping, tag_no_case("ping"));
        let tcp = map(preceded(tag_no_case("tcp"), preceded(char(':'), u16)), Tcp);
        let https = map(
            preceded(
                tag_no_case("https"),
                map(opt(preceded(char(':'), u16)), |r| r.unwrap_or(443)),
            ),
            Https,
        );

        // 🌟 核心修复：清理掉对 http 的解析
        alt((none, ping, tcp, https)).parse(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_speed_mode_parse() {
        use SpeedCheckMode::*;

        assert_eq!(SpeedCheckMode::parse("ping"), Ok(("", Ping)));
        assert_eq!(SpeedCheckMode::parse("Ping"), Ok(("", Ping)));
        assert_eq!(SpeedCheckMode::parse("tcp:96"), Ok(("", Tcp(96))));
        // 🌟 清理掉对 Http 的测试断言
        assert_eq!(SpeedCheckMode::parse("https"), Ok(("", Https(443))));
        assert_eq!(SpeedCheckMode::parse("https:8443"), Ok(("", Https(8443))));

        assert!(SpeedCheckMode::parse("tcp").is_err());
    }

    #[test]
    fn test_speed_mode_list_parse() {
        use SpeedCheckMode::*;
        assert_eq!(
            SpeedCheckModeList::parse("ping,tcp:96"),
            Ok(("", vec![Ping, Tcp(96)].into()))
        );
    }

    #[test]
    fn test_speed_mode_none() {
        // 🔐 问题 24：`none` 必须解析成**含 `None` 元素的列表**（`Some([None])`），
        // 而**不是**折叠成 `Option::None`。
        //
        // 折叠的后果：`speed-check-mode none` 与"根本没写这一行"**完全同形**，
        // 于是双栈那条路径的 `.unwrap_or_default()` 会把前者当成后者，
        // 拿默认的 `ping,tcp:443` 去探测 —— 用户配了 `none` 却反而触发测速。
        assert_eq!(
            Option::<SpeedCheckModeList>::parse("none"),
            Ok(("", Some(SpeedCheckModeList(vec![SpeedCheckMode::None]))))
        );
    }

    /// 🔐 问题 24：**"没配置"与"配了 `none`"必须可区分**。
    ///
    /// 这是整套修复的前提 —— 两者一旦同形，下游就没有任何办法把
    /// "用户明确要求不测速"和"用户没表态"分开。
    #[test]
    fn unset_and_explicit_none_are_distinguishable() {
        // "配了 none" → `Some([None])`
        let explicit = Option::<SpeedCheckModeList>::parse("none").unwrap().1;
        assert!(
            explicit.is_some(),
            "显式 none 必须是 Some(...)，否则与'没配置'同形（这正是问题 24 的病根）"
        );
        assert!(
            explicit.as_ref().unwrap().iter().any(|m| m.is_none()),
            "显式 none 的列表里必须含 SpeedCheckMode::None 元素"
        );

        // "没配置" → `None`（由 `Config` 字段的 `Default` 给出，这里用 `Default::default()` 表示）
        let unset = Option::<SpeedCheckModeList>::default();
        assert!(unset.is_none(), "未配置应当是 None");
        assert!(
            unset != explicit,
            "未配置与显式 none 必须不同 —— 相同则下游无法区分二者"
        );

        // 顺带确认：普通的模式列表不受影响
        assert_eq!(
            Option::<SpeedCheckModeList>::parse("ping,tcp:53"),
            Ok((
                "",
                Some(vec![SpeedCheckMode::Ping, SpeedCheckMode::Tcp(53)].into())
            ))
        );
    }
}
