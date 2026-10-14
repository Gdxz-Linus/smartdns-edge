// Copyright 2015-2016 Benjamin Fry
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::{char, iter::Peekable};

use crate::serialize::txt::errors::{LexerError, LexerErrorKind, LexerResult};

/// A Lexer for Zone files
pub(crate) struct Lexer<'a> {
    txt: Peekable<CowChars<'a>>,
    state: State,
}

impl<'a> Lexer<'a> {
    /// Creates a new lexer with the given data to parse
    pub(crate) fn new(txt: impl Into<Cow<'a, str>>) -> Self {
        Lexer {
            txt: CowChars {
                data: txt.into(),
                offset: 0,
            }
            .peekable(),
            state: State::StartLine,
        }
    }

    /// Return the next Token in the string
    pub(crate) fn next_token(&mut self) -> LexerResult<Option<Token>> {
        let mut char_data_vec: Option<Vec<String>> = None;
        let mut char_data: Option<String> = None;

        for i in 0..4_096 {
            // max chars in a single lex, helps with issues in the lexer...
            assert!(i < 4095); // keeps the bounds of the loop defined (nothing lasts forever)

            // This is to get around mutability rules such that we can peek at the iter without moving next...
            let ch: Option<char> = self.peek();

            // handy line for debugging
            // debug!("ch = {:?}; state = {:?}(c: {:?}, v: {:?})", ch, self.state, char_data, char_data_vec);

            // continuing states should pass back the state as the last statement,
            //  terminal states should set the state internally and return the proper Token::*.
            // TODO: there is some non-ideal copying going on in here...
            match self.state {
                State::StartLine => {
                    match ch {
                        Some('\r') | Some('\n') => {
                            self.state = State::EOL;
                        }
                        // white space at the start of line is a Blank
                        Some(ch) if ch.is_whitespace() => self.state = State::Blank,
                        Some(_) => self.state = State::RestOfLine,
                        None => {
                            self.state = State::EOF;
                        }
                    }
                }
                State::RestOfLine => {
                    match ch {
                        Some('@') => self.state = State::At,
                        Some('(') => {
                            self.txt.next();
                            char_data_vec = Some(Vec::new());
                            self.state = State::List;
                        }
                        Some(ch @ ')') => return Err(LexerErrorKind::IllegalCharacter(ch).into()),
                        Some('$') => {
                            self.txt.next();
                            char_data = Some(String::new());
                            self.state = State::Dollar;
                        }
                        Some('\r') | Some('\n') => {
                            self.state = State::EOL;
                        }
                        Some('"') => {
                            self.txt.next();
                            char_data = Some(String::new());
                            self.state = State::Quote;
                        }
                        Some(';') => self.state = State::Comment { is_list: false },
                        Some(ch) if ch.is_whitespace() => {
                            self.txt.next();
                        } // gobble other whitespace
                        Some(ch) if !ch.is_control() && !ch.is_whitespace() => {
                            char_data = Some(String::new());
                            self.state = State::CharData { is_list: false };
                        }
                        Some(ch) => return Err(LexerErrorKind::UnrecognizedChar(ch).into()),
                        None => {
                            self.state = State::EOF;
                        }
                    }
                }
                State::Blank => {
                    // consume the whitespace
                    self.txt.next();
                    self.state = State::RestOfLine;
                    return Ok(Some(Token::Blank));
                }
                State::Comment { is_list } => {
                    match ch {
                        Some('\r') | Some('\n') => {
                            self.state = if is_list { State::List } else { State::EOL };
                        } // out of the comment
                        Some(_) => {
                            self.txt.next();
                        } // advance the token by default and maintain state
                        None => {
                            self.state = State::EOF;
                        }
                    }
                }
                State::Quote => {
                    match ch {
                        // end and gobble the '"'
                        Some('"') => {
                            self.state = State::RestOfLine;
                            self.txt.next();
                            return Ok(Some(Token::CharData(
                                char_data.take().unwrap_or_else(|| "".into()),
                            )));
                        }
                        Some('\\') => {
                            Self::push_to_str(&mut char_data, self.escape_seq()?)?;
                        }
                        Some(ch) => {
                            self.txt.next();
                            Self::push_to_str(&mut char_data, ch)?;
                        }
                        None => return Err(LexerErrorKind::UnclosedQuotedString.into()),
                    }
                }
                State::Dollar => {
                    match ch {
                        // even this is a little broad for what's actually possible in a dollar...
                        Some(ch @ 'A'..='Z') => {
                            self.txt.next();
                            Self::push_to_str(&mut char_data, ch)?;
                        }
                        // finishes the Dollar...
                        Some(_) | None => {
                            self.state = State::RestOfLine;
                            let dollar: String = char_data.take().ok_or_else(|| {
                                LexerError::from(LexerErrorKind::IllegalState(
                                    "char_data \
                                     is None",
                                ))
                            })?;

                            return Ok(Some(match dollar.as_str() {
                                "INCLUDE" => Token::Include,
                                "ORIGIN" => Token::Origin,
                                "TTL" => Token::Ttl,
                                // 🔐 R-P3-4：dollar 已在第 151 行 take 移出，此处二次 take
                                // 恒得 None——错误信息里永远是空字符串。直接用已取出的值。
                                _ => {
                                    return Err(LexerErrorKind::UnrecognizedDollar(dollar).into());
                                }
                            }));
                        }
                    }
                }
                State::List => match ch {
                    Some(';') => {
                        self.txt.next();
                        self.state = State::Comment { is_list: true }
                    }
                    Some(')') => {
                        self.txt.next();
                        self.state = State::RestOfLine;
                        return char_data_vec
                            .take()
                            .ok_or_else(|| {
                                LexerErrorKind::IllegalState("char_data_vec is None").into()
                            })
                            .map(|v| Some(Token::List(v)));
                    }
                    Some(ch) if ch.is_whitespace() => {
                        self.txt.next();
                    }
                    Some(ch) if !ch.is_control() && !ch.is_whitespace() => {
                        char_data = Some(String::new());
                        self.state = State::CharData { is_list: true }
                    }
                    Some(ch) => return Err(LexerErrorKind::UnrecognizedChar(ch).into()),
                    None => return Err(LexerErrorKind::UnclosedList.into()),
                },
                State::CharData { is_list } => {
                    match ch {
                        Some(ch @ ')') if !is_list => {
                            return Err(LexerErrorKind::IllegalCharacter(ch).into());
                        }
                        Some(ch) if ch.is_whitespace() || ch == ')' || ch == ';' => {
                            if is_list {
                                char_data_vec
                                    .as_mut()
                                    .ok_or_else(|| {
                                        LexerError::from(LexerErrorKind::IllegalState(
                                            "char_data_vec is None",
                                        ))
                                    })
                                    .and_then(|v| {
                                        let char_data = char_data.take().ok_or(
                                            LexerErrorKind::IllegalState("char_data is None"),
                                        )?;

                                        v.push(char_data);
                                        Ok(())
                                    })?;
                                self.state = State::List;
                            } else {
                                self.state = State::RestOfLine;
                                let result = char_data.take().ok_or_else(|| {
                                    LexerErrorKind::IllegalState("char_data is None").into()
                                });
                                let opt = result.map(|s| Some(Token::CharData(s)));
                                return opt;
                            }
                        }
                        // 🔐 R-P2-2：非引号上下文的 CharData 同样处理转义（RFC 1035 §5.1——
                        // \X 与 \DDD 的转义语义不因是否在引号内而不同）。恢复上游注释掉的分支。
                        Some('\\') => {
                            self.txt.next();
                            Self::push_to_str(&mut char_data, self.escape_seq()?)?;
                        }
                        Some(ch) if !ch.is_control() && !ch.is_whitespace() => {
                            self.txt.next();
                            Self::push_to_str(&mut char_data, ch)?;
                        }
                        Some(ch) => return Err(LexerErrorKind::UnrecognizedChar(ch).into()),
                        None => {
                            self.state = State::EOF;
                            return char_data
                                .take()
                                .ok_or_else(|| {
                                    LexerErrorKind::IllegalState("char_data is None").into()
                                })
                                .map(|s| Some(Token::CharData(s)));
                        }
                    }
                }
                State::At => {
                    self.txt.next();
                    self.state = State::RestOfLine;
                    return Ok(Some(Token::At));
                }
                State::EOL => match ch {
                    Some('\r') => {
                        self.txt.next();
                    }
                    Some('\n') => {
                        self.txt.next();
                        self.state = State::StartLine;
                        return Ok(Some(Token::EOL));
                    }
                    Some(ch) => return Err(LexerErrorKind::IllegalCharacter(ch).into()),
                    None => return Err(LexerErrorKind::EOF.into()),
                },
                // to exhaust all cases, this should never be run...
                State::EOF => {
                    self.txt.next(); // making sure we consume the last... it will always return None after.
                    return Ok(None);
                }
            }
        }

        // 🔐 R-P2-1：原 unreachable!() 已移除——防御性错误处理不应以 panic 收场。
        // 所有状态在 match 内要么返回、要么转移；若未来新增状态遗漏终态，
        // 走到这里按非法状态返回错误，而不是让进程崩溃。
        Err(LexerErrorKind::IllegalState("lexer state machine reached a non-terminal state").into())
    }

    fn push_to_str(collect: &mut Option<String>, ch: char) -> LexerResult<()> {
        // 🔐 R-P2-1：单 token 长度上限 4096。zone 文件里合法 token（域名/文本）远小于此；
        // 无上限时一个超长 token（如单行无分隔符的恶意 zone 文件）会让 String 持续增长
        // 直至内存耗尽。超限返回错误而不是继续累积。
        const MAX_TOKEN_LEN: usize = 4096;
        let s = collect
            .as_mut()
            .ok_or_else(|| LexerErrorKind::IllegalState("collect is None"))?;
        if s.len() >= MAX_TOKEN_LEN {
            return Err(LexerErrorKind::TokenTooLong.into());
        }
        s.push(ch);
        Ok(())
    }

    fn escape_seq(&mut self) -> LexerResult<char> {
        // escaped character, let's decode it.
        self.txt.next(); // consume the escape
        let ch = self
            .peek()
            .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))?;

        if !ch.is_control() {
            if ch.is_numeric() {
                // 🔐 R-P2-2：\DDD 是三位**十进制**转义（RFC 1035 §5.1），如 \077 = 77 = 'M'。
                // 原实现按十六进制位权（d1<<16 + d2<<8 + d3）解码，\077 会错解成 0x707。
                // 十进制位权最大值 999 超出字节范围，须校验 ≤ 255。
                let d1: u32 = self
                    .txt
                    .next()
                    .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))
                    .map(|c| {
                        c.to_digit(10)
                            .ok_or_else(|| LexerError::from(LexerErrorKind::IllegalCharacter(c)))
                    })??; // gobble
                let d2: u32 = self
                    .txt
                    .next()
                    .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))
                    .map(|c| {
                        c.to_digit(10)
                            .ok_or_else(|| LexerError::from(LexerErrorKind::IllegalCharacter(c)))
                    })??; // gobble
                let d3: u32 = self
                    .txt
                    .next()
                    .ok_or_else(|| LexerError::from(LexerErrorKind::EOF))
                    .map(|c| {
                        c.to_digit(10)
                            .ok_or_else(|| LexerError::from(LexerErrorKind::IllegalCharacter(c)))
                    })??; // gobble

                let val: u32 = d1 * 100 + d2 * 10 + d3;
                if val > 255 {
                    return Err(LexerError::from(LexerErrorKind::UnrecognizedOctet(val)));
                }
                let ch: char = char::from_u32(val)
                    .ok_or_else(|| LexerError::from(LexerErrorKind::UnrecognizedOctet(val)))?;

                Ok(ch)
            } else {
                // this is an escaped char: \X
                self.txt.next(); // gobble the char
                Ok(ch)
            }
        } else {
            Err(LexerErrorKind::IllegalCharacter(ch).into())
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.txt.peek().copied()
    }
}

struct CowChars<'a> {
    data: Cow<'a, str>,
    offset: usize,
}

impl Iterator for CowChars<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        let mut iter = self.data[self.offset..].char_indices();
        let (_, ch) = iter.next()?; // The returned index is always `0`
        match iter.next() {
            Some((idx, _)) => self.offset += idx,
            None => self.offset = self.data.len(),
        }

        Some(ch)
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum State {
    StartLine,
    RestOfLine,
    Blank,                      // only if the first part of the line
    List,                       // (..)
    CharData { is_list: bool }, // [a-zA-Z, non-control utf8]+
    //  Name,              // CharData + '.' + CharData
    Comment { is_list: bool }, // ;.*
    At,                        // @
    Quote,                     // ".*"
    Dollar,                    // $
    EOL,                       // \n or \r\n
    EOF,
}

/// Tokens emited from each Lexer pass
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Token {
    /// only if the first part of the line
    Blank,
    /// (..) TODO, this is probably wrong, List maybe should just skip line endings
    List(Vec<String>),
    /// [a-zA-Z, non-control utf8, ., -, 0-9]+, ".*"
    CharData(String),
    /// @
    At,
    /// $INCLUDE
    Include,
    /// $ORIGIN
    Origin,
    /// $TTL
    Ttl,
    /// \n or \r\n
    EOL,
}

#[cfg(test)]
mod lex_test {
    use alloc::string::ToString;

    use super::*;

    #[allow(clippy::uninlined_format_args)]
    fn next_token(lexer: &mut Lexer<'_>) -> Option<Token> {
        let result = lexer.next_token();
        assert!(result.is_ok(), "{:?}", result);
        result.unwrap()
    }

    #[test]
    fn blank() {
        // first blank
        let mut lexer = Lexer::new("     dead beef");
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("dead".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("beef".to_string())
        );

        // not the second blank
        let mut lexer = Lexer::new("dead beef");
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("dead".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("beef".to_string())
        );

        let mut lexer = Lexer::new("dead beef\r\n after");
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("dead".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("beef".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("after".to_string())
        );

        let mut lexer = Lexer::new(
            "dead beef ();comment
         after",
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("dead".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("beef".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::List(vec![]));
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("after".to_string())
        );
    }

    #[test]
    fn escape() {
        assert_eq!(
            Lexer::new("a\\Aa").next_token().unwrap().unwrap(),
            Token::CharData("a\\Aa".to_string())
        );
        assert_eq!(
            Lexer::new("a\\$").next_token().unwrap().unwrap(),
            Token::CharData("a\\$".to_string())
        );
        assert_eq!(
            Lexer::new("a\\077").next_token().unwrap().unwrap(),
            // 🔐 R-P2-2：非引号上下文同样解码 \DDD（原实现原样保留是错误行为）
            Token::CharData("aM".to_string())
        );
    }

    #[test]
    fn quoted_txt() {
        assert_eq!(
            Lexer::new("\"Quoted\"").next_token().unwrap().unwrap(),
            Token::CharData("Quoted".to_string())
        );
        assert_eq!(
            Lexer::new("\";@$\"").next_token().unwrap().unwrap(),
            Token::CharData(";@$".to_string())
        );
        assert_eq!(
            Lexer::new("\"some \\A\"").next_token().unwrap().unwrap(),
            Token::CharData("some A".to_string())
        );
        assert_eq!(
            Lexer::new("\"a\\Aa\"").next_token().unwrap().unwrap(),
            Token::CharData("aAa".to_string())
        );
        assert_eq!(
            Lexer::new("\"a\\$\"").next_token().unwrap().unwrap(),
            Token::CharData("a$".to_string())
        );
        assert_eq!(
            Lexer::new("\"a\\077\"").next_token().unwrap().unwrap(),
            // 🔐 R-P2-2：\077 按十进制解码 = 77 = 'M'（原实现错误地按十六进制位权解成 \u{707}）
            Token::CharData("aM".to_string())
        );

        assert!(Lexer::new("\"a\\\"").next_token().is_err());
        assert!(Lexer::new("\"a\\0\"").next_token().is_err());
        assert!(Lexer::new("\"a\\07\"").next_token().is_err());

        let mut lexer = Lexer::new("\"multi\nline\ntext\"");

        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("multi\nline\ntext".to_string())
        );
        assert_eq!(next_token(&mut lexer), None);

        let mut lexer = Lexer::new("\"multi\r\nline\r\ntext\"\r\n");

        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("multi\r\nline\r\ntext".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer), None);

        assert!(Lexer::new("\"multi").next_token().is_err());
    }

    #[test]
    fn unicode() {
        assert_eq!(
            Lexer::new("♥").next_token().unwrap().unwrap(),
            Token::CharData("♥".to_string())
        );
    }

    // fun with tests!!! lots of options
    #[test]
    fn lex() {
        assert_eq!(
            next_token(&mut Lexer::new(".")).unwrap(),
            Token::CharData(".".to_string())
        );
        assert_eq!(
            next_token(&mut Lexer::new("            .")).unwrap(),
            Token::Blank
        );
        assert_eq!(
            next_token(&mut Lexer::new("abc")).unwrap(),
            Token::CharData("abc".to_string())
        );
        assert_eq!(
            next_token(&mut Lexer::new("abc.")).unwrap(),
            Token::CharData("abc.".to_string())
        );
        assert_eq!(next_token(&mut Lexer::new(";abc")), None);
        assert_eq!(next_token(&mut Lexer::new(";;@$-\"")), None);
        assert_eq!(next_token(&mut Lexer::new("@")).unwrap(), Token::At);
        assert_eq!(
            next_token(&mut Lexer::new("123")).unwrap(),
            Token::CharData("123".to_string())
        );
        assert_eq!(
            next_token(&mut Lexer::new("$INCLUDE")).unwrap(),
            Token::Include
        );
        assert_eq!(
            next_token(&mut Lexer::new("$ORIGIN")).unwrap(),
            Token::Origin
        );
        assert_eq!(next_token(&mut Lexer::new("$TTL")).unwrap(), Token::Ttl);
        assert_eq!(next_token(&mut Lexer::new("\n")), Some(Token::EOL));
        assert_eq!(next_token(&mut Lexer::new("\r\n")), Some(Token::EOL));
    }

    #[test]
    fn list() {
        let mut lexer = Lexer::new("(");
        assert!(lexer.next_token().is_err());

        assert!(Lexer::new(")").next_token().is_err());

        let mut lexer = Lexer::new("()");
        assert_eq!(next_token(&mut lexer).unwrap(), Token::List(vec![]));
        assert_eq!(next_token(&mut lexer), None);

        let mut lexer = Lexer::new("(abc)");
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::List(vec!["abc".to_string()])
        );
        assert_eq!(next_token(&mut lexer), None);

        let mut lexer = Lexer::new("(\nabc\n)");
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::List(vec!["abc".to_string()])
        );
        assert_eq!(next_token(&mut lexer), None);

        let mut lexer = Lexer::new("(\nabc\nabc)");
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::List(vec!["abc".to_string(), "abc".to_string()])
        );
        assert_eq!(next_token(&mut lexer), None);

        let mut lexer = Lexer::new("(\nabc;comment\n)");
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::List(vec!["abc".to_string()])
        );
        assert_eq!(next_token(&mut lexer), None);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn soa() {
        let mut lexer = Lexer::new(
            "@   IN  SOA     VENERA      Action\\.domains (
                                 \
                        20     ; SERIAL
                                 7200   ; REFRESH
                                 \
                        600    ; RETRY
                                 3600000; EXPIRE
                                 \
                        60)    ; MINIMUM

        NS      A.ISI.EDU.
        NS      VENERA
        \
                        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA

\
                        A       A       26.3.0.103

VENERA  A       10.1.0.52
        A       \
                        128.9.0.32

$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT",
        );

        assert_eq!(next_token(&mut lexer).unwrap(), Token::At);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("IN".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("SOA".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("VENERA".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("Action\\.domains".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::List(vec![
                "20".to_string(),
                "7200".to_string(),
                "600".to_string(),
                "3600000".to_string(),
                "60".to_string(),
            ])
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("NS".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("A.ISI.EDU.".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("NS".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("VENERA".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("NS".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("VAXA".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("MX".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("10".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("VENERA".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("MX".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("20".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("VAXA".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("A".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("A".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("26.3.0.103".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("VENERA".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("A".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("10.1.0.52".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Blank);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("A".to_string())
        );
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("128.9.0.32".to_string())
        );
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::EOL);
        assert_eq!(next_token(&mut lexer).unwrap(), Token::Include);
        assert_eq!(
            next_token(&mut lexer).unwrap(),
            Token::CharData("<SUBSYS>ISI-MAILBOXES.TXT".to_string())
        );
        assert!(next_token(&mut lexer).is_none());
    }
}
