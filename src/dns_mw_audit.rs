use std::io;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use chrono::prelude::*;
use tokio::sync::mpsc::{self, Sender};

use crate::dns::*;
use crate::infra::mapped_file::MappedFile;
use crate::libdns::proto::op::Query;
use crate::log::warn;
use crate::middleware::*;

pub struct DnsAuditMiddleware {
    audit_sender: Sender<DnsAuditRecord>,
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsAuditMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let now = Local::now();

        let start = Instant::now();

        let res = next.run(ctx, req).await;

        let duration = start.elapsed();

        let audit = DnsAuditRecord {
            id: req.id(),
            date: now,
            client: req.src().to_string(),
            query: req.query().original().to_owned(),
            result: res.clone(),
            elapsed: duration,
            speed: ctx.fastest_speed,
            lookup_source: ctx.source.clone(),
        };

        // debug!("{}", audit.to_string_without_date());

        // 🌟 核心修复 1：绝不阻塞主业务！如果管道满了直接丢弃日志，保全 DNS 解析性能。
        if let Err(err) = self.audit_sender.try_send(audit) {
            crate::log::trace!("Audit channel full or closed, dropping log: {}", err);
        }

        res
    }
}

impl DnsAuditMiddleware {
    /// `console` = 🔐 Q9：审计行同时打到控制台（stdout）。
    /// `syslog` = 🔐 Q8：审计改送系统日志（**不再写文件**、行首不带时间戳，与 C 版一致）。
    pub fn new<P: AsRef<Path>>(
        path: P,
        audit_size: u64,
        audit_num: usize,
        mode: Option<u32>,
        console: bool,
        syslog: bool,
    ) -> Self {
        let audit_file = path.as_ref().to_owned();
        
        // 🌟 扩大缓冲池，配合 try_send 吸收突发流量
        let (audit_tx, mut audit_rx) = mpsc::channel::<DnsAuditRecord>(1024);

        tokio::spawn(async move {
            // 🔐 P3：先把审计档的目录准备好 —— 同上，不再依赖"构建时顺手建出来的 ./logs"。
            if let Err(err) = crate::infra::mapped_file::ensure_parent_dir(&audit_file) {
                crate::log::error!(
                    "审计档所在目录建不出来（{}）：{err}；本次审计可能写不进文件",
                    audit_file.display()
                );
            }
            let mut audit_file = MappedFile::open(audit_file, audit_size, Some(audit_num), mode);
            const BUF_SIZE: usize = 10;
            // 改用 Vec 方便利用 std::mem::replace 进行内存腾挪
            let mut buf: Vec<DnsAuditRecord> = Vec::with_capacity(BUF_SIZE);
            
            // 🌟 核心修复 2：加入定时器，每 3 秒强制刷新一次，拒绝“日志黑洞”
            let mut flush_interval = tokio::time::interval(Duration::from_secs(3));

            loop {
                tokio::select! {
                    _ = flush_interval.tick() => {
                        if !buf.is_empty() {
                            let records_to_write = std::mem::replace(&mut buf, Vec::with_capacity(BUF_SIZE));
                            
                            // 🌟 核心修复 1：把 block_in_place 替换为 spawn_blocking。
                            // 相当于给写磁盘开辟了一条专属的“系统辅道”，绝不霸占 Tokio 的高速主干道！
                            // 利用 Rust 的 Move 语义将文件句柄带进辅道，写完再带出来，完美绕过借用检查。
                            audit_file = tokio::task::spawn_blocking(move || {
                                if syslog {
                                    // 🔐 Q8：改送系统日志（C 版 `audit.c:145-166` 也是"送 syslog 就不写文件"）
                                    write_audit_to_syslog(&records_to_write, console);
                                } else if let Err(err) = record_audit_to_file(&mut audit_file, &records_to_write, console) {
                                    warn!("log audit failed {}", err);
                                }
                                audit_file // 活干完了，把文件句柄交还给主循环
                            }).await.unwrap();
                        }
                    }
                    msg = audit_rx.recv() => {
                        match msg {
                            Some(audit) => {
                                buf.push(audit);
                                if buf.len() >= BUF_SIZE {
                                    let records_to_write = std::mem::replace(&mut buf, Vec::with_capacity(BUF_SIZE));
                                    
                                    // 🌟 核心修复 2：同上，转移至系统辅道执行磁盘 I/O
                                    audit_file = tokio::task::spawn_blocking(move || {
                                        if syslog {
                                            write_audit_to_syslog(&records_to_write, console);
                                        } else if let Err(err) = record_audit_to_file(&mut audit_file, &records_to_write, console) {
                                            warn!("log audit failed {}", err);
                                        }
                                        audit_file
                                    }).await.unwrap();
                                }
                            }
                            None => break, // 通道关闭，安全退出
                        }
                    }
                }
            }
        });

        Self {
            audit_sender: audit_tx,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsAuditRecord {
    id: u16,
    client: String,
    query: Query,
    result: Result<DnsResponse, DnsError>,
    speed: Duration,
    elapsed: Duration,
    date: DateTime<Local>,
    lookup_source: LookupFrom,
}

impl DnsAuditRecord {
    fn fmt_result(&self) -> String {
        if let Ok(lookup) = self.result.as_ref() {
            let mut out = String::new();

            for (i, record) in lookup
                .records()
                .iter()
                // .filter(|r| r.data().is_some())
                .enumerate()
            {
                let data = record.data();

                if i > 0 {
                    out.push('|');
                }

                out.push_str(data.to_string().as_str());

                out.push(' ');
                out.push_str(record.ttl().to_string().as_str());
                out.push(' ');
                out.push_str(record.record_type().to_string().as_str());
            }
            out
        } else {
            "query failed".to_string()
        }
    }

    fn to_string_without_date(&self) -> String {
        format!(
            "{} query {}, type: {}, elapsed: {:?}, speed: {:?}, result {}",
            self.client,
            self.query.name(),
            self.query.query_type(),
            self.elapsed,
            self.speed,
            self.fmt_result()
        )
    }
}

impl std::fmt::Display for DnsAuditRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} query {}, type: {}, elapsed: {:?}, speed: {:?}, result {}",
            self.date.format("%Y-%m-%d %H:%M:%S,%3f"),
            self.client,
            self.query.name(),
            self.query.query_type(),
            self.elapsed,
            self.speed,
            self.fmt_result()
        )
    }
}

/// 🔐 Q8 `audit-syslog`：把审计行送系统日志。
///
/// 与 C 版一致的两点（`src/dns_server/audit.c:145-157`）：
/// ① 用**不带时间戳**的行（`to_string_without_date`）—— 系统日志自己会加时间；
/// ② 开着的时候**不写审计文件**（调用方负责不再写）。
/// 另外保留 `audit-console` 那一路（用户两个都开就两个都出）。
fn write_audit_to_syslog(records: &[DnsAuditRecord], console: bool) {
    for audit in records {
        let line = audit.to_string_without_date();
        crate::log::audit_to_syslog(&line);

        if console {
            println!("{line}");
        }
    }
}

fn record_audit_to_file(
    audit_file: &mut MappedFile,
    audit_records: &[DnsAuditRecord],
    console: bool,
) -> io::Result<()> {
    // 🔐 Q9 `audit-console`：审计行**同时**打到控制台。
    // 放在落盘之前 —— 文件写不进去也不影响"在屏幕上看得见"这件事。
    if console {
        use std::io::Write;

        let mut out = io::stdout();
        for audit in audit_records {
            let _ = writeln!(out, "{audit}");
        }
        let _ = out.flush();
    }

    if matches!(audit_file.extension(), Some(ext) if ext == "csv") {
        // write as csv

        if audit_file.peamble().is_none() {
            let mut writer = csv::Writer::from_writer(vec![]);
            writer.write_record([
                "id",
                "timestamp",
                "client",
                "name",
                "type",
                "elapsed",
                "speed",
                "state",
                "result",
                "lookup_source",
            ])?;

            audit_file.set_peamble(Some(
                writer
                    .into_inner()
                    .expect("read csv peamble")
                    .into_boxed_slice(),
            ))
        }

        let mut writer = csv::Writer::from_writer(audit_file);

        for audit in audit_records {
            writer.write_record([
                audit.id.to_string().as_str(),
                audit.date.timestamp().to_string().as_str(),
                audit.client.as_str(),
                audit.query.name().to_string().as_str(),
                audit.query.query_type().to_string().as_str(),
                format!("{:?}", audit.elapsed).as_str(),
                format!("{:?}", audit.speed).as_str(),
                if audit.result.is_ok() {
                    "success"
                } else {
                    "failed"
                },
                audit.fmt_result().as_str(),
                format!("{:?}", audit.lookup_source).as_str(),
            ])?;
        }
    } else {
        // write as nornmal log format.
        for audit in audit_records {
            if writeln!(audit_file, "{audit}").is_err() {
                warn!("Write audit to file '{:?}' failed", audit_file.path());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::libdns::proto::op::Query;
    use crate::libdns::proto::rr::{RData, RecordType};
    use std::io::Read;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_dns_audit_to_string() {
        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();
        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);
        let result = Ok(DnsResponse::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let audit = DnsAuditRecord {
            id: 11,
            date: now,
            client: "127.0.0.1".to_string(),
            query,
            result,
            elapsed: Duration::from_millis(10),
            speed: Duration::from_millis(11),
            lookup_source: LookupFrom::Server("default".to_string()),
        };

        assert_eq!(
            audit.to_string(),
            format!(
                "[{}] 127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34 86400 A",
                now.format("%Y-%m-%d %H:%M:%S,%3f")
            )
        );
    }

    #[test]
    fn test_dns_audit_to_string_without_date() {
        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();

        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);
        let result = Ok(DnsResponse::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let audit = DnsAuditRecord {
            id: 11,
            date: now,
            client: "127.0.0.1".to_string(),
            query,
            result,
            elapsed: Duration::from_millis(10),
            speed: Duration::from_millis(11),
            lookup_source: LookupFrom::Server("default".to_string()),
        };

        assert_eq!(
            audit.to_string_without_date(),
            "127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34 86400 A"
        );
    }


    /// 🔐 Q9：开了 `audit-console` 之后，审计**照样**要落到文件里
    /// （控制台那半走 stdout，单测里只看"文件这半没被搞坏"）。
    #[test]
    fn test_audit_console_still_writes_file() {
        let dir = std::env::temp_dir().join("smartdns_audit_console_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("audit_console.log");
        let _ = std::fs::remove_file(&file);

        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);
        let result = Ok(DnsResponse::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));
        let audit = DnsAuditRecord {
            id: 11,
            date: "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap(),
            client: "127.0.0.1".to_string(),
            query,
            result,
            elapsed: Duration::from_millis(10),
            speed: Duration::from_millis(11),
            lookup_source: LookupFrom::Server("default".to_string()),
        };
        let file = Path::new(file.as_path());

        record_audit_to_file(
            &mut MappedFile::open(file, 102400, None, Default::default()),
            &[audit],
            true,
        )
        .unwrap();

        let content = std::fs::read_to_string(file).unwrap();
        assert!(
            content.contains("www.example.com"),
            "开了控制台输出后，文件里仍应有这条审计：{content}"
        );
    }

    #[test]
    fn test_record_audit_to_file() {
        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);

        let result = Ok(DnsResponse::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let now = "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap();

        let audit = DnsAuditRecord {
            id: 11,
            date: now,
            client: "127.0.0.1".to_string(),
            query,
            result,
            elapsed: Duration::from_millis(10),
            speed: Duration::from_millis(11),
            lookup_source: LookupFrom::Server("default".to_string()),
        };

        // 🔐 P3-14：这里原来写 `./logs/...` —— 那是**依赖 build.rs 在源码树里建出来的目录**
        // （构建副作用）。改用系统临时目录，测试才和"构建时建了什么目录"无关。
        let file = std::env::temp_dir().join(format!(
            "smartdns-audit-{}-{}.log",
            std::process::id(),
            Local::now().timestamp_millis()
        ));
        let file = Path::new(file.as_path());

        record_audit_to_file(
            &mut MappedFile::open(file, 102400, None, Default::default()),
            &[audit],
            false,
        )
        .unwrap();

        assert!(file.exists());

        let mut s = String::new();

        std::fs::File::open(file)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();

        assert_eq!(
            s,
            format!(
                "[{}] 127.0.0.1 query www.example.com, type: A, elapsed: 10ms, speed: 11ms, result 93.184.216.34 86400 A\n",
                now.format("%Y-%m-%d %H:%M:%S,%3f")
            )
        );

        std::fs::remove_file(file).unwrap();

        assert!(!file.exists());
    }

    #[test]
    fn test_record_audit_to_csv_file() {
        let query = Query::query(Name::from_str("www.example.com").unwrap(), RecordType::A);

        let result = Ok(DnsResponse::from_rdata(
            query.to_owned(),
            RData::A("93.184.216.34".parse().unwrap()),
        ));

        let audit1 = DnsAuditRecord {
            id: 11,
            date: "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap(),
            client: "127.0.0.1".to_string(),
            query: query.clone(),
            result: result.clone(),
            elapsed: Duration::from_millis(10),
            speed: Duration::from_millis(11),
            lookup_source: LookupFrom::Server("default1".to_string()),
        };

        let audit2 = DnsAuditRecord {
            id: 12,
            date: "2022-11-11 20:18:11.099966887 +08:00".parse().unwrap(),
            client: "127.0.0.1".to_string(),
            query,
            result,
            elapsed: Duration::from_millis(10),
            speed: Duration::from_millis(11),
            lookup_source: LookupFrom::Server("default2".to_string()),
        };

        // 🔐 P3-14：同上 —— 别依赖构建时建出来的 ./logs，用系统临时目录
        let file = std::env::temp_dir().join(format!(
            "smartdns-audit-{}-{}.csv",
            std::process::id(),
            Local::now().timestamp_millis()
        ));
        let file = Path::new(file.as_path());

        record_audit_to_file(
            &mut MappedFile::open(file, 102400, None, Default::default()),
            &[audit1],
            false,
        )
        .unwrap();

        assert!(file.exists());

        let mut s = String::new();

        std::fs::File::open(file)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();

        assert_eq!(
            s,
            "id,timestamp,client,name,type,elapsed,speed,state,result,lookup_source\n11,1668169091,127.0.0.1,www.example.com,A,10ms,11ms,success,93.184.216.34 86400 A,Server: default1\n"
        );

        record_audit_to_file(
            &mut MappedFile::open(file, 102400, None, Default::default()),
            &[audit2],
            false,
        )
        .unwrap();

        let mut s = String::new();

        std::fs::File::open(file)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();

        assert_eq!(
            s,
            "id,timestamp,client,name,type,elapsed,speed,state,result,lookup_source\n11,1668169091,127.0.0.1,www.example.com,A,10ms,11ms,success,93.184.216.34 86400 A,Server: default1\n12,1668169091,127.0.0.1,www.example.com,A,10ms,11ms,success,93.184.216.34 86400 A,Server: default2\n"
        );

        std::fs::remove_file(file).unwrap();

        assert!(!file.exists());
    }
}
