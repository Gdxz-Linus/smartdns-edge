#![allow(dead_code)]

use std::fs::File;
use std::io::Write;
use std::{env, path::Path};

fn create_build_time_vars() -> anyhow::Result<()> {
    let target_dir = env::var_os("OUT_DIR").unwrap();
    let target_dir = Path::new(&target_dir);
    let build_file = target_dir.join("build_time_vars.rs");
    let mut file = File::create(build_file)?;
    let build_timestamp = chrono::Utc::now().timestamp_millis();
    writeln!(
        file,
        r#"pub const BUILD_DATE: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_timestamp_millis({build_timestamp}).unwrap();"#
    )?;

    writeln!(
        file,
        r#"pub const BUILD_TARGET: &str = "{}";"#,
        env::var("TARGET").unwrap()
    )?;

    writeln!(
        file,
        r#"pub const BUILD_VERSION: &str = "{}";"#,
        env::var("CARGO_PKG_VERSION").unwrap()
    )?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // 🔐 P3：这里原来会 `create_dir_all("./logs")` —— 等于"构建时在源码树里建目录"。
    // 源码树只读（发行版打包、Docker/容器里编译）时连构建都过不去；而且这个目录跟运行期
    // 真正需要的"日志文件所在目录"根本不是一回事。
    // 现在改成由运行期负责：`src/log.rs` 打开日志文件前先把它的目录准备好，并如实报告失败。

    // 🔐 B-②（2026-09-26）：这里原来在 Linux 上执行 `build_nftset()` ——
    // 用 `cc` 编译 `include/nftset.c`、再用 `bindgen` 生成 `src/ffi/nftset_sys.rs`。
    // nftset 已改写为**纯 Rust**（`src/ffi/nftset.rs`），于是：
    //   · 不再需要 C 编译器与 libclang（发行版打包 / Docker / 交叉编译都跟着减负）；
    //   · 不再有"构建时往源码树写文件"这个副作用（与上面 P3 修掉的是同一类问题）。
    // 因此本文件不再依赖 cc / bindgen。

    create_build_time_vars()?;
    Ok(())
}
