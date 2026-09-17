#![allow(dead_code)]

use std::fs::File;
use std::io::Write;
use std::{env, path::Path};

#[cfg(target_os = "linux")]
fn build_nftset() -> anyhow::Result<()> {
    let target = env::var("TARGET")?;

    if !target.contains("linux") {
        return Ok(());
    }

    let mut build = cc::Build::new();
    build
        .file("include/nftset.c")
        .static_flag(true)
        .warnings(false);

    build.compile("nftset");

    bindgen::Builder::default()
        .header("include/nftset.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/ffi/nftset_sys.rs")
        .unwrap();

    Ok(())
}

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

    #[cfg(target_os = "linux")]
    build_nftset()?;

    create_build_time_vars()?;
    Ok(())
}
