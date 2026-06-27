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
    std::fs::create_dir_all("./logs")?;

    #[cfg(target_os = "linux")]
    build_nftset()?;

    create_build_time_vars()?;
    Ok(())
}
