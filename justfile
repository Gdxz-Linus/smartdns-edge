cargo := if env_var_or_default('USE_CROSS', 'false') == "true" { "cross" } else { "cargo" }

alias b := build
alias c := clippy
alias t := test
alias pack := package

set positional-arguments

name := "smartdns"
target := `rustc -vV | grep host | cut -d ' ' -f2`

version := `grep -m1 '^version' Cargo.toml | cut -d '"' -f2`

diagnostic := ""
bin_name := if os_family() == "windows" { name + ".exe" } else { name }
dist_dir := "dist"
dist_name := name + "-" + target
dist_zip := if os() == "windows" { dist_name + "-v" + version + ".zip" } else if os() == "macos" { dist_name + "-v" + version + ".zip" } else { dist_name + "-v" + version + ".tar.gz" }


#------------#
# versioning #
#------------#

# Increment manifest version: major, minor, patch, rc, beta, alpha
bump +args: require_set-version
  @cargo set-version --bump {{args}}

# Print current version
version:
  @echo "{{version}}"


#----------#
# building #
#----------#

# Build
build *args: patch
  #!/usr/bin/env sh
  if [ ! -z {{diagnostic}} ] ; then
    echo "{{cargo}} build --features "future-diagnostic" {{args}}"
    RUSTFLAGS="--cfg tokio_unstable" {{cargo}} build --features "future-diagnostic" {{args}}
  else
    echo "{{cargo}} build {{args}}"
    {{cargo}} build {{args}}
  fi

# 🌟 彻底干掉了 Windows 生成 msi 的 wix 模块，现在是纯净的绿色软件！

# Publish to Crates.io
publish *args: patch
  {{cargo}} publish --no-verify

# Package the binary for distribution
[unix]
package: patch package-clean package-prepare && zip package-list
  cp target/{{target}}/release/{{bin_name}}  {{dist_dir}}/{{dist_name}}


# Package the binary for distribution
[windows]
# 🌟 彻底去除了依赖链里的 wix
package: patch package-clean package-prepare && zip package-list
  cp target/{{target}}/release/{{bin_name}}  {{dist_dir}}/{{dist_name}}

[private]
package-prepare:
  @mkdir -p {{dist_dir}}/{{dist_name}}
  cp LICENSE README*.md etc/smartdns/smartdns.conf  {{dist_dir}}/{{dist_name}} || true
  echo "Version: {{version}}" >  {{dist_dir}}/{{dist_name}}/version
  echo "Build date: $(date)" >>  {{dist_dir}}/{{dist_name}}/version
  echo "Branch: $(git rev-parse --abbrev-ref HEAD)" >>  {{dist_dir}}/{{dist_name}}/version
  echo "Commit: $(git rev-parse HEAD)" >>  {{dist_dir}}/{{dist_name}}/version

[private]
package-clean:
  @rm -rf  {{dist_dir}}/{{dist_name}}*

[private]
package-list:
  @ls -lh dist


[private]
[windows]
zip: && zip-sha256sum
  cd {{dist_dir}} && 7z a -tzip {{dist_zip}} {{dist_name}}

[private]
[macos]
zip: && zip-sha256sum
  cd {{dist_dir}} && zip -9r {{dist_zip}} {{dist_name}}

[private]
[linux]
zip: && zip-sha256sum
  cd {{dist_dir}} && tar -zcvf {{dist_zip}} {{dist_name}}

[private]
zip-sha256sum:
  echo {{sha256_file(dist_dir + "/" + dist_zip)}} > {{dist_dir}}/{{dist_zip}}-sha256sum.txt

# cleanup the workspace
clean:
   cargo clean


#---------------#
# running tests #
#---------------#

# Run tests
test *args: patch
  {{cargo}} test {{args}}


#-----------------------#
# code quality and misc #
#-----------------------#

# Analyze the package and report errors, but don't build object files
check *args: patch
  {{cargo}} check --workspace --tests --benches --examples {{args}}

# Run clippy fix
clippy: patch
  {{cargo}} clippy --fix --all

# Format the code
fmt: patch
  {{cargo}} fmt --all

# Check the clippy and format.
cleanliness: patch
  cargo clippy
  cargo fmt --all -- --check


#-------#
# tools #
#-------#

# Set cap for smartdns binary
setcap:
  sudo find ./target -type f -name smartdns -exec setcap CAP_SYS_ADMIN,CAP_NET_ADMIN,CAP_NET_RAW,CAP_NET_BIND_SERVICE+eip  {} \;
  @find ./target -type f -name smartdns


# Apply patch
[private]
patch: # require_patch-crate
  @#cargo patch-crate -f

#------------#
# dependency #
#------------#

[private]
@require_patch-crate:
  cargo patch-crate --version >/dev/null 2>&1 || cargo install patch-crate

[private]
@require_set-version:
  cargo set-version --version >/dev/null 2>&1 || cargo install cargo-edit > /dev/null
