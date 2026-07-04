use std::sync::Arc;
use anyhow::anyhow;
use serde::Deserialize;
// 🌟 修复：引入读写锁，细化并发粒度
use tokio::sync::RwLock;
use std::sync::LazyLock;

use crate::{
    config::{
        AddressRule, Domain,
        parser::{ConfigFile, ConfigItem, ConfigLine},
    },
    third_ext::serde_str,
};

use super::openapi::{IntoRouter, ToSchema, routes};
use super::{ApiError, DataListPayload, ServeState, StatefulRouter};
use axum::{Json, extract::State, http::StatusCode};

// 🌟 修复：全局异步读写锁，GET 共享，POST/DELETE 排他，防止大粒度阻塞
static CONFIG_FILE_LOCK: LazyLock<RwLock<()>> = LazyLock::new(|| RwLock::new(()));

pub fn routes() -> StatefulRouter {
    routes![list, create, update, delete].into_router()
}

#[utoipa::path(get, path = "/addresses", tag = "Addresses")]
async fn list(State(state): State<Arc<ServeState>>) -> Json<DataListPayload<AddressRule>> {
    // 🌟 抢占共享读锁：多个 GET 请求可完全并发，只有写操作时才会被短暂阻塞
    let _guard = CONFIG_FILE_LOCK.read().await;

    let groups = state
        .app
        .cfg()
        .await
        .rule_groups()
        .get("default")
        .map(|group| group.address_rules.clone())
        .unwrap_or_default();

    Json(groups.into())
}

#[utoipa::path(post, path = "/addresses", tag = "Addresses")]
async fn create(
    State(state): State<Arc<ServeState>>,
    Json(input): Json<CreateAddressRule>,
) -> Result<StatusCode, ApiError> {
    let rule = input.rule;
    let cfg = state.app.cfg().await;
    let Some(managed_dir) = cfg.managed_dir() else {
        return Err(ApiError::NotFound("managed_dir not found".to_string()));
    };

    // 🌟 抢占排他写锁：写入期间，其他读写请求全部等待
    let _guard = CONFIG_FILE_LOCK.write().await;

    if !managed_dir.exists() {
        // 🌟 修复 1：全面替换为 tokio::fs 异步 I/O
        tokio::fs::create_dir_all(&managed_dir).await?;
    }
    let file = managed_dir.join("address.conf");
    
    if file.exists() {
        let text = tokio::fs::read_to_string(&file).await?;
        let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

        let rules = config
            .iter()
            .enumerate()
            .flat_map(|(i, c)| match c {
                ConfigLine::Config {
                    config: ConfigItem::Address(rule),
                    ..
                } => Some((i, rule.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

        let idx = rules
            .iter()
            .find(|r| r.1.domain == rule.domain)
            .map(|(i, _)| *i);

        if idx.is_some() {
            return Err(anyhow!("address already exists"))?;
        } else {
            config.push(ConfigLine::Config {
                config: ConfigItem::Address(rule),
                comment: None,
            });
        };

        safe_write_config(&file, format!("{config}")).await?;
    } else {
        let config = ConfigItem::Address(rule);
        safe_write_config(&file, format!("{config}")).await?;
    }

    Ok(StatusCode::CREATED)
}

#[utoipa::path(put, path = "/addresses", tag = "Addresses")]
async fn update() {}

#[utoipa::path(delete, path = "/addresses", tag = "Addresses")]
async fn delete(
    State(state): State<Arc<ServeState>>,
    Json(input): Json<DeleteAddressRule>,
) -> Result<StatusCode, ApiError> {
    let domain = input.domain;

    let cfg = state.app.cfg().await;
    let Some(managed_dir) = cfg.managed_dir() else {
        return Err(ApiError::NotFound("managed_dir not found".to_string()));
    };

    // 🌟 抢占排他写锁：写入期间，其他读写请求全部等待
    let _guard = CONFIG_FILE_LOCK.write().await;

    if !managed_dir.exists() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }
    let file = managed_dir.join("address.conf");
    if !file.exists() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }

    // 🌟 替换为异步 I/O
    let text = tokio::fs::read_to_string(&file).await?;
    let (_, mut config) = ConfigFile::parse(&text).map_err(|err| err.to_owned())?;

    let idx = config
        .iter()
        .enumerate()
        .flat_map(|(i, c)| match c {
            ConfigLine::Config {
                config: ConfigItem::Address(rule),
                ..
            } if rule.domain == domain => Some(i),
            _ => None,
        })
        .collect::<Vec<_>>();

    if idx.is_empty() {
        return Err(ApiError::NotFound(format!("Domain {domain} not found")));
    }

    for i in idx.iter().rev() {
        config.remove(*i);
    }

    safe_write_config(&file, format!("{config}")).await?;

    Ok(StatusCode::NO_CONTENT)
}

// 🌟 核心修复：原子化配置文件写入，杜绝断电/强杀导致的配置清零问题
async fn safe_write_config(file: &std::path::Path, content: String) -> std::io::Result<()> {
    // 先写到临时的 .tmp 文件中
    let tmp_file = file.with_extension("tmp");
    tokio::fs::write(&tmp_file, content).await?;
        
    // 操作系统级原子重命名，只有写入完全成功后才会瞬间覆盖原文件
    tokio::fs::rename(&tmp_file, file).await?;
    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
struct CreateAddressRule {
    rule: AddressRule,
}

#[derive(Debug, Deserialize, ToSchema)]
struct DeleteAddressRule {
    #[serde(with = "serde_str")]
    #[schema(value_type = String)]
    domain: Domain,
}
