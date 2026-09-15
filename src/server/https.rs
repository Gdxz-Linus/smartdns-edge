use axum::extract::Request;
use http::{HeaderValue, header};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server,
};
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc};
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tower::{Service as _, ServiceBuilder, ServiceExt};
use tower_http::set_header::SetResponseHeaderLayer;

use tokio_rustls::TlsAcceptor;

use super::{DnsHandle, reap_tasks, sanitize_src_address};

use crate::{
    api::ServeState,
    app::App,
    log,
    rustls::{ResolvesServerCert, tls_server_config},
};

pub fn serve(
    app: App,
    listener: net::TcpListener,
    dns_handle: DnsHandle,
    api_enabled: bool,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    h3_port: Option<u16>,
) -> io::Result<CancellationToken> {
    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    log::debug!("HTTPS listener successfully registered on {}", listener.local_addr().unwrap());

    let tls_config = tls_server_config(b"h2", server_cert_resolver)
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let state = Arc::new(ServeState { app, dns_handle });

    let service_builder = ServiceBuilder::new().option_layer(h3_port.map(|port| {
        let alt_svc = format!(r#"h3=":{port}"; h3-29=":{port}"; ma=86400"#);
        SetResponseHeaderLayer::overriding(
            header::ALT_SVC,
            HeaderValue::from_str(alt_svc.as_str()).expect("invalid header value"), // TODO: handle error better?
        )
    }));

    let make_service = (if api_enabled {
        crate::api::routes()
    } else {
        crate::api::dns_only_routes()
    })
        .layer(service_builder)
        .with_state(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();

    tokio::spawn(async move {
        // 🔐 逐监听连接上限（若该监听单独配了 max-connections*，与全局限额同时生效）
        let listener_limiter = listener
            .local_addr()
            .ok()
            .and_then(crate::server::limit::for_listener);

        let mut inner_join_set = JoinSet::new();
        loop {
            let (tcp_stream, src_addr) = tokio::select! {
                tcp_stream = listener.accept() => match tcp_stream {
                    Ok((t, s)) => (t, s),
                    Err(e) => {
                        log::debug!("error receiving TLS tcp_stream error: {}", e);
                        continue;
                    },
                },
                _ = cancellation_token.cancelled() => {
                    // A graceful shutdown was initiated. Break out of the loop.
                    break;
                },
            };

            // verify that the src address is safe for responses
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!(
                    "address can not be responded to {src_addr}: {e}",
                    src_addr = src_addr,
                    e = e
                );
                continue;
            }

            // 🔐 P0-5：连接数上限。超出预算就拒绝新连接（不影响已有连接），保护进程内存。
            // 默认上限按物理内存自动推算：家庭小机器自动收紧，企业大机器自动放宽。
            let Some(conn_guard) = crate::server::limit::global().acquire(src_addr.ip()) else {
                log::debug!("连接数超出上限，拒绝 {src_addr} 的新连接");
                continue;
            };

            // 🔐 该监听自身（若单独配置过）的限额也要通过
            let listener_guard = match listener_limiter.as_ref() {
                Some(l) => match l.acquire(src_addr.ip()) {
                    Some(guard) => Some(guard),
                    None => {
                        log::debug!("该监听连接数超限，拒绝 {src_addr} 的新连接");
                        continue;
                    }
                },
                None => None,
};

            let tls_acceptor = tls_acceptor.clone();

            // kick out to a different task immediately, let them do the TLS handshake
            let mut make_service = make_service.clone();
            inner_join_set.spawn(async move {
                let _conn_guard = conn_guard; // 连接结束时自动归还配额
                    let _listener_guard = listener_guard;
                log::debug!("starting HTTPS request from: {}", src_addr);

                // perform the TLS
                // 🌟 核心修复：同理，防 DoH 的慢速连接死锁
                let tls_stream = tokio::time::timeout(
                    std::time::Duration::from_secs(5), 
                    tls_acceptor.accept(tcp_stream)
                ).await;

                let socket = match tls_stream {
                    Ok(Ok(tls_stream)) => tls_stream,
                    Ok(Err(e)) => {
                        log::debug!("https handshake src: {} error: {}", src_addr, e);
                        return;
                    }
                    Err(_) => {
                        log::debug!("https handshake src: {} timeout (dropped)", src_addr);
                        return;
                    }
                };
                log::debug!("accepted HTTPS request from: {}", src_addr);

                let tower_service = unwrap_infallible(make_service.call(src_addr).await);

                let hyper_service =
                    hyper::service::service_fn(move |request: Request<Incoming>| {
                        tower_service.clone().oneshot(request)
                    });

                let socket = TokioIo::new(socket);

                if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
                    .http2()
                    .enable_connect_protocol()
                    .serve_connection_with_upgrades(socket, hyper_service)
                    .await
                {
                    eprintln!("failed to serve connection: {err:#}");
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    Ok(token)
}

fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => match err {},
    }
}
