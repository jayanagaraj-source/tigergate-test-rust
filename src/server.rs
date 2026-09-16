//! Minimal hyper server that wires untrusted request data (sources) into the
//! vulnerable functions (sinks) so taint-tracking SAST engines have real flows.
//! Also exercises hyper 0.14.9 / tokio 1.8.0 (SCA reachability).

use crate::app;
use crate::sast::{crypto, filesystem, injection, misc, network};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use rusqlite::Connection;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;

fn query_params(req: &Request<Body>) -> HashMap<String, String> {
    req.uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            Some((it.next()?.to_string(), it.next().unwrap_or("").to_string()))
        })
        .collect()
}

fn respond(status: StatusCode, body: String) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    for (k, v) in network::cors_headers() {
        builder = builder.header(k, v);
    }
    builder.body(Body::from(body)).unwrap()
}

async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let params = query_params(&req);
    let p = |k: &str| params.get(k).cloned().unwrap_or_default();

    let resp = match req.uri().path() {
        "/login" => {
            if app::login_with_audit(&p("user"), &p("pass")) {
                respond(StatusCode::OK, format!("session={}", crypto::generate_session_id(&p("user"))))
            } else {
                respond(StatusCode::UNAUTHORIZED, "invalid credentials".into())
            }
        }
        "/greet" => respond(StatusCode::OK, injection::render_greeting(&p("name"))),
        "/ping" => match injection::ping_host(&p("host")) {
            Ok(out) => respond(StatusCode::OK, out),
            Err(e) => respond(StatusCode::INTERNAL_SERVER_ERROR, misc::error_response(&e)),
        },
        "/user" => {
            let conn = Connection::open("app.db").unwrap();
            match injection::find_user_email(&conn, &p("username")) {
                Ok(emails) => respond(StatusCode::OK, emails.join("\n")),
                Err(e) => respond(StatusCode::INTERNAL_SERVER_ERROR, misc::error_response(&e)),
            }
        }
        "/file" => match filesystem::read_upload(&p("name")) {
            Ok(body) => respond(StatusCode::OK, body),
            Err(e) => respond(StatusCode::NOT_FOUND, misc::error_response(&e)),
        },
        "/fetch" => match network::fetch_url(&p("url")) {
            Ok(body) => respond(StatusCode::OK, body),
            Err(e) => respond(StatusCode::BAD_GATEWAY, misc::error_response(&e)),
        },
        "/search" => {
            injection::log_search(&p("q"));
            let hit = injection::user_regex_match(&p("pattern"), &p("q"));
            respond(StatusCode::OK, hit.to_string())
        }
        "/decode" => respond(
            StatusCode::OK,
            String::from_utf8_lossy(&misc::decode_base64(&p("data"))).into_owned(),
        ),
        "/redirect" => Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", p("next"))
            .body(Body::empty())
            .unwrap(),
        "/debug/env" => respond(StatusCode::OK, format!("{:#?}", std::env::vars().collect::<Vec<_>>())),
        _ => respond(StatusCode::NOT_FOUND, "not found".into()),
    };
    Ok(resp)
}

pub async fn run(addr: &str) -> Result<(), hyper::Error> {
    let addr: SocketAddr = addr.parse().expect("listen address");
    let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle)) });
    Server::bind(&addr).serve(make_svc).await
}
