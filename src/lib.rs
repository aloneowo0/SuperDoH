use worker::{Context, Env, Request, Response, Result, Router, event};

pub mod algo;
pub mod config;
pub mod dns;
pub mod http;
pub mod policy;

/// Routes one Worker fetch request through the public endpoint layer.
///
/// # Errors
///
/// Returns a Worker error when request cloning, route dispatch, or a handler fails.
#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    match fetch_inner(req, env).await {
        Ok(response) => Ok(response),
        Err(error) => {
            worker::console_error!("request handling failed: {error}");
            Response::error("Internal Server Error", 500)
        }
    }
}

async fn fetch_inner(req: Request, env: Env) -> Result<Response> {
    let state = http::AppState::from_env(&env);
    let Some(internal_path) = http::internal_path(&req.path(), &state.entrance) else {
        return http::fallback(req, &state).await;
    };
    let mut routed_request = req.clone_mut()?;
    *routed_request.path_mut()? = internal_path;

    Router::with_data(state)
        .on_async("/", |req, route| async move {
            http::home::serve(req, &route.data.runtime, &route.data.entrance, false)
        })
        .on_async("/index.html", |req, route| async move {
            http::home::serve(req, &route.data.runtime, &route.data.entrance, false)
        })
        .on_async("/en", |req, route| async move {
            http::home::serve(req, &route.data.runtime, &route.data.entrance, true)
        })
        .on_async("/health", |_req, route| async move {
            http::health::serve(&route.data.runtime)
        })
        .on_async("/config.json", |_req, route| async move {
            http::config_json::serve(&route.data.runtime)
        })
        .on_async("/css/style.css", |_req, _route| async move {
            http::home::stylesheet()
        })
        .on_async("/js/resolver.js", |_req, _route| async move {
            http::home::resolver_script()
        })
        .on_async("/js/config-wizard.js", |_req, _route| async move {
            http::home::wizard_script()
        })
        .on_async("/dns-query", |req, route| async move {
            http::doh::serve(req, &route.data).await
        })
        .or_else_any_method_async("/*path", |req, route| async move {
            http::fallback(req, &route.data).await
        })
        .run(routed_request, env)
        .await
}
