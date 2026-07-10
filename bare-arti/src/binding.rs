//! Bare native-addon glue (in-process backend).
//!
//! Compiled only under `--features bare` (via bare-make with cmake-cargo), so it
//! never affects the plain `cargo build` that verifies the Tor core. It owns a
//! multi-thread tokio runtime, bootstraps the embedded client once, starts the
//! SOCKS proxy, and hands the bound port back to JS as `start()` / `stop()`.
//!
//! NOTE: this layer targets the bare-rust addon API and is built/run on a real
//! Bare target (see CMakeLists.txt + CI prebuilds); it is not exercised by the
//! cargo-based verification in this repo. The sidecar backend in index.js is the
//! portable, already-verified path.

use std::sync::Mutex;

use bare_rust::{bare_exports, Env, Function, Object, Value};
use tokio::runtime::Runtime;

struct Embedded {
    _runtime: Runtime,
    handle: tokio::task::JoinHandle<()>,
    port: u16,
}

static STATE: Mutex<Option<Embedded>> = Mutex::new(None);

bare_exports!(bare_arti_exports, |env| {
    let exports = Object::new(&env)?;

    let start = Function::new(&env, |env, _args| {
        let mut guard = STATE.lock().unwrap();
        if guard.is_none() {
            let runtime = Runtime::new().map_err(anyhow_to_js)?;
            let (port, handle) = runtime
                .block_on(async {
                    let client = crate::bootstrap().await?;
                    crate::serve_socks(client, "127.0.0.1").await
                })
                .map_err(anyhow_to_js)?;
            *guard = Some(Embedded {
                _runtime: runtime,
                handle,
                port,
            });
        }
        let port = guard.as_ref().unwrap().port;
        Ok(Value::from_u32(&env, port as u32)?)
    })?;
    exports.set_named_property("start", start)?;

    let stop = Function::new(&env, |env, _args| {
        if let Some(state) = STATE.lock().unwrap().take() {
            state.handle.abort();
        }
        Ok(Value::undefined(&env)?)
    })?;
    exports.set_named_property("stop", stop)?;

    Ok(exports.into())
});

fn anyhow_to_js(err: anyhow::Error) -> bare_rust::Error {
    bare_rust::Error::from(err.to_string())
}
