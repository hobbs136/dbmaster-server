//! End-to-end process test for the ADR-0003 S2 embedded mode.
//!
//! Spawns the actual `dbmaster-server --embedded` binary as a child process,
//! reads the stdout handshake line, parses it, and exercises the live HTTP
//! server (`/api/health`, `/api/entitlement`). This is the executable contract
//! that the Flutter `EmbeddedServerService` (S2b) will consume.
//!
//! Concurrency note: each test spawns its own process with a unique temp
//! `--data-dir` so parallel `cargo test` runs never collide.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Path to the compiled server binary (this crate's bin target).
fn server_bin() -> String {
    // cargo builds the bin into target/{debug,release}/dbmaster-server[.exe].
    // The test runner's CARGO_BIN_EXE env var isn't set for integration tests
    // in the same way as bin-tests, so locate it from the test exe's location.
    let mut exe = std::env::current_exe().expect("current_exe");
    // .../target/debug/deps/embedded_process_test-<hash>.exe → walk up to debug/
    exe.pop(); // drop the deps dir (deps is a dir on windows; on unix too)
    // We're now in target/debug/deps or target/debug — normalize.
    if exe.file_name().and_then(|s| s.to_str()) == Some("deps") {
        exe.pop();
    }
    let exe_name = if cfg!(windows) {
        "dbmaster-server.exe"
    } else {
        "dbmaster-server"
    };
    exe.push(exe_name);
    exe.to_string_lossy().into_owned()
}

/// A spawned embedded server with its temp data dir. Drops kill the process
/// and clean the dir.
struct EmbeddedProc {
    child: Option<Child>,
    #[allow(dead_code)]
    port: u16,
    #[allow(dead_code)]
    access_token: String,
    data_dir: std::path::PathBuf,
}

impl Drop for EmbeddedProc {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Close stdin (triggers the server's stdin-EOF shutdown path) then
            // wait briefly; fall back to kill if it doesn't exit gracefully.
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Spawn the embedded server, keep stdin open (so it doesn't immediately shut
/// down), wait for the ready handshake on stdout, and parse it.
fn spawn_and_read_handshake(timeout: Duration) -> (EmbeddedProc, Value) {
    let bin = server_bin();
    // Each spawn gets a unique data dir via a process-global atomic counter
    // (Instant::now().elapsed() is unreliable here — near zero early in a
    // process, and two parallel tests can collide). pid + counter guarantees
    // uniqueness across parallel test processes.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let data_dir = std::env::temp_dir().join(format!(
        "dbmaster-embedded-proctest-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&data_dir).unwrap();

    let mut child = Command::new(&bin)
        .arg("--embedded")
        .arg("--data-dir")
        .arg(&data_dir)
        // stdin = a pipe we hold open until Drop (otherwise the server sees EOF
        // immediately under a backgrounded test runner and shuts down).
        .stdin(Stdio::piped())
        // stdout = piped so we can read the handshake line.
        .stdout(Stdio::piped())
        // stderr = inherit for debug visibility on failure.
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"));

    // Read the first line of stdout (the ready handshake). Block up to timeout.
    let stdout = child.stdout.take().expect("piped stdout");
    let deadline = Instant::now() + timeout;
    let handshake = read_first_line_with_deadline(stdout, deadline);

    let v: Value = serde_json::from_str(&handshake)
        .unwrap_or_else(|e| panic!("handshake is not valid JSON: {e}\nraw: {handshake}"));

    // Validate the contract shape before returning.
    assert_eq!(v["type"], "dbmaster_embedded_ready", "handshake type");
    let port = v["port"]
        .as_u64()
        .expect("port is a number") as u16;
    let access_token = v["access_token"]
        .as_str()
        .expect("access_token is a string")
        .to_string();
    assert!(port > 0, "OS-assigned port must be > 0");
    assert!(!access_token.is_empty(), "access token must be present");
    assert!(
        v["refresh_token"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "refresh token must be present"
    );
    assert!(
        v["install_uuid"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "install_uuid must be present"
    );
    assert!(!v["version"].as_str().unwrap_or("").is_empty(), "version present");

    // Re-attach child (stdout already consumed). Put stdout back so Drop has a
    // consistent handle; the read exhausted it but kill/wait still work.
    child.stdout = None;
    let proc = EmbeddedProc {
        child: Some(child),
        port,
        access_token,
        data_dir,
    };
    (proc, v)
}

/// Read the first line from `r`, but give up after `deadline`.
fn read_first_line_with_deadline(mut r: std::process::ChildStdout, deadline: Instant) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() > deadline {
            panic!(
                "timed out waiting for embedded server stdout handshake; got so far: {:?}",
                String::from_utf8_lossy(&buf)
            );
        }
        match r.read(&mut byte) {
            Ok(0) => panic!(
                "embedded server stdout closed before handshake; partial: {:?}",
                String::from_utf8_lossy(&buf)
            ),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
            Err(e) => panic!("error reading embedded stdout: {e}"),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// HTTP GET helper (blocking, no reqwest dependency needed). Returns (status, body).
fn http_get(url: &str) -> (u16, String) {
    // Use std-free minimal HTTP via the `http` crate? No — simplest is curl-style
    // via std::net::TcpStream. But that's fiddly; prefer the already-available
    // reqwest dev-dependency (it's in [dev-dependencies] for e2e tests).
    // We build a blocking client here.
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream = TcpStream::connect(("127.0.0.1", port_from_url(url))).unwrap();
    let req = format!("GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path_from_url(url));
    stream.write_all(req.as_bytes()).unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    // Body is everything after the blank line separating headers from body.
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn port_from_url(url: &str) -> u16 {
    // url like http://127.0.0.1:PORT/path
    url.split(':')
        .nth(2)
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(80)
}

fn path_from_url(url: &str) -> &str {
    // url like http://127.0.0.1:PORT/path → /path
    // Strip the scheme+host: find the 3rd '/' (after the two in "://").
    match url.find("://") {
        Some(scheme_end) => {
            let rest = &url[scheme_end + 3..]; // "127.0.0.1:PORT/path"
            match rest.find('/') {
                Some(p) => &rest[p..],
                None => "/",
            }
        }
        None => "/",
    }
}

#[test]
fn embedded_process_emits_ready_handshake() {
    let (proc, handshake) = spawn_and_read_handshake(Duration::from_secs(30));
    // The handshake fields are already asserted inside spawn_and_read_handshake;
    // this test exists as a standalone contract check.
    assert_eq!(handshake["type"], "dbmaster_embedded_ready");
    drop(proc); // triggers clean shutdown
}

#[test]
fn embedded_process_serves_health_and_entitlement() {
    let (proc, _handshake) = spawn_and_read_handshake(Duration::from_secs(30));
    let port = proc.port;

    // /api/health — 200 + ok status (no auth).
    let (status, body) = http_get(&format!("http://127.0.0.1:{port}/api/health"));
    assert_eq!(status, 200, "health status; body: {body}");
    let v: Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("health body not JSON: {e}"));
    assert_eq!(v["status"], "ok");

    // /api/entitlement — must report state=licensed, type=embedded, no expiry
    // (the synthesized lifetime-Licensed entitlement).
    let (status, body) = http_get(&format!("http://127.0.0.1:{port}/api/entitlement"));
    assert_eq!(status, 200, "entitlement status; body: {body}");
    let v: Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("entitlement body not JSON: {e}"));
    assert_eq!(v["data"]["state"], "licensed", "embedded is the free tier → licensed");
    assert_eq!(v["data"]["license"]["type"], "embedded");
    assert!(v["data"]["expires_at"].is_null(), "lifetime → no expiry");

    drop(proc);
}
