// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::{
    ffi::{OsStr, OsString},
    net::TcpListener,
    process,
    sync::atomic::{AtomicU16, Ordering},
    thread, time,
};

use sp_keyring::AccountKeyring;
use subxt::{Config, OnlineClient};

/// Spawn a local substrate node for testing subxt.
pub struct TestNodeProcess<R: Config> {
    proc: process::Child,
    client: OnlineClient<R>,
    pub ws_url: String,
}

impl<R> Drop for TestNodeProcess<R>
where
    R: Config,
{
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

impl<R> TestNodeProcess<R>
where
    R: Config,
{
    /// Construct a builder for spawning a test node process.
    pub fn build<S>(
        program: S,
        chain_type: String,
        force_authoring: bool,
        bootnode: Option<String>,
        threshold_url: Option<String>,
    ) -> TestNodeProcessBuilder
    where
        S: AsRef<OsStr> + Clone,
    {
        TestNodeProcessBuilder::new(program, chain_type, force_authoring, bootnode, threshold_url)
    }

    /// Attempt to kill the running substrate process.
    pub fn kill(&mut self) -> Result<(), String> {
        tracing::info!("Killing node process {}", self.proc.id());
        if let Err(err) = self.proc.kill() {
            let err = format!("Error killing node process {}: {err}", self.proc.id());
            tracing::error!("{}", err);
            return Err(err);
        }
        Ok(())
    }

    /// Returns the subxt client connected to the running node.
    pub fn client(&self) -> &OnlineClient<R> {
        &self.client
    }
}

/// Construct a test node process.
pub struct TestNodeProcessBuilder {
    node_path: OsString,
    authority: Option<AccountKeyring>,
    scan_port_range: bool,
    chain_type: String,
    force_authoring: bool,
    bootnode: Option<String>,
    tss_server_endpoint: Option<String>,
}

impl TestNodeProcessBuilder {
    pub fn new<P>(
        node_path: P,
        chain_type: String,
        force_authoring: bool,
        bootnode: Option<String>,
        tss_server_endpoint: Option<String>,
    ) -> TestNodeProcessBuilder
    where
        P: AsRef<OsStr>,
    {
        Self {
            node_path: node_path.as_ref().into(),
            authority: None,
            scan_port_range: false,
            chain_type,
            force_authoring,
            bootnode,
            tss_server_endpoint,
        }
    }

    /// Set the authority dev account for a node in validator mode e.g. --alice.
    pub fn with_authority(&mut self, account: AccountKeyring) -> &mut Self {
        self.authority = Some(account);
        self
    }

    /// Enable port scanning to scan for open ports.
    ///
    /// Allows spawning multiple node instances for tests to run in parallel.
    pub fn scan_for_open_ports(&mut self) -> &mut Self {
        self.scan_port_range = true;
        self
    }

    /// Spawn the substrate node at the given path, and wait for rpc to be initialized.
    pub async fn spawn<R>(&self) -> Result<TestNodeProcess<R>, String>
    where
        R: Config,
    {
        let mut cmd = process::Command::new(&self.node_path);
        cmd.env("RUST_LOG", "error").arg(&self.chain_type).arg("--tmp");
        cmd.arg("--unsafe-force-node-key-generation");
        cmd.arg("--public-addr=/ip4/0.0.0.0/tcp/30333");
        if self.force_authoring {
            cmd.arg("--force-authoring");
        }
        if let Some(authority) = self.authority {
            let authority = format!("{authority:?}");
            let arg = format!("--{}", authority.as_str().to_lowercase());
            cmd.arg(arg);
        }

        if let Some(bootnode) = &self.bootnode {
            let arg = format!("--bootnodes={}", bootnode.as_str());
            cmd.arg(arg);
        }

        if let Some(tss_server_endpoint) = &self.tss_server_endpoint {
            let arg = format!("--tss-server-endpoint={}", tss_server_endpoint.as_str());
            cmd.arg(arg);
        }

        let ws_port = if self.scan_port_range {
            let (p2p_port, _http_port, ws_port) = next_open_port()
                .ok_or_else(|| "No available ports in the given port range".to_owned())?;
            cmd.arg(format!("--port={p2p_port}"));
            cmd.arg(format!("--rpc-port={ws_port}"));
            tracing::info!("ws port: {ws_port}");
            ws_port
        } else {
            // the default Websockets port
            9944
        };

        let ws_url = format!("ws://127.0.0.1:{ws_port}");

        let mut proc = cmd.spawn().map_err(|e| {
            format!("Error spawning substrate node '{}': {e}", self.node_path.to_string_lossy())
        })?;
        // wait for rpc to be initialized
        const MAX_ATTEMPTS: u32 = 6;
        let mut attempts = 1;
        let mut wait_secs = 1;
        let client = loop {
            thread::sleep(time::Duration::from_secs(wait_secs));
            tracing::info!(
                "Connecting to contracts enabled node, attempt {}/{}",
                attempts,
                MAX_ATTEMPTS
            );
            let result = OnlineClient::<R>::from_url(ws_url.clone()).await;
            match result {
                Ok(client) => break Ok(client),
                Err(err) => {
                    if attempts < MAX_ATTEMPTS {
                        attempts += 1;
                        wait_secs *= 2; // backoff
                        continue;
                    }
                    break Err(err);
                },
            }
        };
        match client {
            Ok(client) => Ok(TestNodeProcess { proc, client, ws_url }),
            Err(err) => {
                let err = format!(
                    "Failed to connect to node rpc at {ws_url} after {attempts} attempts: {err}"
                );
                tracing::error!("{}", err);
                proc.kill()
                    .map_err(|e| format!("Error killing substrate process '{}': {e}", proc.id()))?;
                Err(err)
            },
        }
    }
}

/// The start of the port range to scan.
const START_PORT: u16 = 9900;
/// The end of the port range to scan.
const END_PORT: u16 = 10000;
/// The maximum number of ports to scan before giving up.
const MAX_PORTS: u16 = 1000;
/// Next available unclaimed port for test node endpoints.
static PORT: AtomicU16 = AtomicU16::new(START_PORT);

/// Returns the next set of 3 open ports.
///
/// Returns None if there are not 3 open ports available.
fn next_open_port() -> Option<(u16, u16, u16)> {
    let mut ports = Vec::new();
    let mut ports_scanned = 0u16;
    loop {
        let _ = PORT.compare_exchange(END_PORT, START_PORT, Ordering::SeqCst, Ordering::SeqCst);
        let next = PORT.fetch_add(1, Ordering::SeqCst);
        if TcpListener::bind(("0.0.0.0", next)).is_ok() {
            ports.push(next);
            if ports.len() == 3 {
                return Some((ports[0], ports[1], ports[2]));
            }
        }
        ports_scanned += 1;
        if ports_scanned == MAX_PORTS {
            return None;
        }
    }
}
