use std::time::{Duration, Instant};

/// Per-connection send rate limit: at most SEND_RATE_LIMIT sends per SEND_RATE_WINDOW.
pub const SEND_RATE_LIMIT: u32 = 60;
pub const SEND_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Per-connection state for one authenticated Android client.
///
/// Owned exclusively by the WebSocket read-loop task; no locking required.
pub struct Session {
    pub authed: bool,
    pub nonce: Option<Vec<u8>>,        // challenge nonce, valid during auth flow only
    pub identity_key: Option<Vec<u8>>, // Ed25519 pubkey, set after successful auth
    pub mailbox_addr: Option<String>,  // derived from identity key
    pub send_count: u32,               // messages sent in current rate-limit window
    pub send_window_start: Instant,    // start of the current rate-limit window
}

impl Session {
    pub fn new() -> Self {
        Self {
            authed: false,
            nonce: None,
            identity_key: None,
            mailbox_addr: None,
            send_count: 0,
            send_window_start: Instant::now(),
        }
    }

    pub fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce = Some(nonce);
    }

    pub fn authenticate(&mut self, identity_key: Vec<u8>, mailbox_addr: String) {
        self.authed = true;
        self.identity_key = Some(identity_key);
        self.mailbox_addr = Some(mailbox_addr);
        self.nonce = None;
    }

    pub fn mailbox_addr(&self) -> Option<&str> {
        self.mailbox_addr.as_deref()
    }

    /// Check send rate and advance the counter. Returns true if the send is allowed.
    pub fn check_send_rate(&mut self) -> bool {
        if self.send_window_start.elapsed() >= SEND_RATE_WINDOW {
            self.send_window_start = Instant::now();
            self.send_count = 0;
        }
        self.send_count += 1;
        self.send_count <= SEND_RATE_LIMIT
    }
}
