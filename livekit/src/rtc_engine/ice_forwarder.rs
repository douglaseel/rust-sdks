// Copyright 2026 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Media through an ICE forwarder.
//!
//! An ICE forwarder is a UDP forwarder in front of this participant. It routes
//! each connectivity check by the ICE username fragment that the check carries,
//! and delivers it to one local port. The forwarder terminates nothing: DTLS and
//! SRTP stay end to end.
//!
//! When a room connects with an [`IceForwarder`], all media goes through it, and
//! only through it:
//!
//! - every local description carries the forwarder's ICE credentials, also
//!   across ICE restarts, because the forwarder routes on the ufrag;
//! - ICE gathers on the one local port the forwarder delivers to, and gathers
//!   no TCP candidates;
//! - the room sees only the forwarder's addresses as this participant's
//!   candidates;
//! - remote candidates are ignored, so this participant never sends a check on
//!   a path of its own. It only answers the checks that arrive through the
//!   forwarder. Thus the server must run full ICE, and the join asks for it;
//! - ICE servers, also those that the server offers, are not used;
//! - the connection fails if the server does not accept single peer connection
//!   mode, because the forwarder routes one set of credentials to one port.

use std::{fmt, net::SocketAddr};

/// The ICE username fragment and password of a local description.
#[derive(Clone, PartialEq, Eq)]
pub struct IceCredentials {
    pub ufrag: String,
    pub pwd: String,
}

impl fmt::Debug for IceCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IceCredentials")
            .field("ufrag", &self.ufrag)
            .field("pwd", &"<redacted>")
            .finish()
    }
}

/// A forwarder that all media of a room connection goes through.
/// See the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceForwarder {
    /// The forwarder's public addresses: what the room sees as this
    /// participant's candidates. At least one.
    pub addresses: Vec<SocketAddr>,
    /// The credentials every local description carries.
    pub credentials: IceCredentials,
    /// The local UDP port the forwarder delivers to. ICE gathers on it alone.
    pub local_port: u16,
}

/// RFC 8839 §5.4: `ice-ufrag` is 4 to 256 `ice-char`, `ice-pwd` 22 to 256.
const UFRAG_LEN: std::ops::RangeInclusive<usize> = 4..=256;
const PWD_LEN: std::ops::RangeInclusive<usize> = 22..=256;

/// Host type preference (RFC 8445 §5.1.2.2).
const HOST_TYPE_PREFERENCE: u32 = 126;

fn is_ice_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/'
}

fn check_ice_value(
    name: &str,
    value: &str,
    len: std::ops::RangeInclusive<usize>,
) -> Result<(), String> {
    if !len.contains(&value.len()) {
        return Err(format!(
            "{name} must be {} to {} characters, got {}",
            len.start(),
            len.end(),
            value.len()
        ));
    }
    if !value.chars().all(is_ice_char) {
        return Err(format!("{name} may hold only letters, digits, '+' and '/'"));
    }
    Ok(())
}

impl IceForwarder {
    /// Check the forwarder before a connection uses it. Each error names the
    /// field at fault.
    pub fn validate(&self) -> Result<(), String> {
        if self.addresses.is_empty() {
            return Err("ice forwarder: addresses must hold at least one address".into());
        }
        for addr in &self.addresses {
            if addr.port() == 0 || addr.ip().is_unspecified() {
                return Err(format!("ice forwarder: address {addr} is not a usable address"));
            }
        }
        if self.local_port == 0 {
            return Err("ice forwarder: local_port must not be 0".into());
        }
        check_ice_value("ice forwarder: ufrag", &self.credentials.ufrag, UFRAG_LEN)?;
        check_ice_value("ice forwarder: pwd", &self.credentials.pwd, PWD_LEN)?;
        Ok(())
    }

    /// The candidates this participant advertises, one for each forwarder
    /// address, in the `candidate-attribute` form a trickle carries (without
    /// the `a=` prefix).
    ///
    /// They are host candidates: the forwarder does not allocate anything, it
    /// is the address the room reaches this participant at. The first address
    /// has the highest priority.
    pub(crate) fn candidates(&self) -> Vec<String> {
        self.addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let local_preference = 65535u32.saturating_sub(i as u32);
                let priority = (HOST_TYPE_PREFERENCE << 24) | (local_preference << 8) | 255;
                format!(
                    "candidate:fwd{i} 1 udp {priority} {} {} typ host generation 0",
                    addr.ip(),
                    addr.port()
                )
            })
            .collect()
    }

    /// Rewrite a local description: put in the forwarder's credentials, and
    /// remove every gathered candidate. The forwarder's candidates are
    /// trickled instead.
    ///
    /// Every `ice-ufrag`/`ice-pwd` line changes, not only the first: bundled
    /// media sections each carry them and they must agree.
    pub(crate) fn rewrite_local_sdp(&self, sdp: &str) -> String {
        let mut out = String::with_capacity(sdp.len() + 64);
        for line in sdp.lines() {
            if line.starts_with("a=ice-ufrag:") {
                out.push_str("a=ice-ufrag:");
                out.push_str(&self.credentials.ufrag);
            } else if line.starts_with("a=ice-pwd:") {
                out.push_str("a=ice-pwd:");
                out.push_str(&self.credentials.pwd);
            } else if is_candidate_line(line) {
                continue;
            } else {
                out.push_str(line);
            }
            // SDP lines end in CRLF (RFC 4566 §5).
            out.push_str("\r\n");
        }
        out
    }

    /// Remove every candidate from a remote description, so this participant
    /// never sends a check on a path of its own.
    pub(crate) fn strip_remote_sdp(sdp: &str) -> String {
        let mut out = String::with_capacity(sdp.len());
        for line in sdp.lines().filter(|l| !is_candidate_line(l)) {
            out.push_str(line);
            out.push_str("\r\n");
        }
        out
    }
}

fn is_candidate_line(line: &str) -> bool {
    line.starts_with("a=candidate:") || line.trim_end() == "a=end-of-candidates"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwarder() -> IceForwarder {
        IceForwarder {
            addresses: vec![
                "203.0.113.10:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
            ],
            credentials: IceCredentials {
                ufrag: "z04yKzdOjjjhPoE5bQE0/NbtKYLwqvo".into(),
                pwd: "5H4joxyoYh0QO3jpq+iQVPqCuDWPsp4I".into(),
            },
            local_port: 50001,
        }
    }

    const OFFER: &str = "v=0\r\n\
o=- 1 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
a=group:BUNDLE 0 1\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=candidate:1 1 udp 2122129151 192.168.1.2 50001 typ host generation 0\r\n\
a=end-of-candidates\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:aaaaaaaaaaaaaaaaaaaaaaaa\r\n\
a=fingerprint:sha-256 AA:BB\r\n\
a=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:aaaaaaaaaaaaaaaaaaaaaaaa\r\n\
a=mid:1\r\n";

    #[test]
    fn a_valid_forwarder_passes() {
        assert_eq!(forwarder().validate(), Ok(()));
    }

    #[test]
    fn validation_names_the_field_at_fault() {
        let mut f = forwarder();
        f.addresses.clear();
        assert!(f.validate().unwrap_err().contains("addresses"));

        let mut f = forwarder();
        f.addresses = vec!["0.0.0.0:443".parse().unwrap()];
        assert!(f.validate().unwrap_err().contains("0.0.0.0:443"));

        let mut f = forwarder();
        f.addresses = vec!["203.0.113.10:0".parse().unwrap()];
        assert!(f.validate().is_err());

        let mut f = forwarder();
        f.local_port = 0;
        assert!(f.validate().unwrap_err().contains("local_port"));

        let mut f = forwarder();
        f.credentials.ufrag = "abc".into();
        assert!(f.validate().unwrap_err().contains("ufrag"));

        let mut f = forwarder();
        f.credentials.ufrag = "abcd:".into();
        assert!(f.validate().unwrap_err().contains("ufrag"));

        let mut f = forwarder();
        f.credentials.pwd = "a".repeat(21);
        assert!(f.validate().unwrap_err().contains("pwd"));
    }

    #[test]
    fn debug_hides_the_password() {
        let shown = format!("{:?}", forwarder());
        assert!(!shown.contains("5H4joxyoYh0QO3jpq"));
        assert!(shown.contains("z04yKzdOjjjhPoE5bQE0/NbtKYLwqvo"));
    }

    #[test]
    fn local_sdp_carries_the_credentials_in_every_section_and_no_candidate() {
        let out = forwarder().rewrite_local_sdp(OFFER);
        assert_eq!(out.matches("a=ice-ufrag:z04yKzdOjjjhPoE5bQE0/NbtKYLwqvo\r\n").count(), 2);
        assert_eq!(out.matches("a=ice-pwd:5H4joxyoYh0QO3jpq+iQVPqCuDWPsp4I\r\n").count(), 2);
        assert!(!out.contains("abcd"));
        assert!(!out.contains("a=candidate:"));
        assert!(!out.contains("a=end-of-candidates"));
        // Everything else is left as it was, the fingerprint above all.
        assert!(out.contains("a=fingerprint:sha-256 AA:BB\r\n"));
        assert!(out.contains("a=group:BUNDLE 0 1\r\n"));
        assert_eq!(out.lines().count(), OFFER.lines().count() - 2);
    }

    #[test]
    fn local_sdp_rewrite_accepts_lf_and_emits_crlf() {
        let out = forwarder().rewrite_local_sdp(&OFFER.replace("\r\n", "\n"));
        assert!(out.lines().all(|l| !l.ends_with('\r')));
        assert_eq!(out.matches("\r\n").count(), out.lines().count());
    }

    #[test]
    fn remote_sdp_loses_only_its_candidates() {
        let out = IceForwarder::strip_remote_sdp(OFFER);
        assert!(!out.contains("a=candidate:"));
        assert!(!out.contains("a=end-of-candidates"));
        assert!(out.contains("a=ice-ufrag:abcd\r\n"));
        assert_eq!(out.lines().count(), OFFER.lines().count() - 2);
    }

    #[test]
    fn candidates_are_host_candidates_in_address_order() {
        let c = forwarder().candidates();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], "candidate:fwd0 1 udp 2130706431 203.0.113.10 443 typ host generation 0");
        assert!(c[1].starts_with("candidate:fwd1 1 udp "));
        assert!(c[1].contains(" 2001:db8::1 443 typ host"));
        let prio = |s: &str| s.split(' ').nth(3).unwrap().parse::<u32>().unwrap();
        assert!(prio(&c[0]) > prio(&c[1]));
    }
}
