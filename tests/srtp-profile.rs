//! The SRTP protection profile the DTLS handshake negotiated is reported
//! once the SRTP keys are in place.
#![cfg(any(
    feature = "aws-lc-rs",
    feature = "rust-crypto",
    feature = "openssl",
    feature = "openssl-dimpl",
    feature = "wincrypto",
    feature = "apple-crypto",
))]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::crypto::dtls::SrtpProfile;
use str0m::{Candidate, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{TestRtc, init_crypto_default, init_log, progress};

#[test]
fn reports_the_negotiated_srtp_profile() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(info_span!("L"), RtcConfig::new().build(now));
    let mut r = TestRtc::new_with_rtc(info_span!("R"), RtcConfig::new().build(now));
    assert_eq!(l.srtp_profile(), None);

    let host_l = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host_r = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();
    l.add_local_candidate(host_l.clone()).unwrap();
    l.add_remote_candidate(host_r.clone());
    r.add_local_candidate(host_r).unwrap();
    r.add_remote_candidate(host_l);

    let finger_l = l.direct_api().local_dtls_fingerprint().clone();
    let finger_r = r.direct_api().local_dtls_fingerprint().clone();
    l.direct_api().set_remote_fingerprint(finger_r);
    r.direct_api().set_remote_fingerprint(finger_l);

    let creds_l = l.direct_api().local_ice_credentials();
    let creds_r = r.direct_api().local_ice_credentials();
    l.direct_api().set_remote_ice_credentials(creds_r);
    r.direct_api().set_remote_ice_credentials(creds_l);
    l.direct_api().set_ice_controlling(true);
    r.direct_api().set_ice_controlling(false);

    l.direct_api().start_dtls(true).unwrap();
    r.direct_api().start_dtls(false).unwrap();

    while !(l.is_connected() && r.is_connected()) {
        if l.duration() > Duration::from_secs(5) {
            panic!("DTLS did not connect");
        }
        progress(&mut l, &mut r)?;
    }

    let profile = l.srtp_profile().expect("a profile once connected");
    assert_eq!(r.srtp_profile(), Some(profile));
    assert!(SrtpProfile::ALL.contains(&profile));
    Ok(())
}
