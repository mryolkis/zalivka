use super::*;

#[test]
fn environment_policy_is_scheme_specific_and_invalid_config_does_not_bypass() {
    let values = std::collections::HashMap::from([
        ("HTTP_PROXY", "http://web:8080"),
        ("HTTPS_PROXY", "socks5h://secure:1080"),
        ("ALL_PROXY", "http://fallback:3128"),
        ("NO_PROXY", "*.internal"),
    ]);
    let read = |name: &str| values.get(name).map(|v| v.to_string());
    for (url, host) in [
        ("http://external.invalid/", "web"),
        ("https://external.invalid/", "secure"),
    ] {
        assert_eq!(
            environment_proxy(&url.parse().unwrap(), read)
                .unwrap()
                .unwrap()
                .host(),
            host
        );
    }
    assert!(
        environment_proxy(&"https://host.internal/".parse().unwrap(), read)
            .unwrap()
            .is_none()
    );
    let invalid = |name: &str| (name == "HTTPS_PROXY").then(|| "invalid proxy address".to_owned());
    assert!(environment_proxy(&"https://external.invalid/".parse().unwrap(), invalid).is_err());
}

#[test]
fn windows_proxy_list_selects_destination_scheme_and_transport() {
    let uri: Uri = "https://gs.apple.com/TSS/controller?action=2"
        .parse()
        .unwrap();
    for (list, protocol, host, port) in [
        (
            "proxy.example:8080",
            ureq::ProxyProtocol::Http,
            "proxy.example",
            8080,
        ),
        (
            "http=web:80;https=secure:3128;socks=sock:1080",
            ureq::ProxyProtocol::Http,
            "secure",
            3128,
        ),
        (
            "HTTPS=https://secure:443",
            ureq::ProxyProtocol::Https,
            "secure",
            443,
        ),
        (
            "socks=sock:1080",
            ureq::ProxyProtocol::Socks4A,
            "sock",
            1080,
        ),
        (
            "socks5h://sock:1081",
            ureq::ProxyProtocol::Socks5h,
            "sock",
            1081,
        ),
        (
            "proxy1:80;proxy2:81",
            ureq::ProxyProtocol::Http,
            "proxy1",
            80,
        ),
    ] {
        let proxy = from_windows_list(&uri, list, "").unwrap().unwrap();
        assert_eq!(
            (proxy.protocol(), proxy.host(), proxy.port()),
            (protocol, host, port),
            "{list}"
        );
    }
    for list in ["", "DIRECT", "http=web:80;ftp=ftp:21"] {
        assert!(
            from_windows_list(&uri, list, "").unwrap().is_none(),
            "{list}"
        );
    }
    assert!(from_windows_list(&uri, "https=", "").is_err());
}

#[test]
fn windows_exceptions_honor_wildcards_scheme_port_and_local_names() {
    for (url, bypass, expected) in [
        ("https://gs.apple.com/", "*.APPLE.COM", true),
        ("https://gs.apple.com/", "gs.*.com:443", true),
        ("https://gs.apple.com/", "gs.apple.com:80", false),
        ("https://gs.apple.com/", "http://*.apple.com", false),
        ("https://gs.apple.com/", "https://gs.apple.com:443", true),
        ("https://gs.apple.com/", "gs.apple.?om", true),
        (
            "https://gs.apple.com/",
            "localhost;other.example *.cdn-apple.com",
            false,
        ),
        ("https://gs.apple.com/", "*", true),
        ("https://gs.apple.com/", "", false),
        ("https://intranet/", "<local>", true),
        ("https://gs.apple.com/", "<local>", false),
        ("https://[::1]/", "[::1]:443", true),
    ] {
        let uri = url.parse().unwrap();
        assert_eq!(windows_bypass(&uri, bypass), expected, "{url}: {bypass}");
        assert_eq!(
            from_windows_list(&uri, "proxy:80", bypass)
                .unwrap()
                .is_none(),
            expected
        );
    }
}

#[test]
fn proxy_environment_trims_addresses_and_falls_back_from_empty_uppercase_bypass() {
    let read = |name: &str| match name {
        "HTTPS_PROXY" => Some("  http://proxy.invalid:8080  ".into()),
        "NO_PROXY" => Some("  ".into()),
        "no_proxy" => Some(", ,gs.apple.com,,".into()),
        _ => None,
    };
    assert!(
        environment_proxy(&"https://gs.apple.com/".parse().unwrap(), read)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        environment_proxy(&"https://mesu.apple.com/".parse().unwrap(), read)
            .unwrap()
            .unwrap()
            .host(),
        "proxy.invalid"
    );
}

#[test]
fn system_routes_preserve_order_explicit_direct_and_unspecified_socks_fallback() {
    let routes = routes_from_strings(vec![
        "http://one.example:3128".into(),
        "socks://two.example:1080".into(),
        "direct://".into(),
    ])
    .unwrap();
    assert_eq!(routes.len(), 4);
    assert_eq!(routes[0].as_ref().unwrap().host(), "one.example");
    assert_eq!(
        routes[1].as_ref().unwrap().protocol(),
        ureq::ProxyProtocol::Socks5h
    );
    assert_eq!(
        routes[2].as_ref().unwrap().protocol(),
        ureq::ProxyProtocol::Socks4A
    );
    assert!(routes[3].is_none());
    let socks = routes_from_strings(vec!["socks5://remote.example:1080".into()]).unwrap();
    assert_eq!(
        socks[0].as_ref().unwrap().protocol(),
        ureq::ProxyProtocol::Socks5h
    );
    assert!(routes_from_strings(vec![]).is_err());
    assert!(routes_from_strings(vec!["bad proxy address".into()]).is_err());
}
