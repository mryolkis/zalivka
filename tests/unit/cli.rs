use super::*;

#[test]
fn restore_logs_needs_only_an_ecid_and_new_output_directory() {
    match Cli::try_parse_from([
        "zalivka",
        "restore-logs",
        "--ecid",
        "000370603a8a4026",
        "--output",
        "evidence",
    ])
    .unwrap()
    .command
    {
        Command::RestoreLogs { ecid, output } => {
            assert_eq!(ecid, 0x000370603a8a4026);
            assert_eq!(output, PathBuf::from("evidence"));
        }
        _ => panic!("wrong command"),
    }
    assert!(Cli::try_parse_from(["zalivka", "restore-logs", "--ecid", "1234"]).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn native_dfu_helper_accepts_a_literal_prompt_and_stays_hidden() {
    let prompt = "Zalivka: Вход в DFU $HOME $(id);";
    match Cli::try_parse_from(["zalivka", "enter-dfu-helper", "--prompt", prompt])
        .unwrap()
        .command
    {
        Command::EnterDfuHelper { prompt: value } => assert_eq!(value.as_deref(), Some(prompt)),
        _ => panic!("wrong command"),
    }
    assert!(Cli::try_parse_from(["zalivka", "enter-dfu-helper"]).is_ok());
    use clap::CommandFactory;
    let help = Cli::command().render_help().to_string();
    assert!(help.contains("enter-dfu"));
    assert!(!help.contains("enter-dfu-helper"));
}

#[test]
fn driver_reset_is_a_separate_command_without_a_device_or_firmware() {
    assert!(matches!(
        Cli::try_parse_from(["zalivka", "drivers", "reset"])
            .unwrap()
            .command,
        Command::Drivers {
            command: DriverCommand::Reset
        }
    ));
    assert!(Cli::try_parse_from(["zalivka", "drivers", "reset-elevated"]).is_err());
    assert!(Cli::try_parse_from(["zalivka", "drivers", "prepare-elevated"]).is_err());
}

#[test]
fn cli_has_no_logging_switches_or_gui_service_parameters() {
    for flag in [
        "--trace",
        "--verbose",
        "-v",
        "--elevated-log",
        "--driver-helper",
    ] {
        assert!(Cli::try_parse_from(["zalivka", flag, "doctor"]).is_err());
    }
    assert!(Cli::try_parse_from(["zalivka", "revive", "--ecid", "2a", "--experimental"]).is_err());
}

#[test]
fn boot_state_requires_an_explicit_flag_to_load_ibss() {
    for load in [false, true] {
        let mut args = vec!["zalivka", "boot-state", "firmware.ipsw", "--ecid", "1234"];
        if load {
            args.push("--load-ibss");
        }
        match Cli::try_parse_from(args).unwrap().command {
            Command::BootState {
                ecid, load_ibss, ..
            } => {
                assert_eq!(ecid, 0x1234);
                assert_eq!(load_ibss, load);
            }
            _ => panic!("unexpected command"),
        }
    }
}

#[test]
fn restore_and_revive_accept_automatic_download_and_shared_options() {
    for command in ["restore", "revive"] {
        let mut argv = vec![
            "zalivka",
            command,
            "--ecid",
            "1234",
            "--firmware-dir",
            "cache",
            "--identity",
            "63",
            "--transcript",
            "restore.jsonl",
            "--authorization-tokens",
            "tokens.plist",
            "--apple-connect-data",
            "connect.data",
        ];
        if command == "restore" {
            argv.push("--erase");
        }
        let args = match Cli::try_parse_from(argv).unwrap().command {
            Command::Restore { args, erase } => {
                assert!(erase);
                args
            }
            Command::Revive(args) => args,
            _ => panic!("wrong command"),
        };
        assert!(args.ipsw.is_none());
        assert_eq!(args.firmware_dir, Some(PathBuf::from("cache")));
        assert_eq!(args.ecid, 0x1234);
        assert_eq!(args.identity, Some(63));
        assert_eq!(args.transcript, Some(PathBuf::from("restore.jsonl")));
        assert_eq!(
            args.authorization_tokens,
            Some(PathBuf::from("tokens.plist"))
        );
        assert_eq!(args.apple_connect_data, Some(PathBuf::from("connect.data")));
        assert_eq!(
            Cli::try_parse_from(["zalivka", command, "--ecid", "1234"]).is_ok(),
            command == "revive"
        );
    }
}

#[test]
fn local_restore_and_revive_reject_cache_options() {
    for command in ["restore", "revive"] {
        let mut argv = vec!["zalivka", command, "local.ipsw", "--ecid", "1234"];
        if command == "restore" {
            argv.push("--erase");
        }
        let args = match Cli::try_parse_from(&argv).unwrap().command {
            Command::Restore { args, .. } | Command::Revive(args) => args,
            _ => panic!("wrong command"),
        };
        assert_eq!(args.ipsw, Some(PathBuf::from("local.ipsw")));
        argv.extend(["--firmware-dir", "cache"]);
        assert!(Cli::try_parse_from(argv).is_err());
    }
    assert!(matches!(
        Cli::try_parse_from(["zalivka", "fetch", "--ecid", "1234"])
            .unwrap()
            .command,
        Command::Fetch { .. }
    ));
}

#[test]
fn usb_pid_uses_one_optional_case_insensitive_prefix_and_rejects_zero() {
    for value in ["1227", "0x1227", "0X1227"] {
        assert_eq!(parse_pid(value).unwrap(), 0x1227);
    }
    for value in ["", "0", "0x", "+1227", "0x0x1227", "10000", " 1227"] {
        assert!(parse_pid(value).is_err(), "{value}");
    }
}

#[test]
fn usb_internet_commands_and_post_restore_sharing_are_rejected() {
    for command in ["status", "prepare", "share"] {
        assert!(Cli::try_parse_from(["zalivka", "usb-internet", command]).is_err());
    }
    for command in ["restore", "revive"] {
        let mut args = vec!["zalivka", command, "--ecid", "2a"];
        if command == "restore" {
            args.push("--erase");
        }
        assert!(Cli::try_parse_from(&args).is_ok());
        args.push("--share-internet");
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn verification_requires_explicit_network_access_and_exclusive_aea_key_sources() {
    let parsed = Cli::try_parse_from(["zalivka", "verify", "firmware.ipsw"]).unwrap();
    assert!(matches!(
        parsed.command,
        Command::Verify {
            online: false,
            aea_key: None,
            aea_private_key: None,
            ..
        }
    ));
    assert!(
        Cli::try_parse_from([
            "zalivka",
            "verify",
            "firmware.ipsw",
            "--aea-key",
            "00",
            "--aea-private-key",
            "key.pem"
        ])
        .is_err()
    );
    let parsed = Cli::try_parse_from(["zalivka", "verify", "firmware.ipsw", "--online"]).unwrap();
    assert!(matches!(
        parsed.command,
        Command::Verify { online: true, .. }
    ));
}
