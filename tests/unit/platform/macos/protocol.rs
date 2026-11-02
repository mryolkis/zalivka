use super::*;
use std::collections::VecDeque;

#[derive(Debug)]
enum Step {
    Read(u8, Result<Vec<u8>, &'static str>),
    Command([u8; 4], Vec<u8>, Result<u8, &'static str>),
}
struct Script(VecDeque<Step>);
impl Controller for Script {
    fn read(&mut self, register: u8) -> Result<Vec<u8>> {
        match self.0.pop_front().expect("unexpected read") {
            Step::Read(expected, result) => {
                assert_eq!(register, expected);
                result.map_err(anyhow::Error::msg)
            }
            other => panic!("expected {other:?}, got read {register:#x}"),
        }
    }
    fn command(&mut self, name: [u8; 4], args: &[u8]) -> Result<u8> {
        match self.0.pop_front().expect("unexpected command") {
            Step::Command(expected, expected_args, result) => {
                assert_eq!(name, expected);
                assert_eq!(args, expected_args);
                result.map_err(anyhow::Error::msg)
            }
            other => panic!("expected {other:?}, got command {name:?}"),
        }
    }
}
fn read(register: u8, data: &[u8]) -> Step {
    Step::Read(register, Ok(data.to_vec()))
}
fn command(name: &[u8; 4], args: &[u8]) -> Step {
    Step::Command(*name, args.to_vec(), Ok(0))
}
fn vdm() -> Step {
    // Independent little-endian encoding of Apple's DFU VDM, matching the reference.
    command(
        b"VDMs",
        &[
            0x33, 0x12, 0x80, 0xac, 0x05, 0x06, 0x01, 0, 0, 0, 0, 0x01, 0x80,
        ],
    )
}
fn script(steps: Vec<Step>, expected: Option<&str>) {
    let mut script = Script(steps.into());
    let result = enter_dfu(&mut script, *b"BcaM", || Ok(()));
    match expected {
        None => result.unwrap(),
        Some(expected) => assert!(format!("{:#}", result.unwrap_err()).contains(expected)),
    }
    assert!(script.0.is_empty(), "unconsumed operations: {:?}", script.0);
}
fn setup() -> Vec<Step> {
    vec![
        read(0x3f, &[1]),
        read(3, b"APP\0"),
        command(b"LOCK", b"BcaM"),
        command(b"DBMa", &[1]),
        read(3, b"DBMa\0"),
        read(0x4d, &[7, 0, 0, 0, 0]),
    ]
}

#[test]
fn dfu_vdm_unlocks_once_checks_the_reply_and_restores_controller_mode() {
    let mut steps = setup();
    steps.extend([
        vdm(),
        read(0x4d, &[7, 0, 0, 0, 0]),
        read(0x4d, &[8, 0x52, 0x80, 0xac, 5]),
        command(b"DBMa", &[0]),
    ]);
    script(steps, None);
}

#[test]
fn existing_debug_mode_is_preserved() {
    script(
        vec![
            read(0x3f, &[3]),
            read(3, b"DBMa\0"),
            read(0x4d, &[2]),
            vdm(),
            read(0x4d, &[3, 0x52, 0x80, 0xac, 5]),
        ],
        None,
    );
}

#[test]
fn disconnected_port_does_not_unlock_or_send_commands() {
    script(vec![read(0x3f, &[0])], Some("No USB-C connection"));
    script(vec![read(0x3f, &[])], Some("No USB-C connection"));
}

#[test]
fn explicit_unlock_refusal_can_reset_the_controller_and_retry_unlock_once() {
    script(
        vec![
            read(0x3f, &[1]),
            read(3, b"APP\0"),
            Step::Command(*b"LOCK", b"BcaM".to_vec(), Ok(1)),
            command(b"Gaid", &[]),
            command(b"LOCK", b"BcaM"),
            command(b"DBMa", &[1]),
            read(3, b"DBMa\0"),
            read(0x4d, &[2]),
            vdm(),
            read(0x4d, &[3, 0x52, 0x80, 0xac, 5]),
            command(b"DBMa", &[0]),
        ],
        None,
    );
    script(
        vec![
            read(0x3f, &[1]),
            read(3, b"APP\0"),
            Step::Command(*b"LOCK", b"BcaM".to_vec(), Err("transport lost")),
        ],
        Some("transport lost"),
    );
}

#[test]
fn failed_or_uncertain_dfu_commands_are_never_replayed_and_still_leave_debug_mode() {
    let mut steps = setup();
    steps.extend([
        Step::Command(
            *b"VDMs",
            vec![
                0x33, 0x12, 0x80, 0xac, 0x05, 0x06, 0x01, 0, 0, 0, 0, 0x01, 0x80,
            ],
            Err("uncertain write"),
        ),
        command(b"DBMa", &[0]),
    ]);
    script(steps, Some("uncertain write"));
    script(
        vec![
            read(0x3f, &[1]),
            read(3, b"APP\0"),
            command(b"LOCK", b"BcaM"),
            Step::Command(*b"DBMa", vec![1], Err("uncertain mode change")),
            command(b"DBMa", &[0]),
        ],
        Some("uncertain mode change"),
    );
}

#[test]
fn nak_truncated_reply_and_missing_ack_fail_without_claiming_dfu_success() {
    for (reply, expected) in [
        (&[8, 0x92, 0x80, 0xac, 5][..], "did not acknowledge"),
        (&[8, 0x52][..], "truncated"),
    ] {
        let mut steps = setup();
        steps.extend([vdm(), read(0x4d, reply), command(b"DBMa", &[0])]);
        script(steps, Some(expected));
    }
    let mut steps = setup();
    steps.push(vdm());
    steps.extend((0..16).map(|_| read(0x4d, &[7])));
    steps.push(command(b"DBMa", &[0]));
    script(steps, Some("No reply"));
}

#[test]
fn cleanup_failure_after_an_ack_is_reported() {
    let mut steps = setup();
    steps.extend([
        vdm(),
        read(0x4d, &[8, 0x52, 0x80, 0xac, 5]),
        Step::Command(*b"DBMa", vec![0], Ok(3)),
    ]);
    script(steps, Some("leaving USB-C debug mode"));
}

#[test]
fn controller_stays_in_debug_mode_until_dfu_detection_and_cleans_up_on_timeout() {
    use std::cell::Cell;

    struct Waiting<'a> {
        script: Script,
        waited: &'a Cell<bool>,
    }
    impl Controller for Waiting<'_> {
        fn read(&mut self, register: u8) -> Result<Vec<u8>> {
            self.script.read(register)
        }
        fn command(&mut self, name: [u8; 4], args: &[u8]) -> Result<u8> {
            if name == *b"DBMa" && args == [0] {
                assert!(
                    self.waited.get(),
                    "controller mode restored before DFU detection"
                );
            }
            self.script.command(name, args)
        }
    }
    for detected in [true, false] {
        let waited = Cell::new(false);
        let mut steps = setup();
        steps.extend([
            vdm(),
            read(0x4d, &[8, 0x52, 0x80, 0xac, 5]),
            command(b"DBMa", &[0]),
        ]);
        let mut controller = Waiting {
            script: Script(steps.into()),
            waited: &waited,
        };
        let result = enter_dfu(&mut controller, *b"BcaM", || {
            waited.set(true);
            anyhow::ensure!(detected, "target did not appear in DFU");
            Ok(())
        });
        assert_eq!(result.is_ok(), detected);
        assert!(waited.get());
        assert!(controller.script.0.is_empty());
    }
}
