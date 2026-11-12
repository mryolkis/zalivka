use super::*;
use std::{collections::VecDeque, task::Poll};

#[derive(Default)]
struct Events {
    pending: VecDeque<()>,
    waker: Option<Waker>,
}

impl Stream for Events {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        self.waker = Some(cx.waker().clone());
        match self.pending.pop_front() {
            Some(event) => Poll::Ready(Some(event)),
            None => Poll::Pending,
        }
    }
}

#[derive(Default)]
struct CountWake(std::sync::atomic::AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn device_changes_are_drained_and_the_next_notification_wakes_the_caller() {
    let notifications = Arc::new(CountWake::default());
    let waker = Waker::from(notifications.clone());
    let mut events = Events {
        pending: [(); 3].into(),
        ..Default::default()
    };
    assert!(poll_changes(&mut events, &waker));
    assert!(events.pending.is_empty());
    assert!(!poll_changes(&mut events, &waker));
    events.pending.push_back(());
    events.waker.take().unwrap().wake();
    assert_eq!(
        notifications.0.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(poll_changes(&mut events, &waker));
}

#[test]
fn device_event_storms_yield_and_schedule_the_remaining_events() {
    let notifications = Arc::new(CountWake::default());
    let waker = Waker::from(notifications.clone());
    let mut events = Events {
        pending: [(); 100].into(),
        ..Default::default()
    };
    assert!(poll_changes(&mut events, &waker));
    assert_eq!(events.pending.len(), 36);
    assert_eq!(
        notifications.0.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(poll_changes(&mut events, &waker));
    assert!(events.pending.is_empty());
}

#[test]
fn unavailable_device_notifications_keep_the_polling_fallback_usable() {
    let mut events = DeviceEvents(None);
    assert!(!events.available());
    assert!(!events.poll(Waker::noop()));
    events.wait(Duration::ZERO);
    assert!(!events.poll(Waker::noop()));
}
