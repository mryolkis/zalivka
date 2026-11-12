use super::*;

#[test]
fn completion_before_wait_stays_ready_until_the_next_poll() {
    let ready = Arc::new(CompletionReady::default());
    assert!(!ready.wait(Duration::ZERO));
    let waker = std::task::Waker::from(ready.clone());
    waker.wake_by_ref();
    assert!(ready.wait(Duration::ZERO));
    assert!(ready.wait(Duration::ZERO));
    ready.clear();
    assert!(!ready.wait(Duration::ZERO));
    waker.wake();
    assert!(ready.wait(Duration::ZERO));
}

#[test]
fn completion_wakes_all_service_workers_without_consuming_input() {
    let ready = Arc::new(CompletionReady::default());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let ready = ready.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                ready.wait(Duration::from_secs(5))
            })
        })
        .collect();
    barrier.wait();
    ready.signal();
    for worker in workers {
        assert!(worker.join().unwrap());
    }
    assert!(ready.wait(Duration::ZERO));
}
