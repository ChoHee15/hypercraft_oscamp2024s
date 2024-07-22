use core::sync::atomic::AtomicU64;

use spin::Mutex;

// pub static OS_TIMER: AtomicU64 = AtomicU64::new(0);
/// os timer
pub static OS_TIMER: Mutex<u64> = Mutex::new(0);

/// update os timer
pub fn update_os_timer(os_timer: u64) {
    // OS_TIMER.fetch_update(set_order, fetch_order, f)
    let mut guard = OS_TIMER.lock();
    *guard = os_timer / 100;
}