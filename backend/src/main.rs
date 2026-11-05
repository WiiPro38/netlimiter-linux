mod monitor;
mod netlink;
mod nft;
mod protocol;
mod rules;
mod server;

use std::thread;

/// Blocks SIGTERM/SIGINT in every thread (the mask is inherited, so this must
/// run before any thread is spawned) and handles them in one dedicated thread
/// that removes the nft table and the socket before exiting.
fn install_signal_handler() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        thread::spawn(move || {
            let mut sig: libc::c_int = 0;
            libc::sigwait(&set, &mut sig);
            eprintln!("netlimiterd: signal {sig}, cleaning up");
            server::shutdown();
            std::process::exit(0);
        });
    }
}

fn main() {
    install_signal_handler();
    let state = server::AppState::new();
    let sampler_state = std::sync::Arc::clone(&state);
    thread::spawn(move || server::sampler_loop(sampler_state));
    if let Err(err) = server::serve(state) {
        eprintln!("fatal: {err}");
        server::shutdown();
        std::process::exit(1);
    }
}
