//@compile-flags: -Zmiri-genmc

fn main() {
    let t0 = std::thread::spawn(thread_func);
    let t1 = std::thread::spawn(thread_func);
    t0.join().unwrap();
    t1.join().unwrap();
}

fn thread_func() {}
