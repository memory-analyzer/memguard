// tests/fixtures/leaky_rust/src/main.rs
// ----------------------------------------
// Intentionally unsound Rust code for Miri + memguard analysis.
// Run: cargo +nightly miri run
//      cargo +nightly miri test

use std::mem;
use std::ptr;

// ── 1. mem::forget — intentional leak ─────────────────────────────────────────
fn mem_forget_leak() {
    let data: Vec<u8> = vec![0u8; 1024 * 1024]; // 1MB
    mem::forget(data);  // destructor never runs → 1MB leaked
}

// ── 2. Box::into_raw without Box::from_raw ────────────────────────────────────
fn raw_pointer_leak() -> *mut i32 {
    let b = Box::new(42i32);
    Box::into_raw(b)  // caller never calls Box::from_raw → leaked
}

// ── 3. Use of uninitialized memory via unsafe ─────────────────────────────────
fn uninit_read() -> i32 {
    unsafe {
        let x: i32 = mem::uninitialized();  // deprecated in 1.39 for good reason
        x
    }
}

// ── 4. Raw pointer arithmetic OOB ────────────────────────────────────────────
fn ptr_oob() {
    let arr = [1i32, 2, 3, 4, 5];
    unsafe {
        let p = arr.as_ptr();
        let oob = ptr::read(p.add(10));  // out of bounds — UB
        println!("{}", oob);
    }
}

// ── 5. Use-after-free via raw pointer ─────────────────────────────────────────
fn use_after_free() {
    let b = Box::new(100i32);
    let raw = Box::into_raw(b);
    unsafe {
        drop(Box::from_raw(raw));  // free
        println!("{}", *raw);      // use after free — UB
    }
}

// ── 6. Double free ────────────────────────────────────────────────────────────
fn double_free() {
    let b = Box::new(42i32);
    let raw = Box::into_raw(b);
    unsafe {
        drop(Box::from_raw(raw));
        drop(Box::from_raw(raw));  // double free — UB
    }
}

// ── 7. Rc cycle (not UB but leaks memory) ─────────────────────────────────────
use std::rc::Rc;
use std::cell::RefCell;

struct RcNode {
    val:  i32,
    next: Option<Rc<RefCell<RcNode>>>,
}

fn rc_cycle() {
    let a = Rc::new(RefCell::new(RcNode { val: 1, next: None }));
    let b = Rc::new(RefCell::new(RcNode { val: 2, next: None }));
    a.borrow_mut().next = Some(Rc::clone(&b));
    b.borrow_mut().next = Some(Rc::clone(&a));  // cycle — neither will be dropped
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let which = args.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

    match which {
        1 => { println!("1. mem::forget leak"); mem_forget_leak(); }
        2 => { println!("2. raw pointer leak"); let _ = raw_pointer_leak(); }
        3 => { println!("3. uninit read"); println!("{}", uninit_read()); }
        4 => { println!("4. OOB read"); ptr_oob(); }
        5 => { println!("5. use after free"); use_after_free(); }
        6 => { println!("6. double free"); double_free(); }
        7 => { println!("7. Rc cycle"); rc_cycle(); }
        _ => {
            println!("Running all safe demos...");
            mem_forget_leak();
            let _ = raw_pointer_leak();
            rc_cycle();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_forget() {
        mem_forget_leak();  // Miri will flag this
    }

    #[test]
    fn test_rc_cycle() {
        rc_cycle();  // Miri reports leak
    }
}
