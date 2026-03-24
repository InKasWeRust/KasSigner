// KasSigner — Flow Counter Anti-Glitch
// 100% Rust, no-std
//
// Execution flow counter to detect fault injection.
//
// A physical attacker could use voltage glitching or
// electromagnetic fault injection para "saltar" instrucciones.
// El flow counter detecta esto: si una etapa se salta, el contador
// final value will not match the expected value.
//
// USO:
//   flow::reset();
//   flow::step();  // etapa 1
//   do_thing_1();
//   flow::step();  // etapa 2
//   do_thing_2();
//   flow::step();  // etapa 3
//   if flow::count() != 3 { panic!("glitch detected"); }
//
// LIMITACIONES:
//   - A sophisticated glitch could increment the counter without executing
//     the actual stage. Combine with canaries and redundant verification.
//   - El contador usa una variable global mutable (necesario en no-std
//     sin allocator). Acceso serializado con compiler_fence.

use core::sync::atomic::{compiler_fence, Ordering};

// Contador de etapas (variable global mutable)
static mut COUNTER: u32 = 0;

// Resetea el contador a cero.
#[inline(never)]
/// Reset the flow integrity counter to zero.
pub fn reset() {
    compiler_fence(Ordering::SeqCst);
    unsafe { COUNTER = 0; }
    compiler_fence(Ordering::SeqCst);
}

// Incrementa el contador en 1.
#[inline(never)]
/// Increment the flow counter by one (marks a completed stage).
pub fn step() {
    compiler_fence(Ordering::SeqCst);
    unsafe { COUNTER += 1; }
    compiler_fence(Ordering::SeqCst);
}

// Lee el valor actual del contador.
#[inline(never)]
/// Read the current flow counter value.
pub fn count() -> u32 {
    compiler_fence(Ordering::SeqCst);
    let val = unsafe { COUNTER };
    compiler_fence(Ordering::SeqCst);
    val
}

// Verifica que el contador tiene el valor esperado.
// Retorna true si coincide.
#[inline(never)]
/// Verify the counter matches the expected stage count.
/// Double-reads to resist voltage glitching attacks.
pub fn verify(expected: u32) -> bool {
    let actual = count();
    compiler_fence(Ordering::SeqCst);

    // Double read to make comparison glitching harder
    let actual2 = count();
    compiler_fence(Ordering::SeqCst);

    actual == expected && actual2 == expected
}
