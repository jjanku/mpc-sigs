use core::slice;

use crate::context::{Keygen, KeygenResult, RoundOutputType};
use crate::protocols::gg18;

#[repr(C)]
pub enum Algorithm {
    Gg18,
}

// TODO: generalize this to just context/task? (Keygen, Signing -> Context)
pub struct KeygenContext {
    keygen: Option<Box<dyn Keygen>>,
    data: Option<Vec<u8>>,
    err: Option<Box<dyn std::error::Error>>,
}

impl KeygenContext {
    fn init(alg: Algorithm, data: &[u8]) -> Self {
        let res = match alg {
            Algorithm::Gg18 => gg18::KeygenContext::init(data),
        };

        match res {
            Ok(out) => KeygenContext {
                keygen: Some(match out.output {
                    RoundOutputType::Inter(keygen) => keygen,
                    RoundOutputType::Final(_) => unreachable!(),
                }),
                data: Some(out.data_out),
                err: None,
            },
            Err(err) => KeygenContext {
                keygen: None,
                data: None,
                err: Some(err),
            },
        }
    }

    fn advance(&mut self, data: &[u8]) {}
}

#[no_mangle]
pub extern "C" fn keygen_init(alg: Algorithm, data: *const u8, len: usize) -> *mut KeygenContext {
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let context = Box::new(KeygenContext::init(alg, slice));
    Box::into_raw(context)
}

#[no_mangle]
pub extern "C" fn keygen_advance(context: *mut KeygenContext, data: *const u8, len: usize) {
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let context = unsafe { &mut *context };

    context.advance(slice);
}

// #[no_mangle]
// pub extern "C" fn gg18_context_data(context: *const Gg18Context) -> *const u8 {
//     let ctx = unsafe { &*context };
//     ctx.data_out.as_ptr()
// }

// #[no_mangle]
// pub extern "C" fn gg18_context_data_size(context: *const Gg18Context) -> usize {
//     let ctx = unsafe { &*context };
//     ctx.data_out.len()
// }

#[no_mangle]
pub extern "C" fn keygen_free(context: *mut KeygenContext) {
    unsafe { Box::from_raw(context) };
}
