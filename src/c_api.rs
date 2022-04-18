use crate::protocols::gg18::KeygenContext;
use core::slice;

pub struct Gg18Context {
    keygen_ctx: Option<KeygenContext>,
    data_out: Vec<u8>,
}

impl Gg18Context {
    fn init(data: &[u8]) -> Self {
        let (ctx, out) = KeygenContext::init(data).unwrap();
        Gg18Context {
            keygen_ctx: Some(ctx),
            data_out: out,
        }
    }

    fn keygen_advance(&mut self, data: &[u8]) {
        let (new_ctx, out) = self.keygen_ctx.take().unwrap().advance(data).unwrap();
        self.keygen_ctx = Some(new_ctx);
        self.data_out = out;
    }
}

#[no_mangle]
pub extern "C" fn gg18_keygen_init(data: *const u8, len: usize) -> *mut Gg18Context {
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let context = Box::new(Gg18Context::init(slice));
    Box::into_raw(context)
}

#[no_mangle]
pub extern "C" fn gg18_keygen_advance(context: *mut Gg18Context, data: *const u8, len: usize) {
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let ctx = unsafe { &mut *context };

    ctx.keygen_advance(slice);
}

#[no_mangle]
pub extern "C" fn gg18_context_data(context: *const Gg18Context) -> *const u8 {
    let ctx = unsafe { &*context };
    ctx.data_out.as_ptr()
}

#[no_mangle]
pub extern "C" fn gg18_context_data_size(context: *const Gg18Context) -> usize {
    let ctx = unsafe { &*context };
    ctx.data_out.len()
}

#[no_mangle]
pub extern "C" fn gg18_keygen_finished(context: *const Gg18Context) -> bool {
    let ctx = unsafe { &*context };
    match ctx.keygen_ctx {
        Some(KeygenContext::Finished(_)) => true,
        _ => false,
    }
}

#[no_mangle]
pub extern "C" fn gg18_context_pk(context: *mut Gg18Context) -> *const u8 {
    let ctx = unsafe { &*context };
    match &ctx.keygen_ctx {
        Some(KeygenContext::Finished(sign_ctx)) => sign_ctx.pk.to_bytes(true).as_ptr(),
        _ => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn gg18_context_free(context: *mut Gg18Context) {
    unsafe { Box::from_raw(context) };
}
