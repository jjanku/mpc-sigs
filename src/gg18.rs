mod meesign {
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}

use core::slice;
use meesign::{Gg18KeyGenInit, Gg18Message, Gg18SignInit};
use mpecdsa::{gg18_key_gen::*, gg18_sign::*};
use prost::Message;
use serde::{Deserialize, Serialize};

fn deserialize_vec<'de, T: Deserialize<'de>>(vec: &'de [Vec<u8>]) -> serde_json::Result<Vec<T>> {
    vec.into_iter()
        .map(|item| serde_json::from_slice::<T>(item))
        .collect()
}

fn serialize_inflate<T: Serialize>(value: &T, n: usize) -> serde_json::Result<Vec<Vec<u8>>> {
    let ser = serde_json::to_vec(value)?;
    Ok(std::iter::repeat(ser).take(n).collect())
}

fn serialize_vec<T: Serialize>(vec: Vec<T>) -> serde_json::Result<Vec<Vec<u8>>> {
    vec.iter().map(|item| serde_json::to_vec(item)).collect()
}

fn unpack(data: &[u8]) -> Result<Vec<Vec<u8>>, prost::DecodeError> {
    let msgs = Gg18Message::decode(data)?.message;
    Ok(msgs)
}

fn pack(msgs: Vec<Vec<u8>>) -> Vec<u8> {
    Gg18Message { message: msgs }.encode_to_vec()
}

enum KeygenContext {
    C1(GG18KeyGenContext1),
    C2(GG18KeyGenContext2),
    C3(GG18KeyGenContext3),
    C4(GG18KeyGenContext4),
    C5(GG18KeyGenContext5),
    Finished(GG18SignContext),
}

type ContextResult<T> = Result<(T, Vec<u8>), Box<dyn std::error::Error>>;

// TODO: use trait objects like tofn?
// maybe macros could help as well?

impl KeygenContext {
    fn init(data: &[u8]) -> ContextResult<Self> {
        let msg = Gg18KeyGenInit::decode(data)?;

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let (out, c1) = gg18_key_gen_1(parties, threshold, index)?;
        let ser = serialize_inflate(&out, msg.parties as usize - 1)?;
        Ok((KeygenContext::C1(c1), pack(ser)))
    }

    fn advance(self, data: &[u8]) -> ContextResult<Self> {
        let parts = unpack(data)?;
        let n = parts.len();

        let (c, data_out) = match self {
            KeygenContext::C1(c1) => {
                let (out, c2) = gg18_key_gen_2(deserialize_vec(&parts)?, c1)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C2(c2), outs)
            }
            KeygenContext::C2(c2) => {
                let (out, c3) = gg18_key_gen_3(deserialize_vec(&parts)?, c2)?;
                let outs = serialize_vec(out)?;
                (Self::C3(c3), outs)
            }
            KeygenContext::C3(c3) => {
                let (out, c4) = gg18_key_gen_4(deserialize_vec(&parts)?, c3)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C4(c4), outs)
            }
            KeygenContext::C4(c4) => {
                let (out, c5) = gg18_key_gen_5(deserialize_vec(&parts)?, c4)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C5(c5), outs)
            }
            KeygenContext::C5(c5) => {
                let c = gg18_key_gen_6(deserialize_vec(&parts)?, c5)?;
                // FIXME: add separate inflate function?
                // maybe it shouldn't be inflated at all
                let outs = std::iter::repeat(c.pk.to_bytes(true).to_vec())
                    .take(n)
                    .collect();
                (Self::Finished(c), outs)
            }
            KeygenContext::Finished(_) => unreachable!(),
        };

        Ok((c, pack(data_out)))
    }
}

enum SignContext {
    C1(GG18SignContext1),
    C2(GG18SignContext2),
    C3(GG18SignContext3),
    C4(GG18SignContext4),
    C5(GG18SignContext5),
    C6(GG18SignContext6),
    C7(GG18SignContext7),
    C8(GG18SignContext8),
    C9(GG18SignContext9),
    Finished(Vec<u8>),
}

impl SignContext {
    fn init(context: &GG18SignContext, data: &[u8]) -> ContextResult<Self> {
        let msg = Gg18SignInit::decode(data)?;

        // FIXME: proto fields should have matching types, i.e. i16, not i32
        let indices: Vec<u16> = msg.indices.into_iter().map(|i| i as u16).collect();
        let parties = indices.len();

        let (out, c1) = gg18_sign1(context.clone(), indices, msg.index as usize, msg.hash)?;
        let ser = serialize_inflate(&out, parties - 1)?;
        Ok((SignContext::C1(c1), pack(ser)))
    }

    fn advance(self, data: &[u8]) -> ContextResult<Self> {
        let parts = unpack(data)?;
        let n = parts.len();

        let (c, data_out) = match self {
            SignContext::C1(c1) => {
                let (out, c2) = gg18_sign2(deserialize_vec(&parts)?, c1)?;
                let outs = serialize_vec(out)?;
                (Self::C2(c2), outs)
            }
            SignContext::C2(c2) => {
                let (out, c3) = gg18_sign3(deserialize_vec(&parts)?, c2)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C3(c3), outs)
            }
            SignContext::C3(c3) => {
                let (out, c4) = gg18_sign4(deserialize_vec(&parts)?, c3)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C4(c4), outs)
            }
            SignContext::C4(c4) => {
                let (out, c5) = gg18_sign5(deserialize_vec(&parts)?, c4)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C5(c5), outs)
            }
            SignContext::C5(c5) => {
                let (out, c6) = gg18_sign6(deserialize_vec(&parts)?, c5)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C6(c6), outs)
            }
            SignContext::C6(c6) => {
                let (out, c7) = gg18_sign7(deserialize_vec(&parts)?, c6)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C7(c7), outs)
            }
            SignContext::C7(c7) => {
                let (out, c8) = gg18_sign8(deserialize_vec(&parts)?, c7)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C8(c8), outs)
            }
            SignContext::C8(c8) => {
                let (out, c9) = gg18_sign9(deserialize_vec(&parts)?, c8)?;
                let outs = serialize_inflate(&out, n)?;
                (Self::C9(c9), outs)
            }
            SignContext::C9(c9) => {
                let sig = gg18_sign10(deserialize_vec(&parts)?, c9)?;
                (Self::Finished(sig), vec![])
            }
            SignContext::Finished(_) => unreachable!(),
        };

        Ok((c, pack(data_out)))
    }
}

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
