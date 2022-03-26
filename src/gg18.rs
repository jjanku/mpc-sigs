mod meesign {
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}

use bincode::{deserialize, serialize};
use core::slice;
use meesign::{Gg18KeyGenInit, Gg18Message};
use mpecdsa::gg18_key_gen::*;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{iter, vec};

fn deserialize_vec<'de, T: Deserialize<'de>>(vec: &'de [Vec<u8>]) -> Vec<T> {
    vec.into_iter()
        .map(|item| deserialize::<T>(item).unwrap())
        .collect()
}

fn serialize_inflate<T: Serialize>(value: &T, n: usize) -> Vec<Vec<u8>> {
    iter::repeat(serialize(value).unwrap()).take(n).collect()
}

fn unpack(data: &[u8]) -> Vec<Vec<u8>> {
    Gg18Message::decode(data).unwrap().message
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

impl KeygenContext {
    fn init(data: &[u8]) -> (Self, Vec<u8>) {
        let msg = Gg18KeyGenInit::decode(data).unwrap();
        let (out, c1) = gg18_key_gen_1(msg.parties as u16, msg.threshold as u16, msg.index as u16);
        (
            KeygenContext::C1(c1),
            pack(serialize_inflate(&out, msg.parties as usize - 1)),
        )
    }

    fn advance(self, data: &[u8]) -> (Self, Vec<u8>) {
        let parts = unpack(data);
        let n = parts.len() - 1;

        let (c, data_out) = match self {
            KeygenContext::C1(c1) => {
                let (out, c2) = gg18_key_gen_2(deserialize_vec(&parts), c1);
                let outs = serialize_inflate(&out, n);
                (Self::C2(c2), outs)
            }
            KeygenContext::C2(c2) => {
                let (out, c3) = gg18_key_gen_3(deserialize_vec(&parts), c2);
                let outs: Vec<Vec<u8>> = out
                    .iter()
                    .map(|scalar| serialize(scalar).unwrap())
                    .collect();
                (Self::C3(c3), outs)
            }
            KeygenContext::C3(c3) => {
                let (out, c4) = gg18_key_gen_4(deserialize_vec(&parts), c3);
                let outs = serialize_inflate(&out, n);
                (Self::C4(c4), outs)
            }
            KeygenContext::C4(c4) => {
                let (out, c5) = gg18_key_gen_5(deserialize_vec(&parts), c4);
                let outs = serialize_inflate(&out, n);
                (Self::C5(c5), outs)
            }
            KeygenContext::C5(c5) => {
                let c = gg18_key_gen_6(deserialize_vec(&parts), c5);
                (Self::Finished(c), vec![])
            }
            KeygenContext::Finished(_) => unreachable!(),
        };

        (c, pack(data_out))
    }
}

pub struct Gg18Context {
    keygen_ctx: Option<KeygenContext>,
    data_out: Vec<u8>,
}

impl Gg18Context {
    fn init(data: &[u8]) -> Self {
        let (ctx, out) = KeygenContext::init(data);
        Gg18Context {
            keygen_ctx: Some(ctx),
            data_out: out,
        }
    }

    fn keygen_advance(&mut self, data: &[u8]) {
        let (new_ctx, out) = self.keygen_ctx.take().unwrap().advance(data);
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
pub extern "C" fn gg18_context_free(context: *mut Gg18Context) {
    unsafe { Box::from_raw(context) };
}
