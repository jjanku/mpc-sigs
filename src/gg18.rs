mod meesign {
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}

use bincode::{deserialize, serialize};
use meesign::{Gg18KeyGenInit, Gg18Message};
use mpecdsa::gg18_key_gen::*;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::iter;

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
