mod meesign {
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}

use meesign::{Gg18KeyGenInit, Gg18Message, Gg18SignInit};
use mpecdsa::{gg18_key_gen::*, gg18_sign::*};
use prost::Message;
use serde::{Deserialize, Serialize};

fn deserialize_vec<'de, T: Deserialize<'de>>(vec: &'de [Vec<u8>]) -> serde_json::Result<Vec<T>> {
    vec.into_iter()
        .map(|item| serde_json::from_slice::<T>(item))
        .collect()
}

fn inflate<T: Clone>(value: T, n: usize) -> Vec<T> {
    std::iter::repeat(value).take(n).collect()
}

/// Serialize value and repeat the result n times,
/// as the current server always expects one message for each party
fn serialize_bcast<T: Serialize>(value: &T, n: usize) -> serde_json::Result<Vec<Vec<u8>>> {
    let ser = serde_json::to_vec(value)?;
    Ok(inflate(ser, n))
}

/// Serialize vector of unicast messages
fn serialize_uni<T: Serialize>(vec: Vec<T>) -> serde_json::Result<Vec<Vec<u8>>> {
    vec.iter().map(|item| serde_json::to_vec(item)).collect()
}

/// Decode a protobuf message from the server
fn unpack(data: &[u8]) -> Result<Vec<Vec<u8>>, prost::DecodeError> {
    let msgs = Gg18Message::decode(data)?.message;
    Ok(msgs)
}

/// Encode msgs as a protobuf message for the server
fn pack(msgs: Vec<Vec<u8>>) -> Vec<u8> {
    Gg18Message { message: msgs }.encode_to_vec()
}

pub enum KeygenContext {
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
    pub fn init(data: &[u8]) -> ContextResult<Self> {
        let msg = Gg18KeyGenInit::decode(data)?;

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let (out, c1) = gg18_key_gen_1(parties, threshold, index)?;
        let ser = serialize_bcast(&out, msg.parties as usize - 1)?;
        Ok((KeygenContext::C1(c1), pack(ser)))
    }

    pub fn advance(self, data: &[u8]) -> ContextResult<Self> {
        let msgs = unpack(data)?;
        let n = msgs.len();

        let (c, data_out) = match self {
            KeygenContext::C1(c1) => {
                let (out, c2) = gg18_key_gen_2(deserialize_vec(&msgs)?, c1)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C2(c2), ser)
            }
            KeygenContext::C2(c2) => {
                let (outs, c3) = gg18_key_gen_3(deserialize_vec(&msgs)?, c2)?;
                let ser = serialize_uni(outs)?;
                (Self::C3(c3), ser)
            }
            KeygenContext::C3(c3) => {
                let (out, c4) = gg18_key_gen_4(deserialize_vec(&msgs)?, c3)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C4(c4), ser)
            }
            KeygenContext::C4(c4) => {
                let (out, c5) = gg18_key_gen_5(deserialize_vec(&msgs)?, c4)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C5(c5), ser)
            }
            KeygenContext::C5(c5) => {
                let c = gg18_key_gen_6(deserialize_vec(&msgs)?, c5)?;
                // FIXME: add separate inflate function?
                // maybe it shouldn't be inflated at all
                let ser = inflate(c.pk.to_bytes(true).to_vec(), n);
                (Self::Finished(c), ser)
            }
            KeygenContext::Finished(_) => unreachable!(),
        };

        Ok((c, pack(data_out)))
    }
}

pub enum SignContext {
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
    pub fn init(context: &GG18SignContext, data: &[u8]) -> ContextResult<Self> {
        let msg = Gg18SignInit::decode(data)?;

        // FIXME: proto fields should have matching types, i.e. i16, not i32
        let indices: Vec<u16> = msg.indices.into_iter().map(|i| i as u16).collect();
        let parties = indices.len();

        let (out, c1) = gg18_sign1(context.clone(), indices, msg.index as usize, msg.hash)?;
        let ser = serialize_bcast(&out, parties - 1)?;
        Ok((SignContext::C1(c1), pack(ser)))
    }

    pub fn advance(self, data: &[u8]) -> ContextResult<Self> {
        let msgs = unpack(data)?;
        let n = msgs.len();

        let (c, data_out) = match self {
            SignContext::C1(c1) => {
                let (outs, c2) = gg18_sign2(deserialize_vec(&msgs)?, c1)?;
                let ser = serialize_uni(outs)?;
                (Self::C2(c2), ser)
            }
            SignContext::C2(c2) => {
                let (out, c3) = gg18_sign3(deserialize_vec(&msgs)?, c2)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C3(c3), ser)
            }
            SignContext::C3(c3) => {
                let (out, c4) = gg18_sign4(deserialize_vec(&msgs)?, c3)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C4(c4), ser)
            }
            SignContext::C4(c4) => {
                let (out, c5) = gg18_sign5(deserialize_vec(&msgs)?, c4)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C5(c5), ser)
            }
            SignContext::C5(c5) => {
                let (out, c6) = gg18_sign6(deserialize_vec(&msgs)?, c5)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C6(c6), ser)
            }
            SignContext::C6(c6) => {
                let (out, c7) = gg18_sign7(deserialize_vec(&msgs)?, c6)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C7(c7), ser)
            }
            SignContext::C7(c7) => {
                let (out, c8) = gg18_sign8(deserialize_vec(&msgs)?, c7)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C8(c8), ser)
            }
            SignContext::C8(c8) => {
                let (out, c9) = gg18_sign9(deserialize_vec(&msgs)?, c8)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::C9(c9), ser)
            }
            SignContext::C9(c9) => {
                let sig = gg18_sign10(deserialize_vec(&msgs)?, c9)?;
                (Self::Finished(sig), vec![])
            }
            SignContext::Finished(_) => unreachable!(),
        };

        Ok((c, pack(data_out)))
    }
}
