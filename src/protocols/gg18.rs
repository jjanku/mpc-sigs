mod meesign {
    include!(concat!(env!("OUT_DIR"), "/meesign.rs"));
}

use crate::protocol::*;
use meesign::{Gg18KeyGenInit, Gg18Message, Gg18SignInit};
use mpecdsa::{gg18_key_gen::*, gg18_sign::*};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::vec;

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

pub struct Gg18Keygen {
    context: Option<KeygenContext>,
}

impl Gg18Keygen {
    pub fn new() -> Box<Self> {
        Box::new(Gg18Keygen { context: None })
    }
}

impl Protocol for Gg18Keygen {
    fn update(&mut self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        // FIXME: return error on reinit?
        let (c, data_out) = match self.context.take() {
            None => KeygenContext::init(data),
            Some(c) => c.advance(data),
        }?;
        self.context = Some(c);
        Ok(data_out)
    }

    fn output(&self) -> ProtocolResult<ProtocolOutput> {
        todo![]
    }
}

enum KeygenContext {
    R1(GG18KeyGenContext1),
    R2(GG18KeyGenContext2),
    R3(GG18KeyGenContext3),
    R4(GG18KeyGenContext4),
    R5(GG18KeyGenContext5),
    Done(GG18SignContext),
}

// TODO: use trait objects like tofn?
// maybe macros could help as well?

impl KeygenContext {
    fn init(data: &[u8]) -> ProtocolResult<(KeygenContext, Vec<u8>)> {
        let msg = Gg18KeyGenInit::decode(data)?;

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let (out, c1) = gg18_key_gen_1(parties, threshold, index)?;
        let ser = serialize_bcast(&out, msg.parties as usize - 1)?;

        Ok((KeygenContext::R1(c1), pack(ser)))
    }

    fn advance(self, data: &[u8]) -> ProtocolResult<(KeygenContext, Vec<u8>)> {
        let msgs = unpack(data)?;
        let n = msgs.len();

        let (c, ser) = match self {
            KeygenContext::R1(c1) => {
                let (out, c2) = gg18_key_gen_2(deserialize_vec(&msgs)?, c1)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R2(c2), ser)
            }
            KeygenContext::R2(c2) => {
                let (outs, c3) = gg18_key_gen_3(deserialize_vec(&msgs)?, c2)?;
                let ser = serialize_uni(outs)?;
                (Self::R3(c3), ser)
            }
            KeygenContext::R3(c3) => {
                let (out, c4) = gg18_key_gen_4(deserialize_vec(&msgs)?, c3)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R4(c4), ser)
            }
            KeygenContext::R4(c4) => {
                let (out, c5) = gg18_key_gen_5(deserialize_vec(&msgs)?, c4)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R5(c5), ser)
            }
            KeygenContext::R5(c5) => {
                let c = gg18_key_gen_6(deserialize_vec(&msgs)?, c5)?;
                let ser = inflate(c.pk.to_bytes(true).to_vec(), n);
                (Self::Done(c), ser)
            }
            KeygenContext::Done(_) => todo!(),
        };

        Ok((c, pack(ser)))
    }
}

impl Group for GG18SignContext {
    fn sign(&self) -> Box<dyn Protocol> {
        Box::new(Gg18Sign {
            group: self.clone(),
            context: None,
        })
    }
}

pub struct Gg18Sign {
    group: GG18SignContext,
    context: Option<SignContext>,
}

impl Protocol for Gg18Sign {
    fn update(&mut self, data: &[u8]) -> ProtocolResult<Vec<u8>> {
        let (c, data_out) = match self.context.take() {
            None => SignContext::init(self.group.clone(), data),
            Some(c) => c.advance(data),
        }?;
        self.context = Some(c);
        Ok(data_out)
    }

    fn output(&self) -> ProtocolResult<ProtocolOutput> {
        todo!()
    }
}

enum SignContext {
    R1(GG18SignContext1),
    R2(GG18SignContext2),
    R3(GG18SignContext3),
    R4(GG18SignContext4),
    R5(GG18SignContext5),
    R6(GG18SignContext6),
    R7(GG18SignContext7),
    R8(GG18SignContext8),
    R9(GG18SignContext9),
    Done(Vec<u8>),
}

impl SignContext {
    fn init(context: GG18SignContext, data: &[u8]) -> ProtocolResult<(SignContext, Vec<u8>)> {
        let msg = Gg18SignInit::decode(data)?;

        // FIXME: proto fields should have matching types, i.e. i16, not i32
        let indices: Vec<u16> = msg.indices.into_iter().map(|i| i as u16).collect();
        let parties = indices.len();

        let (out, c1) = gg18_sign1(context, indices, msg.index as usize, msg.hash)?;
        let ser = serialize_bcast(&out, parties - 1)?;

        Ok((SignContext::R1(c1), pack(ser)))
    }

    fn advance(self, data: &[u8]) -> ProtocolResult<(SignContext, Vec<u8>)> {
        let msgs = unpack(data)?;
        let n = msgs.len();

        let (c, ser) = match self {
            SignContext::R1(c1) => {
                let (outs, c2) = gg18_sign2(deserialize_vec(&msgs)?, c1)?;
                let ser = serialize_uni(outs)?;
                (Self::R2(c2), ser)
            }
            SignContext::R2(c2) => {
                let (out, c3) = gg18_sign3(deserialize_vec(&msgs)?, c2)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R3(c3), ser)
            }
            SignContext::R3(c3) => {
                let (out, c4) = gg18_sign4(deserialize_vec(&msgs)?, c3)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R4(c4), ser)
            }
            SignContext::R4(c4) => {
                let (out, c5) = gg18_sign5(deserialize_vec(&msgs)?, c4)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R5(c5), ser)
            }
            SignContext::R5(c5) => {
                let (out, c6) = gg18_sign6(deserialize_vec(&msgs)?, c5)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R6(c6), ser)
            }
            SignContext::R6(c6) => {
                let (out, c7) = gg18_sign7(deserialize_vec(&msgs)?, c6)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R7(c7), ser)
            }
            SignContext::R7(c7) => {
                let (out, c8) = gg18_sign8(deserialize_vec(&msgs)?, c7)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R8(c8), ser)
            }
            SignContext::R8(c8) => {
                let (out, c9) = gg18_sign9(deserialize_vec(&msgs)?, c8)?;
                let ser = serialize_bcast(&out, n)?;
                (Self::R9(c9), ser)
            }
            SignContext::R9(c9) => {
                let sig = gg18_sign10(deserialize_vec(&msgs)?, c9)?;
                (Self::Done(sig), vec![])
            }
            SignContext::Done(_) => todo!(),
        };

        Ok((c, pack(ser)))
    }
}
