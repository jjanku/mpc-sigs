use core::slice;
use std::ptr::{null, null_mut};

use crate::protocol::*;
use crate::protocols::gg18;

#[repr(C)]
pub enum Algorithm {
    Gg18,
}

pub struct ProtoWrapper {
    // FIXME: can we avoid the double indirection?
    proto: Box<dyn Protocol>,
    res: Option<ProtocolResult<Vec<u8>>>,
}

#[repr(C)]
pub struct Buffer {
    ptr: *const u8,
    len: usize,
}

#[no_mangle]
pub extern "C" fn protocol_new(alg: Algorithm) -> *mut ProtoWrapper {
    let proto = match alg {
        Algorithm::Gg18 => gg18::Gg18Keygen::new(),
    };
    let wrapper = Box::new(ProtoWrapper { proto, res: None });
    Box::into_raw(wrapper)
}

#[no_mangle]
pub extern "C" fn protocol_update(proto: *mut ProtoWrapper, data: *const u8, len: usize) -> Buffer {
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let wrapper = unsafe { &mut *proto };

    wrapper.res = Some(wrapper.proto.update(slice));
    let (ptr, len) = match &wrapper.res {
        Some(Ok(data)) => (data.as_ptr(), data.len()),
        _ => (null(), 0),
    };
    Buffer { ptr, len }
}

pub struct GroupWrapper {
    group: Box<dyn Group>,
}

#[no_mangle]
pub extern "C" fn protocol_result_group(proto: *mut ProtoWrapper) -> *mut GroupWrapper {
    let wrapper = unsafe { &mut *proto };
    let res = wrapper.proto.output();
    // FIXME: save the result
    if let Ok(ProtocolOutput::Group(group)) = res {
        let wrapper = Box::new(GroupWrapper { group });
        return Box::into_raw(wrapper);
    }
    null_mut()
}

#[no_mangle]
pub extern "C" fn group_sign(group: *mut GroupWrapper) -> *mut ProtoWrapper {
    let wrapper = unsafe { &mut *group };
    let proto = wrapper.group.sign();
    let proto_wrapper = Box::new(ProtoWrapper { proto, res: None });
    Box::into_raw(proto_wrapper)
}

#[no_mangle]
pub extern "C" fn protocol_free(proto: *mut ProtoWrapper) {
    unsafe { Box::from_raw(proto) };
}
