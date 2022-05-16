use core::slice;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr::null;

use crate::protocol::*;
use crate::protocols::gg18;

#[repr(C)]
pub enum Algorithm {
    Gg18,
}

pub struct ProtoWrapper {
    // FIXME: can we avoid the double indirection?
    proto: Box<dyn Protocol>,
    res: Option<Vec<u8>>,
    err: CString,
}

impl ProtoWrapper {
    fn new(proto: Box<dyn Protocol>) -> Self {
        ProtoWrapper {
            proto,
            res: None,
            err: CString::new("").unwrap(),
        }
    }

    fn set_res(&mut self, res: ProtocolResult<Vec<u8>>) {
        match res {
            Ok(data) => self.res = Some(data),
            Err(err) => self.err = CString::new(format!("{:?}", err)).unwrap(),
        };
    }

    fn update(&mut self, data: &[u8]) {
        let res = self.proto.update(data);
        self.set_res(res);
    }

    fn output(&mut self) {
        let res = self.proto.output();
        self.set_res(res);
    }

    fn res_buffer(&self) -> Buffer {
        let (ptr, len) = match &self.res {
            Some(data) => (data.as_ptr(), data.len()),
            _ => (null(), 0),
        };
        Buffer { ptr, len }
    }
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
    let wrapper = Box::new(ProtoWrapper::new(proto));
    Box::into_raw(wrapper)
}

#[no_mangle]
pub extern "C" fn protocol_update(proto: *mut ProtoWrapper, data: *const u8, len: usize) -> Buffer {
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let wrapper = unsafe { &mut *proto };
    wrapper.update(slice);
    wrapper.res_buffer()
}

// TODO: merge with update?
#[no_mangle]
pub extern "C" fn protocol_result(proto: *mut ProtoWrapper) -> Buffer {
    let wrapper = unsafe { &mut *proto };
    wrapper.output();
    wrapper.res_buffer()
}

#[no_mangle]
pub extern "C" fn protocol_error(proto: *const ProtoWrapper) -> *const c_char {
    let wrapper = unsafe { &*proto };
    wrapper.err.as_ptr()
}

#[no_mangle]
pub extern "C" fn protocol_free(proto: *mut ProtoWrapper) {
    unsafe { Box::from_raw(proto) };
}

// TODO: provide some access to info about group?
#[no_mangle]
pub extern "C" fn group_sign(
    // TODO: store the alg inside group data?
    alg: Algorithm,
    group_data: *const u8,
    len: usize,
) -> *mut ProtoWrapper {
    let slice = unsafe { slice::from_raw_parts(group_data, len) };

    let proto = match alg {
        Algorithm::Gg18 => gg18::Gg18Sign::with_group(slice),
    };
    let proto_wrapper = Box::new(ProtoWrapper::new(proto));
    Box::into_raw(proto_wrapper)
}
