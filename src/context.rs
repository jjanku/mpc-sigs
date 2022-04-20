pub enum RoundOutputType<T, U> {
    Inter(T),
    Final(U),
}

pub struct RoundOutput<T, U> {
    pub output: RoundOutputType<T, U>,
    pub data_out: Vec<u8>,
}

pub type RoundResult<T> = Result<T, Box<dyn std::error::Error>>;

pub type KeygenResult = RoundResult<RoundOutput<Box<dyn Keygen>, Box<dyn Group>>>;

pub trait Keygen {
    fn advance(self, data: &[u8]) -> KeygenResult;
}

pub type Signature = Vec<u8>;

pub type SigningResult = RoundResult<RoundOutput<Box<dyn Signing>, Signature>>;

pub trait Signing {
    fn advance(self, data: &[u8]) -> SigningResult;
}

pub trait Group {
    fn sign(&self, data: &[u8]) -> SigningResult;
}
