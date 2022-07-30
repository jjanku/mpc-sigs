pub type ProtocolResult<T> = Result<T, Box<dyn std::error::Error>>;

pub trait Protocol {
    fn update(&mut self, data: &[u8]) -> ProtocolResult<Vec<u8>>;
    fn output(&mut self) -> ProtocolResult<Vec<u8>>;
}
