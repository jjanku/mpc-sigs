pub enum ProtocolOutput {
    Round(Box<dyn Protocol>),
    Group(Box<dyn Group>),
    Signature(Vec<u8>),
}

pub type ProtocolResult = Result<(ProtocolOutput, Vec<u8>), Box<dyn std::error::Error>>;

pub trait Protocol {
    fn advance(self, data: &[u8]) -> ProtocolResult;
}

pub trait Group {
    fn sign(&self, data: &[u8]) -> ProtocolResult;
}
