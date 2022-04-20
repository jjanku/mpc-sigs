pub mod c_api;
pub mod cert;
mod context;
mod protocols;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
