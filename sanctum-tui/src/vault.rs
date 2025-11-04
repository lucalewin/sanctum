pub struct Vault {
    items: Vec<Item>,
}

impl Vault {
    pub fn new() -> Self {
        Vault { items: Vec::new() }
    }
}

pub fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    todo!()
}

struct Item {}

enum Credential {
    Login,
    SSHKey,
    CreditCard,
    Identity,
    Other,
}
