use std::path::Path;

use serde::{Deserialize, Serialize};
use time::UtcDateTime;
use uuid::Uuid;

pub struct LocalStore {
    db: sled::Db,
    blobs: sled::Tree,
    outbox: sled::Tree,
}

impl LocalStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        let tree_blobs = db.open_tree("blobs")?;
        // let tree_meta = db.open_tree("meta")?;
        let tree_outbox = db.open_tree("outbox")?;
        Ok(Self {
            db,
            blobs: tree_blobs,
            outbox: tree_outbox,
        })
    }

    pub fn get_outbox(&self) -> Result<Vec<OutboxEntry>, sled::Error> {
        self.outbox
            .scan_prefix(b"")
            .map(|item| {
                let (_, value) = item?;
                Ok(serde_json::from_slice(&value).unwrap())
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct OutboxEntry {
    pub id: Uuid,
    pub kind: OutboxEntryKind,
    pub object_kind: OutputEntryObject,
    pub payload: serde_json::Value,
    pub created_at: UtcDateTime,
}

#[derive(Serialize, Deserialize)]
pub enum OutputEntryObject {
    Vault,
    Record,
}

#[derive(Serialize, Deserialize)]
pub enum OutboxEntryKind {
    Create,
    Update,
    Delete,
}
