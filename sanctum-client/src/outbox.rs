use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Action {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum EntityType {
    Vault,
    Record,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum OutboxStatus {
    Pending,
    InFlight,
    Sent,
    Failed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutboxEntry {
    pub id: Uuid,
    pub action: Action,
    pub entity_type: EntityType,
    pub payload: Value,
    pub created_at: OffsetDateTime,
    pub attempts: u32,
    pub status: OutboxStatus,
}

impl OutboxEntry {
    pub fn new(action: Action, entity_type: EntityType, payload: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            action,
            entity_type,
            payload,
            created_at: OffsetDateTime::now_utc(),
            attempts: 0,
            status: OutboxStatus::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
}
