//! Persistence abstraction layer.
//!
//! Provides a trait-based interface for storage, allowing seamless switching
//! between in-memory and PostgreSQL backends.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::Utc;

use crate::state::{
    AccountRecord, BlobRecord, ContactRecord, MessageRecord, SessionRecord, SpaceMetaRecord,
};

/// Error type for persistence operations.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Database(#[from] diesel::result::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for persistence operations.
pub type PersistenceResult<T> = Result<T, PersistenceError>;

/// Trait for account storage operations.
pub trait AccountStore: Send + Sync {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>>;
    fn put(&self, record: &AccountRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<AccountRecord>>;
    fn delete(&self, did: &str) -> PersistenceResult<()>;
}

/// Trait for session storage operations.
pub trait SessionStore: Send + Sync {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>>;
    fn put(&self, record: &SessionRecord) -> PersistenceResult<()>;
    fn delete(&self, token: &str) -> PersistenceResult<()>;
    fn cleanup_expired(&self) -> PersistenceResult<usize>;
}

/// Trait for contact storage operations.
pub trait ContactStore: Send + Sync {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>>;
    fn put(&self, record: &ContactRecord) -> PersistenceResult<()>;
    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>>;
    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()>;
}

/// Trait for space metadata storage operations.
pub trait SpaceMetaStore: Send + Sync {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>>;
    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()>;
    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>>;
    fn delete(&self, space_id: &str) -> PersistenceResult<()>;
}

/// Trait for message storage operations.
pub trait MessageStore: Send + Sync {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>>;
    fn put(&self, record: &MessageRecord) -> PersistenceResult<()>;
    fn list_for_space(&self, space_id: &str, limit: usize) -> PersistenceResult<Vec<MessageRecord>>;
    fn list_for_thread(&self, thread_id: &str, limit: usize) -> PersistenceResult<Vec<MessageRecord>>;
    fn delete(&self, event_id: &str) -> PersistenceResult<()>;
}

/// Trait for blob storage operations.
pub trait BlobStore: Send + Sync {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>>;
    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()>;
    fn delete(&self, blob_ref: &str) -> PersistenceResult<()>;
}

/// Combined persistence store trait.
pub trait PersistenceStore: Send + Sync {
    fn accounts(&self) -> &dyn AccountStore;
    fn sessions(&self) -> &dyn SessionStore;
    fn contacts(&self) -> &dyn ContactStore;
    fn space_meta(&self) -> &dyn SpaceMetaStore;
    fn messages(&self) -> &dyn MessageStore;
    fn blobs(&self) -> &dyn BlobStore;
}

/// In-memory implementation of persistence store.
pub struct MemoryPersistenceStore {
    accounts: MemoryAccountStore,
    sessions: MemorySessionStore,
    contacts: MemoryContactStore,
    space_meta: MemorySpaceMetaStore,
    messages: MemoryMessageStore,
    blobs: MemoryBlobStore,
}

impl MemoryPersistenceStore {
    pub fn new() -> Self {
        Self {
            accounts: MemoryAccountStore::new(),
            sessions: MemorySessionStore::new(),
            contacts: MemoryContactStore::new(),
            space_meta: MemorySpaceMetaStore::new(),
            messages: MemoryMessageStore::new(),
            blobs: MemoryBlobStore::new(),
        }
    }
}

impl Default for MemoryPersistenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceStore for MemoryPersistenceStore {
    fn accounts(&self) -> &dyn AccountStore {
        &self.accounts
    }

    fn sessions(&self) -> &dyn SessionStore {
        &self.sessions
    }

    fn contacts(&self) -> &dyn ContactStore {
        &self.contacts
    }

    fn space_meta(&self) -> &dyn SpaceMetaStore {
        &self.space_meta
    }

    fn messages(&self) -> &dyn MessageStore {
        &self.messages
    }

    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }
}

// In-memory account store
struct MemoryAccountStore {
    data: Arc<Mutex<BTreeMap<String, AccountRecord>>>,
}

impl MemoryAccountStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl AccountStore for MemoryAccountStore {
    fn get(&self, did: &str) -> PersistenceResult<Option<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(did).cloned())
    }

    fn put(&self, record: &AccountRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.did.clone(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<AccountRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.values().cloned().collect())
    }

    fn delete(&self, did: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(did);
        Ok(())
    }
}

// In-memory session store
struct MemorySessionStore {
    data: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
}

impl MemorySessionStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SessionStore for MemorySessionStore {
    fn get(&self, token: &str) -> PersistenceResult<Option<SessionRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(token).cloned())
    }

    fn put(&self, record: &SessionRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(record.token.clone(), record.clone());
        Ok(())
    }

    fn delete(&self, token: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(token);
        Ok(())
    }

    fn cleanup_expired(&self) -> PersistenceResult<usize> {
        let mut data = self.data.lock().expect("lock");
        let now = Utc::now();
        let before = data.len();
        data.retain(|_, session| session.expires_at > now);
        Ok(before - data.len())
    }
}

// In-memory contact store
struct MemoryContactStore {
    data: Arc<Mutex<BTreeMap<(String, String), ContactRecord>>>,
}

impl MemoryContactStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl ContactStore for MemoryContactStore {
    fn get(&self, requester: &str, target: &str) -> PersistenceResult<Option<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(&(requester.to_owned(), target.to_owned())).cloned())
    }

    fn put(&self, record: &ContactRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(
            (record.requester.clone(), record.target.clone()),
            record.clone(),
        );
        Ok(())
    }

    fn list_for_actor(&self, actor: &str) -> PersistenceResult<Vec<ContactRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data
            .values()
            .filter(|c| c.requester == actor || c.target == actor)
            .cloned()
            .collect())
    }

    fn delete(&self, requester: &str, target: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(&(requester.to_owned(), target.to_owned()));
        Ok(())
    }
}

// In-memory space meta store
struct MemorySpaceMetaStore {
    data: Arc<Mutex<BTreeMap<String, SpaceMetaRecord>>>,
}

impl MemorySpaceMetaStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl SpaceMetaStore for MemorySpaceMetaStore {
    fn get(&self, space_id: &str) -> PersistenceResult<Option<SpaceMetaRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(space_id).cloned())
    }

    fn put(&self, space_id: &str, record: &SpaceMetaRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(space_id.to_owned(), record.clone());
        Ok(())
    }

    fn list(&self) -> PersistenceResult<Vec<(String, SpaceMetaRecord)>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn delete(&self, space_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(space_id);
        Ok(())
    }
}

// In-memory message store
struct MemoryMessageStore {
    data: Arc<Mutex<Vec<MessageRecord>>>,
}

impl MemoryMessageStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl MessageStore for MemoryMessageStore {
    fn get(&self, event_id: &str) -> PersistenceResult<Option<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.iter().find(|m| m.event_id == event_id).cloned())
    }

    fn put(&self, record: &MessageRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.push(record.clone());
        Ok(())
    }

    fn list_for_space(&self, space_id: &str, limit: usize) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.space_id == space_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn list_for_thread(&self, thread_id: &str, limit: usize) -> PersistenceResult<Vec<MessageRecord>> {
        let data = self.data.lock().expect("lock");
        let messages: Vec<_> = data
            .iter()
            .filter(|m| m.thread_id == thread_id)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        Ok(messages)
    }

    fn delete(&self, event_id: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.retain(|m| m.event_id != event_id);
        Ok(())
    }
}

// In-memory blob store
struct MemoryBlobStore {
    data: Arc<Mutex<BTreeMap<String, BlobRecord>>>,
}

impl MemoryBlobStore {
    fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl BlobStore for MemoryBlobStore {
    fn get(&self, blob_ref: &str) -> PersistenceResult<Option<BlobRecord>> {
        let data = self.data.lock().expect("lock");
        Ok(data.get(blob_ref).cloned())
    }

    fn put(&self, blob_ref: &str, record: &BlobRecord) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.insert(blob_ref.to_owned(), record.clone());
        Ok(())
    }

    fn delete(&self, blob_ref: &str) -> PersistenceResult<()> {
        let mut data = self.data.lock().expect("lock");
        data.remove(blob_ref);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_account_store_crud() {
        let store = MemoryAccountStore::new();
        let record = AccountRecord {
            did: "did:web:test".to_owned(),
            handle: "@test".to_owned(),
            display_name: Some("Test".to_owned()),
            created_at: Utc::now(),
        };

        // Create
        store.put(&record).unwrap();

        // Read
        let fetched = store.get("did:web:test").unwrap().unwrap();
        assert_eq!(fetched.did, "did:web:test");

        // List
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete("did:web:test").unwrap();
        assert!(store.get("did:web:test").unwrap().is_none());
    }

    #[test]
    fn memory_session_store_expiry() {
        let store = MemorySessionStore::new();
        let expired = SessionRecord {
            token: "expired".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            expires_at: Utc::now() - chrono::Duration::hours(1),
        };
        let valid = SessionRecord {
            token: "valid".to_owned(),
            actor: "did:web:test".to_owned(),
            device_id: "dev".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };

        store.put(&expired).unwrap();
        store.put(&valid).unwrap();

        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert!(store.get("expired").unwrap().is_none());
        assert!(store.get("valid").unwrap().is_some());
    }

    #[test]
    fn memory_contact_store_filtering() {
        let store = MemoryContactStore::new();
        let now = Utc::now();

        store
            .put(&ContactRecord {
                requester: "alice".to_owned(),
                target: "bob".to_owned(),
                status: "accepted".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        store
            .put(&ContactRecord {
                requester: "charlie".to_owned(),
                target: "alice".to_owned(),
                status: "pending".to_owned(),
                created_at: now,
                updated_at: now,
            })
            .unwrap();

        let alice_contacts = store.list_for_actor("alice").unwrap();
        assert_eq!(alice_contacts.len(), 2);

        let bob_contacts = store.list_for_actor("bob").unwrap();
        assert_eq!(bob_contacts.len(), 1);
    }
}
