use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use cokret_sdk::{Did, RealmId};

#[derive(Clone, Debug, Default)]
pub struct RealmDirectoryQuery {
    pub text: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<Did>,
    pub public_only: bool,
    pub limit: Option<usize>,
}

/// Searchable Realm directory entry. This intentionally replaces the SDK
/// `SpaceSearchEntry` in soland because Realm, not Space, owns membership,
/// discovery, history visibility and plaintext-service policy.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, salvo::oapi::ToSchema,
)]
pub struct RealmDirectoryEntry {
    pub realm_id: RealmId,
    pub title: String,
    /// Canonical realm alias `<localpart>:<domain>` (object-addressing.md §3.3),
    /// or `None` if the realm has no human-readable alias. The `#` share sigil is
    /// a display-only affordance and is never stored here.
    pub alias: Option<String>,
    pub description: Option<String>,
    pub tags: BTreeSet<String>,
    pub members: BTreeSet<Did>,
    pub public: bool,
    pub category: Option<String>,
    pub as_of: DateTime<Utc>,
    pub source_refs: Vec<String>,
    pub policy_revision: String,
}

impl RealmDirectoryEntry {
    pub fn new(realm_id: RealmId, title: impl Into<String>) -> Self {
        Self {
            realm_id,
            title: title.into(),
            alias: None,
            description: None,
            tags: BTreeSet::new(),
            members: BTreeSet::new(),
            public: false,
            category: None,
            as_of: Utc::now(),
            source_refs: vec![crate::ids::generate_event_id()],
            policy_revision: "local".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RealmDirectoryIndex {
    entries: BTreeMap<RealmId, RealmDirectoryEntry>,
}

impl RealmDirectoryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, entry: RealmDirectoryEntry) {
        self.entries.insert(entry.realm_id.clone(), entry);
    }

    pub fn get(&self, realm_id: &RealmId) -> Option<&RealmDirectoryEntry> {
        self.entries.get(realm_id)
    }

    pub fn get_mut(&mut self, realm_id: &RealmId) -> Option<&mut RealmDirectoryEntry> {
        self.entries.get_mut(realm_id)
    }

    /// Iterate `(realm_id, entry)` pairs. Used by the erasure cascade
    /// (`account.rs::remove_realm_memberships_for_actor`) to enumerate
    /// every realm the erased actor was a member of.
    pub fn entries_iter(&self) -> impl Iterator<Item = (&RealmId, &RealmDirectoryEntry)> {
        self.entries.iter()
    }

    pub fn search_by_text(&self, query: &str) -> Vec<&RealmDirectoryEntry> {
        let query = query.to_lowercase();
        self.entries
            .values()
            .filter(|entry| realm_directory_text(entry).contains(&query))
            .collect()
    }

    pub fn search_by_tag(&self, tag: &str) -> Vec<&RealmDirectoryEntry> {
        self.entries
            .values()
            .filter(|entry| entry.tags.contains(tag))
            .collect()
    }

    pub fn search_by_member(&self, member: &Did) -> Vec<&RealmDirectoryEntry> {
        self.entries
            .values()
            .filter(|entry| entry.members.contains(member))
            .collect()
    }

    pub fn search(&self, query: RealmDirectoryQuery) -> Vec<&RealmDirectoryEntry> {
        let mut scored: Vec<_> = self
            .entries
            .values()
            .filter(|entry| !query.public_only || entry.public)
            .filter(|entry| {
                query
                    .text
                    .as_ref()
                    .map(|text| realm_directory_text(entry).contains(&text.to_lowercase()))
                    .unwrap_or(true)
            })
            .filter(|entry| query.tags.iter().all(|tag| entry.tags.contains(tag)))
            .filter(|entry| {
                query
                    .members
                    .iter()
                    .all(|member| entry.members.contains(member))
            })
            .map(|entry| (realm_directory_score(entry, &query), entry))
            .collect();

        scored.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| left.title.cmp(&right.title))
        });

        let mut results: Vec<_> = scored.into_iter().map(|(_, entry)| entry).collect();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }
}

fn realm_directory_text(entry: &RealmDirectoryEntry) -> String {
    format!(
        "{} {} {}",
        entry.title,
        entry.description.as_deref().unwrap_or_default(),
        entry.tags.iter().cloned().collect::<Vec<_>>().join(" ")
    )
    .to_lowercase()
}

fn realm_directory_score(entry: &RealmDirectoryEntry, query: &RealmDirectoryQuery) -> usize {
    let mut score = 0;
    if let Some(text) = &query.text {
        let text = text.to_lowercase();
        if entry.title.to_lowercase().contains(&text) {
            score += 10;
        }
        if entry
            .description
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains(&text)
        {
            score += 4;
        }
    }
    score += query
        .tags
        .iter()
        .filter(|tag| entry.tags.contains(*tag))
        .count()
        * 3;
    score += query
        .members
        .iter()
        .filter(|member| entry.members.contains(*member))
        .count()
        * 2;
    score
}
