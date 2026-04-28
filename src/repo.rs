use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use contrix_sdk::{
    Commit, CommitId, CommitProofVerifier, Error, MemoryRepoStore, Operation, OperationId,
    RepoStore, Result as SdkResult,
};
use diesel::{
    Connection, OptionalExtension, PgConnection, QueryableByName, RunQueryDsl,
    r2d2::{ConnectionManager, Pool},
    sql_query,
    sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz},
};
use serde_json::Value;

use crate::wire::now;

pub type RepoAdapterRef = Arc<dyn RepoAdapter>;
type PgPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Clone, Debug)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

pub trait RepoAdapter: Send + Sync {
    fn head(&self, repo_id: &str) -> SdkResult<Option<String>>;
    fn list_commits(
        &self,
        repo_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Commit>>;
    fn get_commit(&self, commit_id: &CommitId) -> SdkResult<Option<Commit>>;
    fn get_operations(
        &self,
        operation_ids: &[String],
        limit: usize,
    ) -> SdkResult<(Vec<Operation>, Vec<String>)>;
    fn get_operations_by_digests(&self, operation_digests: &[String]) -> SdkResult<Vec<Operation>>;
    fn sync_operations(
        &self,
        repo_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Operation>>;
    fn sync_space_operations(
        &self,
        space_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Operation>>;
    fn submit_commit(
        &self,
        repo_id: &str,
        expected_head: Option<&str>,
        operations: Vec<Operation>,
        commit: Commit,
        verifier: &dyn CommitProofVerifier,
    ) -> SdkResult<Option<String>>;
}

#[derive(Debug, Default)]
pub struct MemoryRepoAdapter {
    repos: Mutex<BTreeMap<String, MemoryRepoStore>>,
}

impl MemoryRepoAdapter {
    pub fn new() -> Self {
        Self {
            repos: Mutex::new(BTreeMap::new()),
        }
    }
}

impl RepoAdapter for MemoryRepoAdapter {
    fn head(&self, repo_id: &str) -> SdkResult<Option<String>> {
        Ok(self
            .repos
            .lock()
            .expect("repo lock")
            .get(repo_id)
            .and_then(|repo| repo.head().map(ToString::to_string)))
    }

    fn list_commits(
        &self,
        repo_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Commit>> {
        let repos = self.repos.lock().expect("repo lock");
        let Some(repo) = repos.get(repo_id) else {
            return Ok(empty_page());
        };
        let mut skipped_cursor = after.is_none();
        let mut commits = Vec::new();
        for commit in repo.commits() {
            if !skipped_cursor {
                skipped_cursor = commit.commit_id.as_str() == after.unwrap_or_default();
                continue;
            }
            if commits.len() == limit + 1 {
                break;
            }
            commits.push(commit.clone());
        }
        Ok(page_from_items(commits, limit, |commit| {
            commit.commit_id.to_string()
        }))
    }

    fn get_commit(&self, commit_id: &CommitId) -> SdkResult<Option<Commit>> {
        Ok(self
            .repos
            .lock()
            .expect("repo lock")
            .values()
            .find_map(|repo| repo.commit(commit_id).cloned()))
    }

    fn get_operations(
        &self,
        operation_ids: &[String],
        limit: usize,
    ) -> SdkResult<(Vec<Operation>, Vec<String>)> {
        let repos = self.repos.lock().expect("repo lock");
        if operation_ids.is_empty() {
            return Ok((
                repos
                    .values()
                    .flat_map(|repo| repo.operations())
                    .take(limit)
                    .cloned()
                    .collect(),
                Vec::new(),
            ));
        }

        let mut operations = Vec::new();
        let mut missing = Vec::new();
        for raw_id in operation_ids {
            match OperationId::new(raw_id.clone()) {
                Ok(operation_id) => {
                    match repos
                        .values()
                        .find_map(|repo| repo.operation(&operation_id).cloned())
                    {
                        Some(operation) => operations.push(operation),
                        None => missing.push(operation_id.to_string()),
                    }
                }
                Err(_) => missing.push(raw_id.clone()),
            }
        }
        Ok((operations, missing))
    }

    fn get_operations_by_digests(&self, operation_digests: &[String]) -> SdkResult<Vec<Operation>> {
        let repos = self.repos.lock().expect("repo lock");
        let mut operations = Vec::new();
        for digest in operation_digests {
            if let Some(operation) = repos.values().find_map(|repo| {
                repo.operations()
                    .find(|operation| {
                        operation
                            .operation_digest()
                            .is_ok_and(|operation_digest| operation_digest == *digest)
                    })
                    .cloned()
            }) {
                operations.push(operation);
            }
        }
        Ok(operations)
    }

    fn sync_operations(
        &self,
        repo_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Operation>> {
        let repos = self.repos.lock().expect("repo lock");
        let Some(repo) = repos.get(repo_id) else {
            return Ok(empty_page());
        };
        let mut skipped_cursor = after.is_none();
        let mut operations = Vec::new();
        for operation in repo.operations() {
            if !skipped_cursor {
                skipped_cursor = operation.operation_id.as_str() == after.unwrap_or_default();
                continue;
            }
            if operations.len() == limit + 1 {
                break;
            }
            operations.push(operation.clone());
        }
        Ok(page_from_items(operations, limit, |operation| {
            operation.operation_id.to_string()
        }))
    }

    fn sync_space_operations(
        &self,
        space_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Operation>> {
        let repos = self.repos.lock().expect("repo lock");
        let mut skipped_cursor = after.is_none();
        let mut operations = Vec::new();
        for operation in repos.values().flat_map(|repo| repo.operations()) {
            if operation.space_id.as_str() != space_id {
                continue;
            }
            if !skipped_cursor {
                skipped_cursor = operation.operation_id.as_str() == after.unwrap_or_default();
                continue;
            }
            if operations.len() == limit + 1 {
                break;
            }
            operations.push(operation.clone());
        }
        Ok(page_from_items(operations, limit, |operation| {
            operation.operation_id.to_string()
        }))
    }

    fn submit_commit(
        &self,
        repo_id: &str,
        expected_head: Option<&str>,
        operations: Vec<Operation>,
        commit: Commit,
        verifier: &dyn CommitProofVerifier,
    ) -> SdkResult<Option<String>> {
        if commit.repo_id != repo_id {
            return Err(Error::Protocol(
                "commit repo_id does not match request repo_id".to_owned(),
            ));
        }

        let mut repos = self.repos.lock().expect("repo lock");
        let repo = repos
            .entry(repo_id.to_owned())
            .or_insert_with(MemoryRepoStore::new);
        if expected_head != repo.head().map(|head| head.as_str()) {
            return Err(Error::Protocol("expected_head mismatch".to_owned()));
        }
        for operation in operations {
            operation.validate_payload_object()?;
            repo.put_operation(operation)?;
        }
        verifier.verify_commit(&commit)?;
        repo.put_commit(commit)?;
        Ok(repo.head().map(ToString::to_string))
    }
}

#[derive(Clone)]
pub struct PgRepoAdapter {
    pool: PgPool,
}

impl PgRepoAdapter {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn conn(&self) -> SdkResult<diesel::r2d2::PooledConnection<ConnectionManager<PgConnection>>> {
        self.pool
            .get()
            .map_err(|error| Error::Protocol(format!("postgres repo error: {error}")))
    }
}

impl RepoAdapter for PgRepoAdapter {
    fn head(&self, repo_id: &str) -> SdkResult<Option<String>> {
        let mut conn = self.conn()?;
        select_head(&mut conn, repo_id)
    }

    fn list_commits(
        &self,
        repo_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Commit>> {
        let mut conn = self.conn()?;
        let rows = if let Some(after) = after {
            sql_query(
                "select payload from repo_commits where repo_id = $1 and commit_id > $2 order by commit_id asc limit $3",
            )
            .bind::<Text, _>(repo_id)
            .bind::<Text, _>(after)
            .bind::<BigInt, _>((limit + 1) as i64)
            .load::<PayloadRow>(&mut conn)
        } else {
            sql_query(
                "select payload from repo_commits where repo_id = $1 order by commit_id asc limit $2",
            )
            .bind::<Text, _>(repo_id)
            .bind::<BigInt, _>((limit + 1) as i64)
            .load::<PayloadRow>(&mut conn)
        }
        .map_err(|error| Error::Protocol(format!("postgres repo error: {error}")))?;
        let commits = rows
            .into_iter()
            .map(|row| serde_json::from_value(row.payload).map_err(Error::from))
            .collect::<SdkResult<Vec<Commit>>>()?;
        Ok(page_from_items(commits, limit, |commit| {
            commit.commit_id.to_string()
        }))
    }

    fn get_commit(&self, commit_id: &CommitId) -> SdkResult<Option<Commit>> {
        let mut conn = self.conn()?;
        let row = sql_query("select payload from repo_commits where commit_id = $1")
            .bind::<Text, _>(commit_id.as_str())
            .get_result::<PayloadRow>(&mut conn)
            .optional_row()?;
        row.map(|row| serde_json::from_value(row.payload).map_err(Error::from))
            .transpose()
    }

    fn get_operations(
        &self,
        operation_ids: &[String],
        limit: usize,
    ) -> SdkResult<(Vec<Operation>, Vec<String>)> {
        let mut conn = self.conn()?;
        if operation_ids.is_empty() {
            let rows =
                sql_query("select payload from repo_operations order by operation_id asc limit $1")
                    .bind::<BigInt, _>(limit as i64)
                    .load::<PayloadRow>(&mut conn)
                    .map_err(|error| Error::Protocol(format!("postgres repo error: {error}")))?;
            let operations = rows
                .into_iter()
                .map(|row| serde_json::from_value(row.payload).map_err(Error::from))
                .collect::<SdkResult<Vec<Operation>>>()?;
            return Ok((operations, Vec::new()));
        }

        let mut operations = Vec::new();
        let mut missing = Vec::new();
        for raw_id in operation_ids {
            let Ok(operation_id) = OperationId::new(raw_id.clone()) else {
                missing.push(raw_id.clone());
                continue;
            };
            match sql_query("select payload from repo_operations where operation_id = $1")
                .bind::<Text, _>(operation_id.as_str())
                .get_result::<PayloadRow>(&mut conn)
                .optional_row()?
            {
                Some(row) => operations.push(serde_json::from_value(row.payload)?),
                None => missing.push(operation_id.to_string()),
            }
        }
        Ok((operations, missing))
    }

    fn get_operations_by_digests(&self, operation_digests: &[String]) -> SdkResult<Vec<Operation>> {
        let mut conn = self.conn()?;
        let mut operations = Vec::new();
        for digest in operation_digests {
            if let Some(row) = sql_query("select payload from repo_operations where digest = $1")
                .bind::<Text, _>(digest)
                .get_result::<PayloadRow>(&mut conn)
                .optional_row()?
            {
                operations.push(serde_json::from_value(row.payload)?);
            }
        }
        Ok(operations)
    }

    fn sync_operations(
        &self,
        _repo_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Operation>> {
        let mut conn = self.conn()?;
        let rows = if let Some(after) = after {
            sql_query(
                "select payload from repo_operations where operation_id > $1 order by operation_id asc limit $2",
            )
            .bind::<Text, _>(after)
            .bind::<BigInt, _>((limit + 1) as i64)
            .load::<PayloadRow>(&mut conn)
        } else {
            sql_query("select payload from repo_operations order by operation_id asc limit $1")
                .bind::<BigInt, _>((limit + 1) as i64)
                .load::<PayloadRow>(&mut conn)
        }
        .map_err(|error| Error::Protocol(format!("postgres repo error: {error}")))?;
        let operations = rows
            .into_iter()
            .map(|row| serde_json::from_value(row.payload).map_err(Error::from))
            .collect::<SdkResult<Vec<Operation>>>()?;
        Ok(page_from_items(operations, limit, |operation| {
            operation.operation_id.to_string()
        }))
    }

    fn sync_space_operations(
        &self,
        space_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> SdkResult<Page<Operation>> {
        let mut conn = self.conn()?;
        let rows = if let Some(after) = after {
            sql_query(
                "select payload from repo_operations where space_id = $1 and operation_id > $2 order by operation_id asc limit $3",
            )
            .bind::<Text, _>(space_id)
            .bind::<Text, _>(after)
            .bind::<BigInt, _>((limit + 1) as i64)
            .load::<PayloadRow>(&mut conn)
        } else {
            sql_query(
                "select payload from repo_operations where space_id = $1 order by operation_id asc limit $2",
            )
            .bind::<Text, _>(space_id)
            .bind::<BigInt, _>((limit + 1) as i64)
            .load::<PayloadRow>(&mut conn)
        }
        .map_err(|error| Error::Protocol(format!("postgres repo error: {error}")))?;
        let operations = rows
            .into_iter()
            .map(|row| serde_json::from_value(row.payload).map_err(Error::from))
            .collect::<SdkResult<Vec<Operation>>>()?;
        Ok(page_from_items(operations, limit, |operation| {
            operation.operation_id.to_string()
        }))
    }

    fn submit_commit(
        &self,
        repo_id: &str,
        expected_head: Option<&str>,
        operations: Vec<Operation>,
        commit: Commit,
        verifier: &dyn CommitProofVerifier,
    ) -> SdkResult<Option<String>> {
        if commit.repo_id != repo_id {
            return Err(Error::Protocol(
                "commit repo_id does not match request repo_id".to_owned(),
            ));
        }
        verifier.verify_commit(&commit)?;
        let mut conn = self.conn()?;
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            let current_head = select_head(conn, repo_id).map_err(to_diesel_error)?;
            if expected_head != current_head.as_deref() {
                return Err(diesel_protocol_error("expected_head mismatch"));
            }

            for operation in operations {
                operation.validate_payload_object().map_err(to_diesel_error)?;
                insert_operation(conn, &operation)?;
            }
            validate_commit_append(conn, &commit, current_head.as_deref())?;
            insert_commit(conn, &commit)?;

            let digest = commit.commit_digest().map_err(to_diesel_error)?;
            sql_query(
                "insert into repo_heads (repo_id, head_commit, updated_at) values ($1, $2, $3) \
                 on conflict (repo_id) do update set head_commit = excluded.head_commit, updated_at = excluded.updated_at",
            )
            .bind::<Text, _>(repo_id)
            .bind::<Text, _>(&digest)
            .bind::<Timestamptz, _>(now())
            .execute(conn)?;

            sql_query(
                "insert into repo_author_sequences (repo_id, author, author_seq, updated_at) values ($1, $2, $3, $4) \
                 on conflict (repo_id, author) do update set author_seq = excluded.author_seq, updated_at = excluded.updated_at",
            )
            .bind::<Text, _>(repo_id)
            .bind::<Text, _>(commit.author.as_str())
            .bind::<BigInt, _>(commit.author_seq as i64)
            .bind::<Timestamptz, _>(now())
            .execute(conn)?;
            Ok(())
        })
        .map_err(|error| Error::Protocol(format!("postgres repo error: {error}")))?;
        self.head(repo_id)
    }
}

#[derive(QueryableByName)]
struct PayloadRow {
    #[diesel(sql_type = Jsonb)]
    payload: Value,
}

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = Nullable<Text>)]
    head_commit: Option<String>,
}

#[derive(QueryableByName)]
struct DigestRow {
    #[diesel(sql_type = Text)]
    digest: String,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct SeqRow {
    #[diesel(sql_type = BigInt)]
    author_seq: i64,
}

trait OptionalRow<T> {
    fn optional_row(self) -> SdkResult<Option<T>>;
}

impl<T> OptionalRow<T> for Result<T, diesel::result::Error> {
    fn optional_row(self) -> SdkResult<Option<T>> {
        match self {
            Ok(row) => Ok(Some(row)),
            Err(diesel::result::Error::NotFound) => Ok(None),
            Err(error) => Err(Error::Protocol(format!("postgres repo error: {error}"))),
        }
    }
}

fn select_head(conn: &mut PgConnection, repo_id: &str) -> SdkResult<Option<String>> {
    let row = sql_query("select head_commit from repo_heads where repo_id = $1")
        .bind::<Text, _>(repo_id)
        .get_result::<HeadRow>(conn)
        .optional_row()?;
    Ok(row.and_then(|row| row.head_commit))
}

fn insert_operation(
    conn: &mut PgConnection,
    operation: &Operation,
) -> Result<(), diesel::result::Error> {
    let digest = operation.operation_digest().map_err(to_diesel_error)?;
    if let Some(existing) = sql_query("select digest from repo_operations where operation_id = $1")
        .bind::<Text, _>(operation.operation_id.as_str())
        .get_result::<DigestRow>(conn)
        .optional()?
    {
        if existing.digest == digest {
            return Ok(());
        }
        return Err(diesel_protocol_error("operation idempotency conflict"));
    }

    sql_query(
        "insert into repo_operations (operation_id, space_id, digest, payload, created_at) values ($1, $2, $3, $4, $5)",
    )
    .bind::<Text, _>(operation.operation_id.as_str())
    .bind::<Text, _>(operation.space_id.as_str())
    .bind::<Text, _>(&digest)
    .bind::<Jsonb, _>(serde_json::to_value(operation).map_err(to_diesel_error)?)
    .bind::<Timestamptz, _>(operation.created_at)
    .execute(conn)?;
    Ok(())
}

fn validate_commit_append(
    conn: &mut PgConnection,
    commit: &Commit,
    current_head: Option<&str>,
) -> Result<(), diesel::result::Error> {
    if commit.prev_commit.as_ref().map(|head| head.as_str()) != current_head {
        return Err(diesel_protocol_error(
            "commit prev_commit does not match current repo head",
        ));
    }

    if let Some(row) =
        sql_query("select author_seq from repo_author_sequences where repo_id = $1 and author = $2")
            .bind::<Text, _>(&commit.repo_id)
            .bind::<Text, _>(commit.author.as_str())
            .get_result::<SeqRow>(conn)
            .optional()?
    {
        if commit.author_seq <= row.author_seq as u64 {
            return Err(diesel_protocol_error(
                "commit author_seq must be monotonically increasing",
            ));
        }
    }

    for operation_digest in &commit.operations {
        let row =
            sql_query("select count(*)::bigint as count from repo_operations where digest = $1")
                .bind::<Text, _>(operation_digest.as_str())
                .get_result::<CountRow>(conn)?;
        if row.count == 0 {
            return Err(diesel_protocol_error(
                "commit references unknown operation digest",
            ));
        }
    }
    Ok(())
}

fn insert_commit(conn: &mut PgConnection, commit: &Commit) -> Result<(), diesel::result::Error> {
    let digest = commit.commit_digest().map_err(to_diesel_error)?;
    if let Some(existing) = sql_query("select digest from repo_commits where commit_id = $1")
        .bind::<Text, _>(commit.commit_id.as_str())
        .get_result::<DigestRow>(conn)
        .optional()?
    {
        if existing.digest == digest {
            return Ok(());
        }
        return Err(diesel_protocol_error("commit idempotency conflict"));
    }

    sql_query(
        "insert into repo_commits (commit_id, repo_id, author, author_seq, prev_commit, digest, payload, created_at) \
         values ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<Text, _>(&commit.repo_id)
    .bind::<Text, _>(commit.author.as_str())
    .bind::<BigInt, _>(commit.author_seq as i64)
    .bind::<Nullable<Text>, _>(commit.prev_commit.as_ref().map(|head| head.as_str()))
    .bind::<Text, _>(&digest)
    .bind::<Jsonb, _>(serde_json::to_value(commit).map_err(to_diesel_error)?)
    .bind::<Timestamptz, _>(commit.created_at)
    .execute(conn)?;

    for (position, operation_digest) in commit.operations.iter().enumerate() {
        sql_query(
            "insert into repo_commit_operations (commit_id, operation_digest, position) values ($1, $2, $3) \
             on conflict (commit_id, operation_digest) do nothing",
        )
        .bind::<Text, _>(commit.commit_id.as_str())
        .bind::<Text, _>(operation_digest.as_str())
        .bind::<BigInt, _>(position as i64)
        .execute(conn)?;
    }
    Ok(())
}

fn page_from_items<T>(mut items: Vec<T>, limit: usize, cursor: impl Fn(&T) -> String) -> Page<T> {
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    let next_cursor = has_more.then(|| items.last().map(&cursor)).flatten();
    Page {
        items,
        next_cursor,
        has_more,
    }
}

fn empty_page<T>() -> Page<T> {
    Page {
        items: Vec::new(),
        next_cursor: None,
        has_more: false,
    }
}

fn to_diesel_error(error: impl std::fmt::Display) -> diesel::result::Error {
    diesel::result::Error::SerializationError(Box::new(std::io::Error::other(error.to_string())))
}

fn diesel_protocol_error(message: &str) -> diesel::result::Error {
    diesel::result::Error::SerializationError(Box::new(std::io::Error::other(message.to_owned())))
}
