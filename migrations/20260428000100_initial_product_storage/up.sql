create table if not exists spaces (
    space_id text primary key,
    title text not null,
    summary text,
    payload jsonb not null,
    updated_at timestamptz not null default now()
);

create table if not exists repo_operations (
    operation_id text primary key,
    space_id text not null,
    digest text not null unique,
    payload jsonb not null,
    created_at timestamptz not null
);

create index if not exists repo_operations_space_created_idx
    on repo_operations (space_id, created_at, operation_id);

create table if not exists repo_commits (
    commit_id text primary key,
    repo_id text not null,
    author text not null,
    author_seq bigint not null,
    prev_commit text,
    digest text not null unique,
    payload jsonb not null,
    created_at timestamptz not null
);

create index if not exists repo_commits_repo_created_idx
    on repo_commits (repo_id, created_at, commit_id);

create table if not exists repo_commit_operations (
    commit_id text not null references repo_commits(commit_id) on delete cascade,
    operation_digest text not null references repo_operations(digest) on delete restrict,
    position bigint not null,
    primary key (commit_id, operation_digest)
);

create table if not exists repo_heads (
    repo_id text primary key,
    head_commit text not null,
    updated_at timestamptz not null default now()
);

create table if not exists repo_author_sequences (
    repo_id text not null,
    author text not null,
    author_seq bigint not null,
    updated_at timestamptz not null default now(),
    primary key (repo_id, author)
);

create table if not exists events (
    event_id text primary key,
    space_id text not null,
    event_type text not null,
    sender text,
    payload jsonb not null,
    created_at timestamptz not null default now()
);

create index if not exists events_space_created_idx
    on events (space_id, created_at, event_id);

create table if not exists sessions (
    token text primary key,
    actor text not null,
    device_id text not null,
    payload jsonb not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create index if not exists sessions_actor_device_idx
    on sessions (actor, device_id);

create table if not exists devices (
    actor text not null,
    device_id text not null,
    payload jsonb not null,
    updated_at timestamptz not null default now(),
    primary key (actor, device_id)
);

create table if not exists device_keys (
    actor text not null,
    device_id text not null,
    payload jsonb not null,
    updated_at timestamptz not null default now(),
    primary key (actor, device_id)
);

create table if not exists one_time_keys (
    key_id bigserial primary key,
    actor text not null,
    device_id text not null,
    algorithm text not null,
    payload jsonb not null,
    claimed_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists one_time_keys_available_idx
    on one_time_keys (actor, device_id, algorithm)
    where claimed_at is null;

create table if not exists blobs (
    blob_ref text primary key,
    sha256 text not null,
    media_type text not null,
    filename text,
    uploaded_by text not null,
    size_bytes bigint not null,
    bytes bytea,
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

create table if not exists push_devices (
    registration_id text primary key,
    actor text,
    device_id text not null,
    push_gateway text not null,
    push_key text not null,
    platform text,
    app_id text,
    payload jsonb not null,
    updated_at timestamptz not null default now()
);

create table if not exists moderation_reports (
    report_id text primary key,
    space_id text not null,
    target_ref text not null,
    reason text not null,
    reporter text not null,
    payload jsonb not null,
    status text not null,
    created_at timestamptz not null default now()
);

create table if not exists presence (
    actor text primary key,
    status text not null,
    payload jsonb not null,
    updated_at timestamptz not null default now()
);

create table if not exists account_data (
    actor text not null,
    data_type text not null,
    payload jsonb not null,
    updated_at timestamptz not null default now(),
    primary key (actor, data_type)
);

create table if not exists notifications (
    notification_id text primary key,
    actor text not null,
    space_id text,
    event_ref text,
    payload jsonb not null,
    read_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists notifications_actor_created_idx
    on notifications (actor, created_at, notification_id);
