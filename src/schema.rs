diesel::table! {
    repo_commits (commit_id) {
        commit_id -> Text,
        repo_id -> Text,
        author -> Text,
        author_seq -> Int8,
        prev_commit -> Nullable<Text>,
        digest -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_operations (operation_id) {
        operation_id -> Text,
        space_id -> Text,
        digest -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    repo_heads (repo_id) {
        repo_id -> Text,
        head_commit -> Text,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    repo_author_sequences (repo_id, author) {
        repo_id -> Text,
        author -> Text,
        author_seq -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    repo_commit_operations (commit_id, operation_digest) {
        commit_id -> Text,
        operation_digest -> Text,
        position -> Int8,
    }
}

diesel::table! {
    spaces (space_id) {
        space_id -> Text,
        title -> Text,
        summary -> Nullable<Text>,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    events (event_id) {
        event_id -> Text,
        space_id -> Text,
        event_type -> Text,
        sender -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    sessions (token) {
        token -> Text,
        actor -> Text,
        device_id -> Text,
        payload -> Jsonb,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    devices (actor, device_id) {
        actor -> Text,
        device_id -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    device_keys (actor, device_id) {
        actor -> Text,
        device_id -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    one_time_keys (key_id) {
        key_id -> Int8,
        actor -> Text,
        device_id -> Text,
        algorithm -> Text,
        payload -> Jsonb,
        claimed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    blobs (blob_ref) {
        blob_ref -> Text,
        sha256 -> Text,
        media_type -> Text,
        filename -> Nullable<Text>,
        uploaded_by -> Text,
        size_bytes -> Int8,
        bytes -> Nullable<Bytea>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    push_devices (registration_id) {
        registration_id -> Text,
        actor -> Nullable<Text>,
        device_id -> Text,
        push_gateway -> Text,
        push_key -> Text,
        platform -> Nullable<Text>,
        app_id -> Nullable<Text>,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    moderation_reports (report_id) {
        report_id -> Text,
        space_id -> Text,
        target_ref -> Text,
        reason -> Text,
        reporter -> Text,
        payload -> Jsonb,
        status -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    presence (actor) {
        actor -> Text,
        status -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    account_data (actor, data_type) {
        actor -> Text,
        data_type -> Text,
        payload -> Jsonb,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    notifications (notification_id) {
        notification_id -> Text,
        actor -> Text,
        space_id -> Nullable<Text>,
        event_ref -> Nullable<Text>,
        payload -> Jsonb,
        read_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::joinable!(repo_commit_operations -> repo_commits (commit_id));

diesel::allow_tables_to_appear_in_same_query!(
    repo_commits,
    repo_operations,
    repo_heads,
    repo_author_sequences,
    repo_commit_operations,
    spaces,
    events,
    sessions,
    devices,
    device_keys,
    one_time_keys,
    blobs,
    push_devices,
    moderation_reports,
    presence,
    account_data,
    notifications,
);
