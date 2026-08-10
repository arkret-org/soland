use arkret_models_collaboration::governance::agent_participation::{
    ParticipationBits, effective_participation,
};
use serde_json::Value;

use crate::state::AppState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedAgentParticipation {
    pub(crate) effective: ParticipationBits,
}

pub(crate) fn realm_scope_key(realm_id: &str) -> String {
    format!("realm:{realm_id}")
}

pub(crate) fn circle_scope_key(realm_id: &str, circle_id: &str) -> String {
    format!("circle:{realm_id}:{circle_id}")
}

pub(crate) fn strand_scope_key(realm_id: &str, strand_id: &str) -> String {
    format!("strand:{realm_id}:{strand_id}")
}

pub(crate) fn participation_from_value(row: &Value) -> ParticipationBits {
    ParticipationBits {
        reply_message: row
            .get("reply_message")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reaction_add: row
            .get("reaction_add")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reaction_remove: row
            .get("reaction_remove")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        accept_third_party_mention: row
            .get("accept_third_party_mention")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        act_on_behalf: row
            .get("act_on_behalf")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn projected_strand_circle_id(state: &AppState, strand_id: &str) -> Option<Option<String>> {
    {
        let projection = state.projections().snapshot();
        {
            projection.strands.get(strand_id).map(|strand| {
                strand
                    .scope_circle_id
                    .clone()
                    .filter(|scope| scope.starts_with("ak:circle:"))
            })
        }
    }
}

pub(crate) fn scope_keys_for_message(
    state: &AppState,
    realm_id: &str,
    strand_id: Option<&str>,
) -> Option<Vec<String>> {
    let mut keys = vec![realm_scope_key(realm_id)];
    let Some(strand_id) = strand_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return Some(keys);
    };
    if !strand_id.starts_with("ak:strand:") {
        return Some(keys);
    }
    if let Some(circle_id) = projected_strand_circle_id(state, strand_id)? {
        keys.push(circle_scope_key(realm_id, &circle_id));
    }
    keys.push(strand_scope_key(realm_id, strand_id));
    Some(keys)
}

pub(crate) async fn resolve_effective_ceiling_for_scope_keys(
    state: &AppState,
    scope_keys: &[String],
) -> ParticipationBits {
    let Ok(rows) = state.agent_participations().ceilings(scope_keys).await else {
        return ParticipationBits::NONE;
    };
    rows.iter()
        .map(participation_from_value)
        .fold(ParticipationBits::ALL, |acc, row| acc.intersect(row))
}

fn selection_for_scope_keys<'a>(
    selections: &'a [Value],
    scope_keys: &[String],
) -> Option<&'a Value> {
    scope_keys.iter().rev().find_map(|scope_key| {
        selections
            .iter()
            .find(|row| row.get("scope_key").and_then(Value::as_str) == Some(scope_key.as_str()))
    })
}

pub(crate) async fn resolve_agent_participation_for_scope_keys(
    state: &AppState,
    agent_id: &str,
    scope_keys: &[String],
) -> Option<ResolvedAgentParticipation> {
    let selections = state
        .agent_participations()
        .selections(agent_id)
        .await
        .unwrap_or_default();
    let selection = participation_from_value(selection_for_scope_keys(&selections, scope_keys)?);
    let ceiling = resolve_effective_ceiling_for_scope_keys(state, scope_keys).await;
    Some(ResolvedAgentParticipation {
        effective: effective_participation(ceiling, selection),
    })
}

#[cfg(test)]
mod tests {
    use super::{circle_scope_key, realm_scope_key, strand_scope_key};

    const REALM_ID: &str = "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO";
    const CIRCLE_ID: &str = "ak:circle:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS";
    const STRAND_ID: &str = "ak:strand:AYbepLWCNKm2SxJt1JgbGtBjKrwf_iGhnjreRy4TZj09";

    #[test]
    fn scope_keys_preserve_complete_event_derived_tokens() {
        assert_eq!(realm_scope_key(REALM_ID), format!("realm:{REALM_ID}"));
        assert_eq!(
            circle_scope_key(REALM_ID, CIRCLE_ID),
            format!("circle:{REALM_ID}:{CIRCLE_ID}")
        );
        assert_eq!(
            strand_scope_key(REALM_ID, STRAND_ID),
            format!("strand:{REALM_ID}:{STRAND_ID}")
        );
    }
}
