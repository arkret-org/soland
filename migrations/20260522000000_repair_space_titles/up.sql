UPDATE spaces
SET title = resolved.title,
    summary = COALESCE(spaces.summary, resolved.summary),
    updated_at = NOW()
FROM (
    SELECT
        id,
        COALESCE(
            NULLIF(payload ->> 'realm_title', ''),
            NULLIF(payload ->> 'title', ''),
            NULLIF(payload #>> '{object,title}', ''),
            NULLIF(payload #>> '{patch,title,value}', ''),
            NULLIF(payload #>> '{patch,title}', '')
        ) AS title,
        COALESCE(
            NULLIF(payload ->> 'realm_summary', ''),
            NULLIF(payload ->> 'summary', ''),
            NULLIF(payload #>> '{object,summary}', ''),
            NULLIF(payload #>> '{patch,summary,value}', ''),
            NULLIF(payload #>> '{patch,summary}', '')
        ) AS summary
    FROM spaces
) AS resolved
WHERE spaces.id = resolved.id
  AND spaces.title = ('ck:realm:' || spaces.id::TEXT)
  AND resolved.title IS NOT NULL;
