import json

from app.schemas.contracts import Finding

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def overlaps(left, right):
    a, b = left.location, right.location
    if left.cwe != right.cwe or a.artifact_id != b.artifact_id or a.kind != b.kind:
        return False
    return (
        a.field == b.field
        if a.kind == "http"
        else a.start_line <= b.end_line and b.start_line <= a.end_line
    )


def merge_findings(findings: list[Finding], parsed_by_id) -> list[dict]:
    groups = []
    for finding in findings:
        members = [finding]
        remaining = []
        # Repeat so a bridging interval joins transitively overlapping groups.
        for group in groups:
            if any(overlaps(a, b) for a in members for b in group):
                members.extend(group)
            else:
                remaining.append(group)
        changed = True
        while changed:
            changed = False
            for group in remaining[:]:
                if any(overlaps(a, b) for a in members for b in group):
                    members.extend(group)
                    remaining.remove(group)
                    changed = True
        groups = remaining + [members]
    result = []
    for members in groups:
        unique = {item.model_dump_json(): item for item in members}
        members = list(unique.values())
        primary = min(members, key=lambda item: RANK[item.severity]).model_copy(deep=True)
        primary.sources = [s for s in ("rule", "llm") if any(s in item.sources for item in members)]
        parsed = parsed_by_id[str(primary.location.artifact_id)]
        if primary.location.kind == "source":
            primary.location.start_line = min(m.location.start_line for m in members)
            primary.location.end_line = max(m.location.end_line for m in members)
            evidence = "\n".join(
                parsed.content.split("\n")[
                    primary.location.start_line - 1 : primary.location.end_line
                ]
            )
        else:
            evidence = parsed.fields[primary.location.field]
        primary.evidence, primary.evidence_truncated = evidence[:4000], len(evidence) > 4000
        result.append(
            {
                "finding": primary.model_dump(mode="json"),
                "contributors": [m.model_dump(mode="json") for m in members],
                "severity_disagreement": len({m.severity for m in members}) > 1,
            }
        )
    # Stable ordering makes retries and pagination reviewable.
    return sorted(
        result,
        key=lambda item: (
            item["finding"]["location"]["artifact_id"],
            json.dumps(item["finding"]["location"], sort_keys=True),
            item["finding"]["cwe"],
        ),
    )
