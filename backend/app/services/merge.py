"""Merge rule and model findings without swallowing distinct sinks.

Grouping is complete-linkage: a finding joins a group only if it overlaps EVERY member
(same artifact, CWE and overlapping lines / same HTTP field), so one wide interval can no
longer chain two separate sinks together. Each contributor keeps its own judgement; the
primary severity follows a versioned standard instead of whichever source shouts loudest.
"""

from app.rules.flow import CATEGORY, terminal_sink
from app.rules.semantics import Semantics
from app.schemas.contracts import Finding

SEVERITY_POLICY = "severity-1.0"
MERGE_VERSION = "flow-merge-1.1"


def _canonical(finding, parsed_by_id, cache):
    location = finding.location
    if location.kind != "source":
        return finding
    key = str(location.artifact_id)
    tree = getattr(parsed_by_id.get(key), "private_tree", None)
    if tree is None:
        return finding
    try:
        if key not in cache:
            cache[key] = Semantics(tree)
        target = terminal_sink(
            tree, cache[key], CATEGORY[finding.cwe], location.start_line, location.end_line
        )
        if target is None:
            return finding
        result = finding.model_copy(deep=True)
        result.location.start_line = target.lineno
        result.location.end_line = target.end_lineno or target.lineno
        return result
    except (KeyError, TypeError, ValueError, RecursionError, AttributeError):
        return finding  # unresolved flow never joins unrelated operations


def standard_severity(finding: Finding) -> str:
    """severity-1.0: static source potential=high; HTTP attack indicator=medium, else low."""
    if finding.location.kind == "source":
        return "high"
    return "medium" if finding.evidence_status == "attack_indicator" else "low"


def overlaps(left, right):
    a, b = left.location, right.location
    if left.cwe != right.cwe or a.artifact_id != b.artifact_id or a.kind != b.kind:
        return False
    return (
        a.field == b.field
        if a.kind == "http"
        else a.start_line <= b.end_line and b.start_line <= a.end_line
    )


def _order(finding: Finding):
    location = finding.location
    is_source = location.kind == "source"
    return (
        str(location.artifact_id),
        0 if is_source else 1,
        location.start_line if is_source else 0,
        location.end_line if is_source else 0,
        "" if is_source else location.field,
        finding.cwe,
        0 if "rule" in finding.sources else 1,
    )


def merge_findings(findings: list[Finding], parsed_by_id) -> list[dict]:
    cache, originals = {}, {}
    normalized = []
    for original in findings:
        item = _canonical(original, parsed_by_id, cache)
        originals[id(item)] = original
        normalized.append(item)
    groups: list[list[Finding]] = []
    for finding in sorted(normalized, key=_order):
        for group in groups:
            if all(overlaps(finding, member) for member in group):
                group.append(finding)
                break
        else:
            groups.append([finding])
    result = []
    for members in groups:
        unique = list({originals[id(item)].model_dump_json(): item for item in members}.values())
        # Explanation of the primary comes from the deterministic rule when one exists.
        base = next((m for m in unique if "rule" in m.sources), unique[0])
        primary = base.model_copy(deep=True)
        primary.sources = [s for s in ("rule", "llm") if any(s in m.sources for m in unique)]
        primary.severity = standard_severity(primary)
        primary.confidence = None
        parsed = parsed_by_id[str(primary.location.artifact_id)]
        if primary.location.kind == "source":
            # Members overlap pairwise, so their common intersection is non-empty; it is the
            # most precise location every source agrees on (contributors keep their own).
            primary.location.start_line = max(m.location.start_line for m in unique)
            primary.location.end_line = min(m.location.end_line for m in unique)
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
                "contributors": [originals[id(m)].model_dump(mode="json") for m in unique],
                "merge_version": MERGE_VERSION,
                "severity_disagreement": any(m.severity != primary.severity for m in unique),
                "severity_policy": SEVERITY_POLICY,
            }
        )
    # Groups were built in numeric location order; keep that order for stable pagination.
    return result
