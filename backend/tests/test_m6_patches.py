"""check_edits is the single source of the exact edit checks; apply_edits stays the authority."""

import asyncio
import json

import pytest
from app.core.errors import DomainError
from app.schemas.contracts import AnalysisResult
from app.services.patches import Edit, EditRejected, RepairWire, apply_edits, check_edits
from app.services.repairs import run_repair_once
from tests.test_repairs import repair, target

SOURCE = "import os\nx = 1  \nos.system(cmd)\nlast = 0"  # no line ending after the last line


def edit(start, end, old, new="pass\n"):
    return Edit(start_line=start, end_line=end, old_text=old, new_text=new)


CONFLICT = ("PATCH_CONFLICT", "patch_conflict")
CASES = [
    # (edit, (expected code, category), fragments the content-free detail must contain)
    (edit(1, 1, "import os\n"), (None, None), ()),
    (edit(1, 1, "import os"), CONFLICT, ("line_ending_only",)),
    (edit(2, 2, "x = 1\n"), CONFLICT, ("trailing_whitespace_only",)),
    (edit(2, 2, "os.system(cmd)\n"), CONFLICT, ("exact_text_at_lines_3",)),
    (edit(4, 4, "last = 0\n"), CONFLICT, ("last_line_has_no_line_ending",)),
    (edit(1, 2, "import os\n"), CONFLICT, ("old_text_has_1_lines",)),
    (
        edit(3, 9, "os.system(cmd)\n"),
        ("PATCH_RANGE", "patch_range"),
        ("declared 3-9", "file has 4 lines"),
    ),
    (
        edit(1, 1, "import os\n", "pass"),
        ("PATCH_NEWLINE", "patch_newline"),
        ("must end with a line feed",),
    ),
]


@pytest.mark.parametrize(("item", "verdict", "fragments"), CASES)
def test_check_edits_and_apply_edits_make_the_same_decision(item, verdict, fragments):
    code, category = verdict
    if code is None:
        lines, ordered = check_edits(SOURCE, [item])
        assert ordered == [item] and "".join(lines) == SOURCE
        apply_edits(SOURCE, [item])  # the authority agrees
        return
    with pytest.raises(EditRejected) as preflight:
        check_edits(SOURCE, [item])
    assert preflight.value.code == code and preflight.value.category == category
    assert all(fragment in preflight.value.detail for fragment in fragments)
    with pytest.raises(DomainError) as authority:
        apply_edits(SOURCE, [item])
    assert authority.value.code == code  # nothing the preflight refuses can slip through


def test_details_never_contain_source_text():
    secret_like = "SENTINEL_SOURCE_TEXT"
    source = f"{secret_like} = 1\nother = 2\n"
    with pytest.raises(EditRejected) as error:
        check_edits(source, [edit(2, 2, f"{secret_like} = 1\n")])
    assert secret_like not in error.value.detail and "exact_text_at_lines_1" in error.value.detail


def test_overlapping_and_unordered_edits_are_still_range_errors():
    first, second = edit(1, 2, "import os\nx = 1  \n"), edit(2, 3, "x = 1  \nos.system(cmd)\n")
    with pytest.raises(EditRejected, match="PATCH_RANGE"):
        check_edits(SOURCE, [first, second])


def test_a_failed_conflict_keeps_a_content_free_diagnostic_and_not_the_raw_edit(api, monkeypatch):
    finding, artifact = target(api)  # source: "import os\nos.system(request.args['cmd'])\n"
    monkeypatch.setenv("AEGISFORGE_DEEPSEEK_API_KEY", "synthetic-repair-key")
    api.app.state.settings.model_mode = "real"
    repair_id = repair(api, finding, artifact, "deepseek").json()["repair"]["id"]

    class Provider:
        async def generate(self, request, _target):
            wrong = edit(1, 1, "import os \n", "import os\nSENTINEL_NEW_TEXT\n")
            return RepairWire(schema_version="repair-1.0", explanation="x", edits=[wrong])

        async def analyze(self, _request):
            return AnalysisResult(mode="real", analysis_complete=True)

    asyncio.run(
        run_repair_once(api.app.state.engine, api.app.state.settings, lambda *_: Provider())
    )
    item = api.get(f"/api/v1/repairs/{repair_id}").json()["repair"]
    assert item["status"] == "failed" and item["error_code"] == "PATCH_CONFLICT"
    diagnostic = item["checks"]["patch_diagnostic"]
    assert diagnostic["category"] == "patch_conflict"
    assert "declared 1-1" in diagnostic["detail"]
    assert "trailing_whitespace_only" in diagnostic["detail"]
    stored = json.dumps(item)
    assert "SENTINEL_NEW_TEXT" not in stored and "import os \\n" not in stored
