from __future__ import annotations

import json

from tools.knowledge_eval_draft import _action_linkage_counts
from tools.target_store import TargetStore


def test_primary_action_linkage_ignores_archived_queue_json(tmp_path):
    target = "knowledge-target.test"
    store = TargetStore(tmp_path, target)
    store.initialize()
    store.create_action(
        command_id="knowledge-action",
        action_id="A-1",
        intent="review authz card",
        execution_key="work:knowledge",
        actor="ai",
        kind="work",
        subject={"target": target},
    )
    (tmp_path / "state" / target / "action_queue.json").write_text(
        json.dumps({"actions": [{"metadata": {"card": "archived-only"}}]}),
        encoding="utf-8",
    )

    counts = _action_linkage_counts(tmp_path, {"authz": {"authz"}, "archived": {"archived-only"}})

    assert counts["authz"] >= 1
    assert counts["archived"] == 0
