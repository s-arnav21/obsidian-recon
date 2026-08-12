"""
attack_path_engine.py
-----------------------
Extends exploit_dispatcher's evidence model with capability tags, then
walks confirmed + queued findings to discover chained attack pathways
(e.g. exposed .git -> leaked creds -> admin login -> RCE).

Feed this AFTER exploit_dispatcher.py has run and evidence_store.json /
manual_review_queue.json exist. Output feeds the Reporting Agent.
"""

import json
import os
from itertools import product

EVIDENCE_FILE = "evidence_store.json"
QUEUE_FILE = "manual_review_queue.json"
PATHWAYS_FILE = "attack_pathways.json"

# --- Extend each handler's evidence with capability tags ---
# Add these two fields to every finding/handler result:
#   "requires": [ ... ]   capabilities needed BEFORE this step can run
#   "grants":   [ ... ]   capabilities this step UNLOCKS if confirmed
#
# Example additions to the dispatcher's handler return value:
#   {
#     "status": "confirmed",
#     "requires": ["unauthenticated"],
#     "grants": ["source_code_access"],
#   }
#
# A capability vocabulary you can start with (extend as you add handlers):
#   unauthenticated, source_code_access, db_credentials, admin_session,
#   file_write, code_execution, root_shell

START_CAPABILITY = "unauthenticated"


def load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def build_graph(evidence, queued):
    """
    Nodes = capabilities. Edges = individual exploit steps, tagged with
    validation status (confirmed / manual_pending) and the finding that
    produced them.
    """
    edges = []

    for entry in evidence:
        for req, grant in product(entry.get("requires", [START_CAPABILITY]),
                                   entry.get("grants", [])):
            edges.append({
                "from": req,
                "to": grant,
                "status": "confirmed" if entry.get("status") == "confirmed" else "not_exploitable",
                "finding_id": entry["finding_id"],
                "validator": entry.get("validator", "auto"),
            })

    for entry in queued:
        for req, grant in product(entry.get("requires", [START_CAPABILITY]),
                                   entry.get("grants", ["unconfirmed_capability"])):
            edges.append({
                "from": req,
                "to": grant,
                "status": "manual_pending",
                "finding_id": entry["id"],
                "validator": "manual",
            })

    return edges


def find_pathways(edges, start=START_CAPABILITY, max_depth=6):
    """
    DFS from `start` through capability edges. Returns every path found,
    labeled by whether EVERY step in it is confirmed, or whether it
    includes manual/unconfirmed links (a "theoretical" path the report
    should still surface, just flagged differently).
    """
    by_source = {}
    for e in edges:
        by_source.setdefault(e["from"], []).append(e)

    pathways = []

    def dfs(node, path, visited):
        outgoing = by_source.get(node, [])
        if not outgoing or len(path) >= max_depth:
            if path:
                pathways.append(list(path))
            return
        for edge in outgoing:
            if edge["to"] in visited:
                continue
            path.append(edge)
            visited.add(edge["to"])
            dfs(edge["to"], path, visited)
            path.pop()
            visited.remove(edge["to"])
        if path:  # also record partial paths that end here (dead ends still matter)
            pathways.append(list(path))

    dfs(start, [], {start})
    return pathways


def classify(path):
    statuses = {step["status"] for step in path}
    if statuses == {"confirmed"}:
        return "confirmed_chain"          # every step actually verified
    elif "manual_pending" in statuses and "not_exploitable" not in statuses:
        return "theoretical_chain"        # plausible, awaiting human validation
    else:
        return "broken_chain"             # at least one step failed to confirm


def main():
    evidence = load(EVIDENCE_FILE)
    queued = load(QUEUE_FILE)
    edges = build_graph(evidence, queued)
    raw_paths = find_pathways(edges)

    report = []
    for path in raw_paths:
        report.append({
            "steps": [f"{s['from']} -> {s['to']} (via {s['finding_id']}, {s['status']})" for s in path],
            "classification": classify(path),
            "finding_ids": [s["finding_id"] for s in path],
        })

    # Sort: confirmed chains first (most report-worthy), then theoretical, then broken
    order = {"confirmed_chain": 0, "theoretical_chain": 1, "broken_chain": 2}
    report.sort(key=lambda r: order[r["classification"]])

    with open(PATHWAYS_FILE, "w") as f:
        json.dump(report, f, indent=2)

    for r in report:
        print(f"[{r['classification']}] " + " -> ".join(r["steps"]))


if __name__ == "__main__":
    main()