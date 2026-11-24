#!/usr/bin/env python3
"""Build the example Jev requests of this package from the study's own data and client code.

Run from the root of the study's repository (``s1mal/``), because the request bodies are built by the
study's own client functions, not re-implemented here:

    cd s1mal
    PYTHONPATH=src .venv/bin/python ../jev-request-example/tools/make_examples.py --out ../jev-request-example

What it does, without sending anything anywhere:

1. reads the S0 states that the frozen E1 run used (development and test files with a complete state);
2. picks one example per stratum below, from the development splits only: the state whose Qwen3 token
   count is closest to the stratum's median (ties broken by file id, so the choice is reproducible);
3. writes, for each example, the state text and the JSON bodies that the Jev client would POST to
   ``/v1/systemone``: the 33 questions of E1's two Jev readouts (the verdict question, then the 32 atomic
   questions, in the order the study asks them), in requests of at most ``batch_size`` questions;
4. writes the 33 questions in wire format and statistics over every state that would be sent in E1.

The file ids of the chosen examples go to ``private/selection.json`` (git-ignored, never shared): like
the states themselves, the shared files carry no hash and no file name of a sample.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
from datetime import date
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq
import yaml

from s1mal.infer.backends.base import request_body
from s1mal.questions.bank import load_bank
from s1mal.state.tokenizer import count_tokens

E1_RUN = Path("runs/e01/20261112T075504Z-061e8b7")  # the frozen E1 run of the preprint
SEL_COLS = ["sha256", "split", "label", "is_dll", "packed_any"]
STRING_KINDS = ["url", "ip", "registry", "path", "command", "mutex", "user_agent"]

# (directory, description, development-split filter)
STRATA = [
    ("ex01_malware_not_packed", "malware, not packed, with a Run-key persistence capability",
     lambda d: (d.split == "T0") & (d.label == 1) & ~d.packed_any
     & d.text.str.contains('"persist via Run registry key"', regex=False)),
    ("ex02_malware_packed", "malware, packed",
     lambda d: (d.split == "T0") & (d.label == 1) & d.packed_any),
    ("ex03_benign_exe", "benign executable (EXE)",
     lambda d: (d.split == "B_fit") & (d.label == 0) & ~d.is_dll),
    ("ex04_benign_dll", "benign library (DLL)",
     lambda d: (d.split == "B_fit") & (d.label == 0) & d.is_dll),
    ("ex05_malware_network_strings", "malware whose quoted strings include URLs or IP addresses",
     lambda d: (d.split == "T0") & (d.label == 1)
     & d.text.str.contains(r'^(?:url|ip): "', regex=True, flags=re.M)),
]
SOURCES = {"T0": "BODMAS malware, training split (first seen August-October 2019)",
           "B_fit": "benign collection (winget, Cygwin, MSYS2 packages, Windows 10 system files), training split"}


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def wire_tokens(q) -> int:
    # the size estimate of the Jev client (JevBackend._est_tokens): the question as sorted JSON
    return count_tokens(json.dumps(q.to_wire(), ensure_ascii=False, sort_keys=True))


def load_states(cfg_hash: str) -> pd.DataFrame:
    parts = sorted((Path("data/states/S0") / cfg_hash).glob("part-*.parquet"))
    cols = ["sha256", "state_variant", "text", "n_tokens", "status", "contains_code"]
    st = pd.concat([pq.read_table(p, columns=cols).to_pandas() for p in parts])
    return st.drop_duplicates("sha256")


def load_selection(phase: str) -> pd.DataFrame:
    main = pq.read_table(E1_RUN / f"selection/{phase}.parquet", columns=SEL_COLS).to_pandas()
    extra = pq.read_table(E1_RUN / f"selection/{phase}__extra.parquet", columns=SEL_COLS).to_pandas()
    return pd.concat([main, extra], ignore_index=True)


def strings_of(text: str) -> dict[str, int]:
    out = {k: 0 for k in STRING_KINDS}
    for line in text.splitlines():
        m = re.match(r"^(\w+): \"", line)
        if m and m.group(1) in out:
            out[m.group(1)] += 1
    return out


def statistics(states: pd.DataFrame) -> dict:
    s = states.copy()
    counts = s.text.map(strings_of)
    for k in STRING_KINDS:
        s[k] = counts.map(lambda c, k=k: c[k])
    s["n_strings"] = s[STRING_KINDS].sum(axis=1)
    s["directed"] = s.text.str.contains(r"^analysis_directed_text: yes", regex=True, flags=re.M)
    out = {"n_states": int(len(s))}
    for name, g in (("all", s), ("malware", s[s.label == 1]), ("benign", s[s.label == 0])):
        out[name] = {
            "n_states": int(len(g)),
            "qwen3_tokens": {"mean": round(float(g.n_tokens.mean()), 1), "median": float(g.n_tokens.median()),
                             "p90": float(g.n_tokens.quantile(0.9)), "max": int(g.n_tokens.max())},
            "quoted_strings_per_state": {"mean": round(float(g.n_strings.mean()), 2),
                                         "max": int(g.n_strings.max())},
            "share_of_states_with_at_least_one": {k: round(float((g[k] > 0).mean()), 4) for k in STRING_KINDS},
            "share_flagged_analysis_directed_text": round(float(g.directed.mean()), 4),
        }
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    out: Path = args.out

    models = yaml.safe_load(Path("configs/models.yaml").read_text())["backends"]["jev"]
    model, batch = models["model"], int(models["batch_size"])
    endpoint = models["routes"]["typesafe"]["base_url"].rstrip("/") + "/v1/systemone"
    margin = float(models["window"]["margin"])

    arms = yaml.safe_load(Path("configs/experiments/e01_main.yaml").read_text())["arms"]
    a0, a1 = arms["jev_a0"], arms["jev_a1"]
    # order of E1's ask job (steps.job_questions): arm jev_a0, then arm jev_a1, each in bank order
    questions = [q for q in load_bank([a0["question_set"]]) if q.id == a0["question"]]
    questions += load_bank([a1["question_set"]], vocabulary=a1["vocabulary"])
    assert len(questions) == 33, len(questions)

    cfg_hash = json.loads((E1_RUN / "states/dev/S0.json").read_text())["state_cfg_hash"]
    states = load_states(cfg_hash)
    dev = load_selection("dev").merge(states, on="sha256")
    dev = dev[dev.status == "ok"]
    every = pd.concat([dev, load_selection("test").merge(states, on="sha256")])
    every = every[every.status == "ok"]
    assert not every.contains_code.any() and set(every.state_variant) == {"S0"}

    q_tokens = {q.id: wire_tokens(q) for q in questions}
    write_json(out / "questions/questions_wire.json",
               {"note": "The 33 questions of E1's two Jev readouts in the wire format of /v1/systemone, "
                        "in the order they are asked: the verdict question (readout A0), then the 32 atomic "
                        "questions (readout A1).",
                "questions": {q.id: q.to_wire() for q in questions}})

    private = []
    for name, desc, filt in STRATA:
        pool = dev[filt(dev)].sort_values("sha256")
        med = float(pool.n_tokens.median())
        row = pool.iloc[(pool.n_tokens - med).abs().argsort(kind="stable")].iloc[0]
        d = out / "examples" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "state.txt").write_text(row.text, encoding="utf-8")
        reqs = []
        for i in range(0, len(questions), batch):
            chunk = questions[i:i + batch]
            body = request_body(row.text, model, chunk)
            k = i // batch + 1
            write_json(d / f"request_{k}.json", body)
            n = int(row.n_tokens) + sum(q_tokens[q.id] for q in chunk)
            reqs.append({"file": f"request_{k}.json", "n_questions": len(chunk), "qwen3_tokens": n,
                         "with_margin": math.ceil(n * (1 + margin))})
        write_json(d / "summary.json", {
            "example": name, "stratum": desc, "label": "malware" if row.label == 1 else "benign",
            "source": SOURCES[row.split], "state_variant": "S0", "state_qwen3_tokens": int(row.n_tokens),
            "stratum_size": int(len(pool)), "stratum_median_tokens": med,
            "requests": reqs, "total_qwen3_tokens": sum(r["qwen3_tokens"] for r in reqs),
            "total_with_margin": sum(r["with_margin"] for r in reqs)})
        private.append({"example": name, "sha256": row.sha256, "split": row.split})

    stats = statistics(every)
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    stats["provenance"] = {"study_commit": commit, "e1_run": E1_RUN.name, "state_cfg_hash": cfg_hash,
                           "states": "every E1 development and test file with a complete S0 state",
                           "generated": date.today().isoformat()}
    write_json(out / "stats/state_statistics.json", stats)
    write_json(out / "request_format.json", {
        "method": "POST", "endpoint": endpoint, "model": model, "max_questions_per_request": batch,
        "headers": {"Content-Type": "application/json", "Authorization": "Bearer <API key, read from an "
                                                                        "environment variable>"},
        "body": "json.dumps(body, ensure_ascii=False), UTF-8; the request_N.json files show the same "
                "object pretty-printed",
        "questions_per_state": len(questions), "requests_per_state": math.ceil(len(questions) / batch)})
    write_json(out / "private/selection.json", private)
    print(json.dumps({"examples": [p["example"] for p in private], "n_states": stats["n_states"]}, indent=1))


if __name__ == "__main__":
    main()
