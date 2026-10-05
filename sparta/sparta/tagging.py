"""Token labels for the secrets tagger, span decoding, and span-level scoring.

Gold data is character spans (SECRET, NAME, DECOY, IGNORE). Tokens get BIO
labels over SECRET and NAME; DECOY tokens are O; IGNORE tokens (e-mail
addresses, IP addresses: the code's job, not the tagger's) get no label and
stay out of the loss. Predictions are decoded back to character spans and
scored per span:

  * a gold SECRET/NAME is caught when a predicted span of the same type
    overlaps it (recall);
  * a predicted span is correct when it overlaps a gold span of its type
    (precision); otherwise it is a false tag;
  * a decoy is falsely tagged when any predicted span overlaps it;
  * an IGNORE span is not gold, and a prediction on one is neither right nor wrong.
"""

from __future__ import annotations

from collections import Counter, defaultdict

LABELS = ["O", "B-SECRET", "I-SECRET", "B-NAME", "I-NAME"]
LABEL2ID = {l: i for i, l in enumerate(LABELS)}
TYPES = ("SECRET", "NAME")
IGNORE = -100
# EVAL-004: secrets and personal data. The first five labels are EVAL-003's, in the same order.
TYPES4 = ("SECRET", "NAME", "EMAIL", "PHONE", "ID", "ADDRESS")


def labels_for(types=TYPES) -> list[str]:
    return ["O"] + [f"{bio}-{t}" for t in types for bio in ("B", "I")]


def token_labels(offsets: list[tuple[int, int]], spans: list[dict], types=TYPES) -> list[int]:
    """BIO label ids for tokens with character `offsets`; special tokens and tokens of IGNORE spans get IGNORE."""
    label2id = LABEL2ID if types == TYPES else {l: i for i, l in enumerate(labels_for(types))}
    ents = sorted((s for s in spans if s["label"] in types), key=lambda s: s["start"])
    skip = [s for s in spans if s["label"] == "IGNORE"]
    labels = []
    seen = set()
    for (a, b) in offsets:
        if b <= a:
            labels.append(IGNORE)
            continue
        lab = "O"
        for i, s in enumerate(ents):
            if a < s["end"] and b > s["start"]:
                lab = ("I-" if i in seen else "B-") + s["label"]
                seen.add(i)
                break
        if lab == "O" and any(a < s["end"] and b > s["start"] for s in skip):
            labels.append(IGNORE)
            continue
        labels.append(label2id[lab])
    return labels


def decode(offsets: list[tuple[int, int]], label_ids: list[int], text: str | None = None,
           labels: list[str] = LABELS) -> list[dict]:
    """Predicted character spans from per-token label ids. An I- with no open span starts one.

    Byte-level BPE offsets include a token's leading space; with `text` given,
    span edges are trimmed of whitespace.
    """
    spans: list[dict] = []
    cur = None
    for (a, b), lid in zip(offsets, label_ids):
        if b <= a or lid == IGNORE:
            continue
        lab = labels[lid]
        if lab == "O":
            cur = None
            continue
        bio, typ = lab.split("-")
        if cur is not None and bio == "I" and cur["label"] == typ:
            cur["end"] = b
        else:
            cur = {"start": a, "end": b, "label": typ}
            spans.append(cur)
    if text is not None:
        for sp in spans:
            while sp["start"] < sp["end"] and text[sp["start"]].isspace():
                sp["start"] += 1
            while sp["end"] > sp["start"] and text[sp["end"] - 1].isspace():
                sp["end"] -= 1
        spans = [sp for sp in spans if sp["end"] > sp["start"]]
    return spans


def _overlap(x: dict, y: dict) -> bool:
    return x["start"] < y["end"] and y["start"] < x["end"]


def _outside(p: dict, ignored: list[dict]) -> list[tuple[int, int]]:
    """The parts of predicted span `p` outside every IGNORE span (an e-mail or IP is judged by code, not by
    the tagger): a tag is neither right nor wrong on one, but what it covers beyond it still counts."""
    pieces = [(p["start"], p["end"])]
    for g in ignored:
        pieces = [q for a, b in pieces
                  for q in (((a, min(b, g["start"])), (max(a, g["end"]), b)) if a < g["end"] and g["start"] < b
                            else ((a, b),))
                  if q[1] > q[0]]
    return pieces


class Scorer:
    """Accumulates span-level results over documents."""

    def __init__(self, types=TYPES):
        self.types = types
        self.gold = Counter()          # (type) -> n gold
        self.caught = Counter()        # (type) -> n gold caught
        self.gold_kind = Counter()     # (type, kind) -> n
        self.caught_kind = Counter()
        self.pred = Counter()          # type -> n predicted
        self.pred_ok = Counter()
        self.decoys = Counter()        # kind -> n decoys
        self.decoy_hit = Counter()
        self.char_iou = defaultdict(list)
        self.misses: list[dict] = []   # gold spans not caught
        self.false_tags: list[dict] = []

    def add(self, doc: dict, pred: list[dict], doc_id=None):
        ignored = [g for g in doc["spans"] if g["label"] == "IGNORE"]
        gold = [g for g in doc["spans"] if g["label"] != "IGNORE"]
        pred = [{**p, "start": a, "end": b} for p in pred for a, b in _outside(p, ignored)]
        for g in gold:
            if g["label"] == "DECOY":
                self.decoys[g["kind"]] += 1
                if any(_overlap(g, p) for p in pred):
                    self.decoy_hit[g["kind"]] += 1
                    self.false_tags.append({"doc": doc_id, "span": g, "why": "decoy"})
                continue
            self.gold[g["label"]] += 1
            self.gold_kind[(g["label"], g["kind"])] += 1
            hits = [p for p in pred if p["label"] == g["label"] and _overlap(g, p)]
            if hits:
                self.caught[g["label"]] += 1
                self.caught_kind[(g["label"], g["kind"])] += 1
                lo = min(p["start"] for p in hits)
                hi = max(p["end"] for p in hits)
                inter = min(hi, g["end"]) - max(lo, g["start"])
                union = max(hi, g["end"]) - min(lo, g["start"])
                self.char_iou[g["label"]].append(inter / union)
            else:
                self.misses.append({"doc": doc_id, "span": g})
        for p in pred:
            self.pred[p["label"]] += 1
            if any(g["label"] == p["label"] and _overlap(g, p) for g in gold):
                self.pred_ok[p["label"]] += 1
            elif not any(g["label"] == "DECOY" and _overlap(g, p) for g in gold):
                self.false_tags.append({"doc": doc_id, "span": p, "why": "no gold"})

    def summary(self) -> dict:
        out = {}
        for t in self.types:
            r = self.caught[t] / self.gold[t] if self.gold[t] else None
            p = self.pred_ok[t] / self.pred[t] if self.pred[t] else None
            f1 = 2 * p * r / (p + r) if p and r else 0.0 if (p is not None and r is not None) else None
            iou = self.char_iou[t]
            out[t] = {"gold": self.gold[t], "caught": self.caught[t], "recall": r,
                      "predicted": self.pred[t], "precision": p, "f1": f1,
                      "mean_char_iou": sum(iou) / len(iou) if iou else None}
        out["by_kind"] = {f"{t}/{k}": {"gold": n, "caught": self.caught_kind[(t, k)],
                                       "recall": self.caught_kind[(t, k)] / n}
                          for (t, k), n in sorted(self.gold_kind.items())}
        total = sum(self.decoys.values())
        out["DECOY"] = {"decoys": total, "false_tagged": sum(self.decoy_hit.values()),
                        "false_tag_rate": sum(self.decoy_hit.values()) / total if total else None,
                        "by_kind": {k: {"n": n, "false_tagged": self.decoy_hit[k]}
                                    for k, n in sorted(self.decoys.items())}}
        return out
