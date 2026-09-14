#!/usr/bin/env python3
"""Bind standalone runtime — certified matter + RCF host with explicit loader FSM.
No Machine Factory tree dependency.
"""
from __future__ import annotations
import hashlib, json, math, os, pickle
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

class LoaderState(Enum):
    EMPTY = "EMPTY"
    LOAD_REQUEST = "LOAD_REQUEST"
    VERIFY_HASH = "VERIFY_HASH"
    VERIFY_CERTIFICATE = "VERIFY_CERTIFICATE"
    VERIFY_SEMANTICS = "VERIFY_SEMANTICS"
    LOAD = "LOAD"
    ACTIVE = "ACTIVE"
    ERROR = "ERROR"

# error codes
E_OK = 0
E_BAD_HASH = 1
E_MISSING_CERT = 2
E_BAD_SEMANTICS = 3
E_MALFORMED_IR = 4
E_UNAUTHORIZED = 5
E_SLOT_BUSY = 6
E_NOT_FOUND = 7
E_NO_RESOURCE = 8

def channels_for(nh: int):
    return ["IN_A", "IN_B", "OUT"] + [f"H{i}" for i in range(int(nh))]

def compile_ops(rules, channels):
    idx = {c: i for i, c in enumerate(channels)}
    ops = []
    for r in rules:
        if not isinstance(r, dict) or "input_pattern" not in r:
            raise ValueError("malformed_ir")
        pat = list(r["input_pattern"])
        if any(p not in idx for p in pat):
            continue
        read = list(r.get("read_indices") or [0])
        weights = list(r.get("weights") or [1.0])
        while len(weights) < len(read):
            weights.append(0.0)
        ti = int(r.get("target_index") or 0)
        if ti < 0 or ti >= len(pat):
            ti = len(pat) - 1
        rid = str(r.get("id") or "")
        ops.append({
            "id": rid, "pattern": pat, "read": read,
            "weights": [float(w) for w in weights[:len(read)]],
            "bias": float(r.get("bias") or 0),
            "target_type": pat[ti],
            "gated": rid.startswith("from_"),
        })
    if not ops:
        raise ValueError("malformed_ir")
    return ops

def run_ops(ops, channels, a, b, ticks=4, gate_all=True, strip_ids=None):
    strip_ids = set(strip_ids or [])
    idx = {c: i for i, c in enumerate(channels)}
    state = [0.0] * len(channels)
    state[idx["IN_A"]] = float(a)
    state[idx["IN_B"]] = float(b)
    for _ in range(ticks):
        contrib = [0.0] * len(channels)
        for op in ops:
            if op["id"] in strip_ids:
                continue
            if op["gated"] and not gate_all:
                continue
            vals = [state[idx[t]] for t in op["pattern"]]
            total = op["bias"]
            for w, ri in zip(op["weights"], op["read"]):
                if 0 <= ri < len(vals):
                    total += w * vals[ri]
            contrib[idx[op["target_type"]]] += total
        for i in range(len(state)):
            if contrib[i] != 0.0:
                state[i] = math.tanh(state[i] + contrib[i])
    return state[idx["OUT"]]

def package_hash(pkg: dict) -> str:
    blob = json.dumps({
        "matter_id": pkg.get("matter_id"),
        "certificate_id": pkg.get("certificate_id"),
        "lineage_id": pkg.get("lineage_id"),
        "semantics_version": pkg.get("semantics_version"),
        "ir_blob": pkg.get("ir_blob"),
        "n_hidden": pkg.get("n_hidden"),
    }, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:32]

class Slot:
    def __init__(self):
        self.state = LoaderState.EMPTY
        self.pkg = None
        self.ops = None
        self.channels = None
        self.gate_all = True
        self.snapshot = None  # for rollback
        self.nodes_used = 0
        self.edges_used = 0

class RCFHost:
    """Fixed host ID; explicit loader FSM; multi-slot isolation."""
    def __init__(self, n_slots=2, n_nodes=64, n_edges=256):
        self.bitstream_id = "RCF_GENERIC_MULTISLOT_v1"
        self.n_nodes = n_nodes
        self.n_edges = n_edges
        self.free_nodes = n_nodes
        self.free_edges = n_edges
        self.slots = [Slot() for _ in range(n_slots)]
        self.last_error = E_OK
        self.log: List[dict] = []

    def _log(self, **kw):
        self.log.append(kw)

    def verify_package(self, pkg: dict) -> int:
        """Returns error code; does not mutate state."""
        if not isinstance(pkg, dict):
            return E_MALFORMED_IR
        if pkg.get("semantics_version") != "faithful_ir_v1":
            return E_BAD_SEMANTICS
        if not pkg.get("certificate_id"):
            return E_MISSING_CERT
        if not pkg.get("lineage_id") or not pkg.get("matter_id"):
            return E_UNAUTHORIZED
        if package_hash(pkg) != pkg.get("content_hash"):
            return E_BAD_HASH
        ir = pkg.get("ir_blob") or {}
        ops = ir.get("ops")
        if not isinstance(ops, list) or len(ops) == 0:
            return E_MALFORMED_IR
        need_n = int((pkg.get("resource_estimate") or {}).get("nodes_needed") or 4)
        need_e = int((pkg.get("resource_estimate") or {}).get("edges_needed") or len(ops))
        if need_n > self.free_nodes or need_e > self.free_edges:
            return E_NO_RESOURCE
        try:
            ch = channels_for(pkg.get("n_hidden") or 1)
            compile_ops(ops, ch)
        except ValueError:
            return E_MALFORMED_IR
        return E_OK

    def load(self, slot: int, pkg: dict) -> bool:
        s = self.slots[slot]
        s.state = LoaderState.LOAD_REQUEST
        self._log(event="LOAD_REQUEST", slot=slot)
        # reset prior ERROR state
        if s.state == LoaderState.ERROR or s.pkg is None:
            pass

        s.state = LoaderState.VERIFY_CERTIFICATE
        if not pkg.get("certificate_id"):
            s.state = LoaderState.ERROR
            self.last_error = E_MISSING_CERT
            self._log(event="REJECT", reason="E_MISSING_CERT", slot=slot)
            return False
        if not pkg.get("lineage_id") or not pkg.get("matter_id"):
            s.state = LoaderState.ERROR
            self.last_error = E_UNAUTHORIZED
            self._log(event="REJECT", reason="E_UNAUTHORIZED", slot=slot)
            return False

        s.state = LoaderState.VERIFY_HASH
        if package_hash(pkg) != pkg.get("content_hash"):
            s.state = LoaderState.ERROR
            self.last_error = E_BAD_HASH
            self._log(event="REJECT", reason="E_BAD_HASH", slot=slot)
            return False

        s.state = LoaderState.VERIFY_SEMANTICS
        err = self.verify_package(pkg)
        if err != E_OK:
            s.state = LoaderState.ERROR
            self.last_error = err
            self._log(event="REJECT", reason=err, slot=slot)
            return False

        if s.pkg is not None and s.state == LoaderState.ACTIVE:
            self.last_error = E_SLOT_BUSY
            return False

        s.state = LoaderState.LOAD
        need_n = int((pkg.get("resource_estimate") or {}).get("nodes_needed") or 4)
        need_e = int((pkg.get("resource_estimate") or {}).get("edges_needed") or len(pkg["ir_blob"]["ops"]))
        ch = channels_for(pkg["n_hidden"])
        ops = compile_ops(pkg["ir_blob"]["ops"], ch)
        # snapshot previous for rollback (empty)
        s.snapshot = None
        s.pkg = pkg
        s.ops = ops
        s.channels = ch
        s.gate_all = True
        s.nodes_used = need_n
        s.edges_used = need_e
        self.free_nodes -= need_n
        self.free_edges -= need_e
        s.state = LoaderState.ACTIVE
        self.last_error = E_OK
        self._log(event="ACTIVE", slot=slot, matter=pkg["matter_id"])
        return True

    def unload(self, slot: int) -> bool:
        s = self.slots[slot]
        if s.pkg is None:
            self.last_error = E_NOT_FOUND
            return False
        self.free_nodes += s.nodes_used
        self.free_edges += s.edges_used
        self.slots[slot] = Slot()
        self._log(event="UNLOAD", slot=slot)
        return True

    def invoke(self, slot: int, a: float, b: float):
        s = self.slots[slot]
        if s.state != LoaderState.ACTIVE or not s.ops:
            self.last_error = E_NOT_FOUND
            return None
        return run_ops(s.ops, s.channels, a, b, gate_all=s.gate_all)

    def set_gate(self, slot: int, gate_all: bool) -> bool:
        s = self.slots[slot]
        if s.state != LoaderState.ACTIVE:
            return False
        s.gate_all = gate_all
        self._log(event="GATE", slot=slot, gate_all=gate_all)
        return True

    def fingerprint(self, slot: int, stimuli):
        return [self.invoke(slot, a, b) for a, b in stimuli]

    def save_checkpoint(self, path: Path):
        data = {
            "bitstream_id": self.bitstream_id,
            "free_nodes": self.free_nodes,
            "free_edges": self.free_edges,
            "slots": [],
        }
        for s in self.slots:
            data["slots"].append({
                "state": s.state.value,
                "pkg": s.pkg,
                "gate_all": s.gate_all,
                "nodes_used": s.nodes_used,
                "edges_used": s.edges_used,
            })
        path.write_text(json.dumps(data, indent=2))

    @classmethod
    def load_checkpoint(cls, path: Path) -> "RCFHost":
        data = json.loads(path.read_text())
        host = cls()
        host.bitstream_id = data["bitstream_id"]
        host.free_nodes = data["free_nodes"]
        host.free_edges = data["free_edges"]
        for i, sd in enumerate(data["slots"]):
            if sd.get("pkg"):
                host.load(i, sd["pkg"])
                host.slots[i].gate_all = sd.get("gate_all", True)
        return host
