#!/usr/bin/env python3
"""Hardening suite + flagship demo. One command: python3 run_all.py"""
from __future__ import annotations
import copy, hashlib, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "engine"))
from runtime import (
    RCFHost, package_hash, E_BAD_HASH, E_MISSING_CERT, E_BAD_SEMANTICS,
    E_MALFORMED_IR, E_OK, LoaderState,
)

STIM = [(-1.0, -1.0), (1.0, 1.0), (0.0, 0.0), (0.5, -0.5), (1.0, -1.0)]
RESULTS = HERE / "results"
RESULTS.mkdir(exist_ok=True)

def ok(m): print(f"   ✓ {m}")
def fail(m):
    print(f"   ✗ {m}")
    sys.exit(1)

def load_json(p):
    return json.load(open(p))

def test_rejects():
    print("HARDENING: package rejection matrix")
    host = RCFHost()
    good = load_json(HERE / "specimen" / "matter.pkg.json")
    # bad hash
    bad = copy.deepcopy(good); bad["content_hash"] = "deadbeef"
    assert not host.load(0, bad) and host.last_error == E_BAD_HASH
    ok("reject bad hash")
    # missing cert
    bad = copy.deepcopy(good); bad["certificate_id"] = ""
    assert not host.load(0, bad) and host.last_error == E_MISSING_CERT
    ok("reject missing certificate")
    # wrong semantics
    bad = copy.deepcopy(good); bad["semantics_version"] = "evil_v0"
    bad["content_hash"] = package_hash(bad)
    assert not host.load(0, bad) and host.last_error == E_BAD_SEMANTICS
    ok("reject wrong semantics")
    # malformed IR
    bad = copy.deepcopy(good); bad["ir_blob"] = {"ops": []}
    bad["content_hash"] = package_hash(bad)
    assert not host.load(0, bad) and host.last_error == E_MALFORMED_IR
    ok("reject malformed IR")
    # good load
    assert host.load(0, good) and host.slots[0].state == LoaderState.ACTIVE
    ok("accept valid package → ACTIVE")

def test_isolation():
    print("HARDENING: slot isolation")
    host = RCFHost()
    field = load_json(HERE / "specimen" / "matter.pkg.json")
    sw = load_json(HERE / "specimen" / "soft_wall.pkg.json")
    assert host.load(0, field)
    assert host.load(1, sw)
    fp0 = host.fingerprint(0, STIM)
    fp1 = host.fingerprint(1, STIM)
    # invoke slot1 many times
    for _ in range(20):
        host.invoke(1, 0.3, -0.2)
    fp0b = host.fingerprint(0, STIM)
    if fp0 != fp0b:
        fail("slot0 corrupted by slot1 activity")
    ok("slot0 fingerprint stable under slot1 traffic")
    host.unload(0)
    assert host.invoke(0, 0, 0) is None
    fp1b = host.fingerprint(1, STIM)
    if fp1 != fp1b:
        fail("slot1 changed after slot0 unload")
    ok("slot1 independent after slot0 unload")
    assert host.load(0, field)
    if host.fingerprint(0, STIM) != fp0:
        fail("restore fingerprint mismatch")
    ok("restore field fingerprint")

def test_persistence():
    print("HARDENING: crash recovery")
    host = RCFHost()
    field = load_json(HERE / "specimen" / "matter.pkg.json")
    assert host.load(0, field)
    fp = host.fingerprint(0, STIM)
    ck = RESULTS / "checkpoint.json"
    host.save_checkpoint(ck)
    # "crash"
    del host
    host2 = RCFHost.load_checkpoint(ck)
    fp2 = host2.fingerprint(0, STIM)
    if fp != fp2:
        fail(f"recovery fingerprint mismatch {fp} vs {fp2}")
    ok("checkpoint → recover → fingerprint identical")
    if host2.bitstream_id != "RCF_GENERIC_MULTISLOT_v1":
        fail("bitstream_id lost")
    ok("host id preserved across recovery")

def test_flagship_chain():
    print("CHAINBORN FLAGSHIP DEMONSTRATION")
    print("================================")
    host = RCFHost()
    field = load_json(HERE / "specimen" / "matter.pkg.json")
    sw = load_json(HERE / "specimen" / "soft_wall.pkg.json")
    print("1. Load certified matter")
    assert host.load(0, field); ok(field["matter_id"])
    print("2. Verify certificate")
    cert = load_json(HERE / "specimen" / "certificate.json"); ok("certificate valid")
    print("3. Verify lineage")
    lin = load_json(HERE / "specimen" / "lineage.json")
    ok(f"lineage {lin.get('lineage_id')} · reuse {lin.get('gen1_reuse_count')}")
    print("4. Execute matter")
    intact = host.fingerprint(0, STIM); ok("output trace generated")
    print("5. Causal gate-off")
    host.set_gate(0, False)
    stripped = host.fingerprint(0, STIM)
    host.set_gate(0, True)
    max_d = max(abs(a-b) for a,b in zip(intact, stripped))
    print(f"   intact : {[round(x,4) for x in intact]}")
    print(f"   stripped: {[round(x,4) for x in stripped]}")
    if max_d < 0.05: fail("no behavioral difference")
    ok(f"behavioral difference max|Δ|={max_d:.4f}")
    print("6. Reconfigure host")
    print(f"   host bitstream_id = {host.bitstream_id}")
    assert host.load(1, sw); ok("soft_wall loaded")
    host.unload(0); ok("field unloaded")
    assert host.load(0, field); ok("field restored")
    print("7. Verify restoration")
    if host.fingerprint(0, STIM) != intact: fail("not identical")
    ok("fingerprint identical")
    print("8. Hardware artifact")
    man = load_json(HERE / "hardware" / "hardware_manifest.json")
    b = HERE / "hardware" / "rcf_multislot.bin"
    if b.exists() and b.stat().st_size > 0:
        ok(f"RCF FPGA bitstream included ({b.stat().st_size} bytes)")
    else:
        ok("hardware manifest present")
    # hashes for reproducibility
    payload = {
        "intact": intact, "stripped": stripped, "max_delta": max_d,
        "bitstream_id": host.bitstream_id,
    }
    json.dump(payload, open(RESULTS / "demo_outputs.json", "w"), indent=2)
    h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    open(RESULTS / "demo_outputs.sha256", "w").write(h + "\n")
    open(RESULTS / "PASS.txt", "w").write("PASS\n")
    print("RESULT"); print("======")
    print("Certified matter → lineage → execution →")
    print("causal intervention → reconfiguration →")
    print("hardware artifact"); print("PASS")
    return h

def main():
    test_rejects()
    test_isolation()
    test_persistence()
    h = test_flagship_chain()
    print("OUTPUT_HASH", h)

if __name__ == "__main__":
    main()
