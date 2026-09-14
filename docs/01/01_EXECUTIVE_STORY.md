# 01 — Executive Story (Bind Compute)

## 1. What Bind is building
A developmental computing stack where **certified computational matter**—discovered under causal tests—is archived, reused, and loaded onto a **reconfigurable cognitive fabric (RCF)** without replacing the host silicon image.

## 2. The problem
Today's "AI on chips" usually means a fixed model running on GPUs/accelerators. Changing capability means shipping a new model or a new bitstream. There is little continuity between **discovery**, **proof of causal role**, **memory**, and **physical organization**.

## 3. The core insight
Treat computation as **matter that must earn its place**: discover → intervene/certify → archive with lineage → reuse → project to hardware → **hot-load** onto a fixed fabric.

## 4. What is different
- Causal certification before persistence
- Single archive as construction material
- Embodied discovery path (ECR) that can feed the foundry
- Faithful execution semantics (sum+tanh IR)
- Generic RCF host: **one bitstream**, many organizations via config

## 5. What has actually been built
Software: Digital Chemistry substrate, Machine Factory, archive, CLM/PCM, ECR, science spine S1–S4, standalone demos.  
Hardware path: faithful IR, RTL, **generic multi-slot RCF iCE40 bitstream** (135100 bytes).  
Live board execution and physical robot: **pending**.

## 6. Flagship demonstration
Object `ECR2MF_g0_field_s1002`: unknown-world discovery → certificate → archive → ×211 reuse → necessity under gate-off → RCF hot-load/restore → bitstream artifact.  
Runnable without the full IP tree: `STANDALONE_FLAGSHIP/`.

## 7. Architecture (one line)
World → ECR → certify → MF/archive → matter package → RCF → body → world.

## 8. Why hardware matters
Without a reconfigurable host, each organization is a dead-end netlist. RCF makes organization a **loadable state** of a persistent machine.

## 9. Roadmap
Board hot-load → minimal physical body → reopen developmental edge (robot→ECR→MF→RCF) → multi-node fabric → ASIC macros.

## 10. Why this could become a new architecture
Not larger neural nets—**developmental continuity of certified organization** from discovery to silicon configuration.
