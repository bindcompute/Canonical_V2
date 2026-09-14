# Reproducibility

```bash
./RUN_DEMO.sh
# or: python3 run_all.py
```

Python 3.9+, stdlib only. No Machine Factory tree.

| Item | Location |
|------|----------|
| Frozen inputs | `specimen/` |
| Live outputs | `results/demo_outputs.json` |
| Output SHA-256 | `41ca684d043bd55e404cf472fb0d013ad2967213daaa54d6f9d07362775ee1bd` |
| Checkpoint recovery | `results/checkpoint.json` |

Hardening covered: reject matrix, slot isolation, crash recovery, flagship chain.
