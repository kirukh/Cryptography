"""
Fuehrt alle vier Statefulness-Demos hintereinander aus.

Aufruf:
    python -m src.stateful_demo.run_all
"""
from src.stateful_demo import (
    demo01_index_progression,
    demo02_reuse_attack,
    demo03_backup_pitfall,
    demo04_multinode_failover,
)


def main():
    print("\n" + "#" * 70)
    print("#  XMSS Statefulness - vollstaendige Demo-Suite")
    print("#" * 70)

    demo01_index_progression.main()
    demo02_reuse_attack.main()
    demo03_backup_pitfall.main()
    demo04_multinode_failover.main()

    print("\n" + "#" * 70)
    print("#  Alle Demos abgeschlossen.")
    print("#  Begleitlektuere: docs/stateful_hsm_discussion.md")
    print("#" * 70)


if __name__ == "__main__":
    main()
