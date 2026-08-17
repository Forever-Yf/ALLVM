#!/usr/bin/env python3
"""Future Android setup executor interface.

Execution is intentionally separated from detection so later phases can add
NDK overlay creation, Gradle changes, and rollback safely.
"""

from pathlib import Path


def execute_plan(plan: dict, project: Path, dry_run: bool = True) -> dict:
    return {
        'project': str(project),
        'dry_run': dry_run,
        'executed': [],
        'pending_actions': plan.get('actions', []),
    }
