#!/usr/bin/env python3
"""ALLVM Android setup planner.

This module is intentionally conservative: it detects a project and prints an
execution plan. It does not modify Gradle/CMake files unless a later phase
explicitly applies the generated plan.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def detect_project(root: Path) -> dict[str, object]:
    files = {p.name for p in root.rglob('*') if p.is_file()}
    gradle_kts = 'build.gradle.kts' in files or 'settings.gradle.kts' in files
    gradle = gradle_kts or 'build.gradle' in files or 'settings.gradle' in files
    cmake = any(p.name == 'CMakeLists.txt' for p in root.rglob('CMakeLists.txt'))
    ndk_build = any(p.name in {'Android.mk', 'Application.mk'} for p in root.rglob('Android.mk'))
    systems = []
    if gradle:
        systems.append('gradle')
    if cmake:
        systems.append('cmake')
    if ndk_build:
        systems.append('ndk-build')
    return {
        'project': str(root),
        'android': gradle or cmake or ndk_build,
        'gradle': gradle,
        'gradle_dsl': 'kotlin' if gradle_kts else ('groovy' if gradle else None),
        'native': cmake or ndk_build,
        'build_systems': systems,
    }


def make_plan(info: dict[str, object]) -> dict[str, object]:
    actions = []
    if info['android']:
        actions.append('create .allvm/allvm.json')
        actions.append('create allvm.lock.json')
    if info['gradle']:
        actions.append('generate Gradle integration fragment')
    if info['native']:
        actions.append('generate native build integration')
        actions.append('prepare NDK overlay configuration')
    actions.append('generate setup report')
    return {'detected': info, 'actions': actions}


def main() -> int:
    parser = argparse.ArgumentParser(description='ALLVM Android setup planner')
    parser.add_argument('project', type=Path, nargs='?', default=Path.cwd())
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    root = args.project.expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f'not a directory: {root}')

    result = make_plan(detect_project(root))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print('ALLVM Android setup plan')
        print(f"Project: {result['detected']['project']}")
        print('Actions:')
        for action in result['actions']:
            print(f'  - {action}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
