#!/usr/bin/env python3

import json
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / 'settings.gradle.kts').write_text('', encoding='utf-8')
        (root / 'build.gradle.kts').write_text('', encoding='utf-8')
        native = root / 'app' / 'src' / 'main' / 'cpp'
        native.mkdir(parents=True)
        (native / 'CMakeLists.txt').write_text('', encoding='utf-8')

        result = subprocess.run(
            ['python3', 'tools/allvm_android_command.py', str(root), '--json'],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout)
        assert payload['detected']['gradle'] is True
        assert payload['detected']['gradle_dsl'] == 'kotlin'
        assert payload['detected']['native'] is True
        assert 'cmake' in payload['detected']['build_systems']

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
