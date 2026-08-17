from pathlib import Path
from tools.android_setup_executor import execute_plan


def test_dry_run():
    result = execute_plan({'actions': ['create config']}, Path('.'))
    assert result['dry_run']
    assert result['pending_actions']


if __name__ == '__main__':
    test_dry_run()
