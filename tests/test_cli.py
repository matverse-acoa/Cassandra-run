import sys

import cli


def test_cli_rejects_invalid_json(capsys) -> None:
    sys.argv = ["cli.py", "submit", "--payload", "{invalid}"]
    cli.main()
    captured = capsys.readouterr()
    assert "Invalid JSON payload" in captured.out
