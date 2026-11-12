"""Run the production supervisor with owned child processes, not network services."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "start-service.sh"


@pytest.mark.parametrize(
    ("failed_child", "exit_status"),
    (("deliver", 23), ("serve", 23), ("deliver", 0)),
)
def test_production_supervisor_fails_closed_and_stops_sibling(
    tmp_path: Path, failed_child: str, exit_status: int
) -> None:
    command = tmp_path / "dinkster-registry"
    command.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, signal, sys, time\n"
        "root = pathlib.Path(os.environ['SUPERVISOR_TEST_ROOT'])\n"
        "name = sys.argv[1]\n"
        "root.joinpath(name + '.started').touch()\n"
        "if name not in {'serve', 'deliver'}: sys.exit(77)\n"
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
        "if name == os.environ['FAILED_CHILD']:\n"
        " sibling = 'serve' if name == 'deliver' else 'deliver'\n"
        " while not root.joinpath(sibling + '.started').exists():\n"
        "  time.sleep(0.01)\n"
        " sys.exit(int(os.environ['CHILD_EXIT_STATUS']))\n"
        "try:\n"
        " while True: time.sleep(0.01)\n"
        "finally: root.joinpath(name + '.stopped').touch()\n"
    )
    command.chmod(0o700)
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "SUPERVISOR_TEST_ROOT": str(tmp_path),
            "FAILED_CHILD": failed_child,
            "CHILD_EXIT_STATUS": str(exit_status),
        },
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == (exit_status or 1)
    assert {path.stem for path in tmp_path.glob("*.started")} == {"serve", "deliver"}
    sibling = "serve" if failed_child == "deliver" else "deliver"
    assert tmp_path.joinpath(sibling + ".stopped").exists()
