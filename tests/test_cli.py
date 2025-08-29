import subprocess
import sys


def test_python_m_cli_runs():
    proc = subprocess.run(
        [sys.executable, "-m", "shenron_core"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0
    assert "SHENRON Research CLI" in proc.stdout
