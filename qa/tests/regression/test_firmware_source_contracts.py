import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "qa/checks/firmware/check_firmware_source_contracts.py"


class FirmwareSourceContractTests(unittest.TestCase):
    def test_repository_satisfies_compile_contracts(self) -> None:
        completed = subprocess.run(
            ["python3", str(CHECKER)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
