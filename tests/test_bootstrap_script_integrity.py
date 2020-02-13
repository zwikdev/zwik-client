import os
from unittest import TestCase

from scripts.zwik_client import ZwikEnvironment


class TestScriptsIntegrity(TestCase):
    def test_scripts_integrity(self):
        boot_scripts = ("zwik_environment", "zwik_environment.bat")
        boot_script_dir = os.path.join(
            os.path.dirname(__file__),
            "..",
            "bootstrap",
        )

        for script in boot_scripts:
            path = os.path.join(boot_script_dir, script)
            actual_hash, expected_hash = ZwikEnvironment.get_file_integrity_hashes(path)
            self.assertEqual(actual_hash, expected_hash)
