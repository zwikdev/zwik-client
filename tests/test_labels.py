import logging
import os
import tempfile
from unittest.mock import patch

import conda

from tests.utils import DummyServerEnvironmentTest, DummyZwikServer


class TestChannelLabels(DummyServerEnvironmentTest):
    def test_create_lockfile(self):
        from scripts.zwik_client import ZwikEnvironment, ZwikSettings

        def get_lock_data(env_settings, package_name):
            env = ZwikEnvironment(env_settings)
            env._installation_checked = True
            env.env_data = {
                "dependencies": [
                    package_name,
                ],
            }

            env.lock_data = None
            with tempfile.TemporaryDirectory() as tmp_dir:
                env.yaml_path = os.path.join(tmp_dir, "dummy.yaml")
                env._yaml_hash = "1234"
                env.working_dir = tmp_dir
                env.create_lockfile()
            assert isinstance(env.lock_data, dict)
            return env.lock_data

        settings = ZwikSettings()

        with self.subTest("normal package"):
            self.dummy_server.dummy_name = "dummy-package-normal"
            lock_data = get_lock_data(settings, self.dummy_server.dummy_name)
            self.assertIn(
                "{}=1.0=0".format(self.dummy_server.dummy_name),
                lock_data["dependencies"],
            )
            self.assertFalse(lock_data.get("labels"))

        with self.subTest("obsolete package"):
            self.dummy_server.dummy_name = "dummy-package-obsolete"
            self.dummy_server.dummy_label = "obsolete"
            with self.assertLogs("zwik_client", level=logging.WARNING):
                lock_data = get_lock_data(settings, self.dummy_server.dummy_name)
            self.assertIn(
                "{}=1.0=0".format(self.dummy_server.dummy_name),
                lock_data["dependencies"],
            )
            self.assertEqual(
                lock_data["labels"][self.dummy_server.dummy_name],
                "obsolete",
            )

        with self.subTest("unsafe package"):
            self.dummy_server.dummy_name = "dummy-package-unsafe"
            self.dummy_server.dummy_label = "unsafe"

            with self.assertRaises(conda.CondaError):
                get_lock_data(settings, self.dummy_server.dummy_name)

            with patch(
                "scripts.zwik_client.ZwikEnvironment.get_yaml_comment",
                return_value="# CAUTION: UNSAFE PACKAGE",
            ):
                with self.assertLogs("zwik_client", level=logging.WARNING):
                    lock_data = get_lock_data(settings, self.dummy_server.dummy_name)
            self.assertIn(
                "{}=1.0=0".format(self.dummy_server.dummy_name),
                lock_data["dependencies"],
            )
            self.assertEqual(
                lock_data["labels"][self.dummy_server.dummy_name],
                "unsafe",
            )

    @patch("conda.core.link.UnlinkLinkTransaction.execute")
    def test_create_environment(self, link_exec_mock):
        from scripts.zwik_client import ZwikEnvironment, ZwikSettings

        def generate_lock_data(name, label=None):
            lock_data = {
                "dependencies": [
                    "{}=1.0=0".format(name),
                ],
                "channels": [
                    "defaults",
                ],
                "subdir": "linux-64",
            }
            if label:
                lock_data["labels"] = {
                    name: label,
                }
            return lock_data

        settings = ZwikSettings()

        env = ZwikEnvironment(settings)
        env._installation_checked = True
        env.override_prefix = "dummy"

        with self.subTest("normal package"):

            self.dummy_server.dummy_name = "dummy-link-pkg-normal"
            self.dummy_server.dummy_label = None
            env.lock_data = generate_lock_data(self.dummy_server.dummy_name)
            env.create_env()
            link_exec_mock.assert_called_once()

        with self.subTest("obsolete package"):
            self.dummy_server.dummy_name = "dummy-link-pkg-obsolete"
            self.dummy_server.dummy_label = "obsolete"
            with self.assertLogs(
                "zwik_client",
                level=logging.WARNING,
            ) as cm:
                env.lock_data = generate_lock_data(
                    self.dummy_server.dummy_name,
                    "obsolete",
                )
                env.create_env()
                # No warning expected when lock data specifies label
                self.assertEqual(len(cm.output), 0)

                env.lock_data = generate_lock_data(self.dummy_server.dummy_name)
                env.create_env()

        with self.subTest("unsafe package"):
            self.dummy_server.dummy_name = "dummy-link-pkg-unsafe"
            self.dummy_server.dummy_label = "unsafe"
            env.lock_data = generate_lock_data(self.dummy_server.dummy_name)
            with self.assertRaises(AssertionError):
                env.create_env()

            env.lock_data = generate_lock_data(self.dummy_server.dummy_name, "unsafe")
            env.create_env()

    @patch("conda.core.link.UnlinkLinkTransaction.execute")
    def test_multiple_packages_with_default(self, link_exec_mock):
        from scripts.zwik_client import ZwikEnvironment, ZwikSettings

        settings = ZwikSettings()

        with DummyZwikServer() as server2:
            server2.dummy_content = b"server2 test"

            env = ZwikEnvironment(settings)
            env._installation_checked = True
            env.override_prefix = "dummy"

            env.lock_data = {
                "dependencies": [
                    "{}=1.0=0".format(self.dummy_server.dummy_name),
                ],
                "channels": [
                    "defaults",
                    server2.channel_url,
                ],
                "subdir": "linux-64",
            }
            env.create_env()
            link_exec_mock.assert_called_once()

    @patch("conda.core.link.UnlinkLinkTransaction.execute")
    def test_multiple_packages_without_default(self, link_exec_mock):
        from scripts.zwik_client import ZwikEnvironment, ZwikSettings

        settings = ZwikSettings()

        with DummyZwikServer() as server1, DummyZwikServer() as server2:
            server1.dummy_content = b"server1 test"
            server2.dummy_content = b"server2 test"

            env = ZwikEnvironment(settings)
            env._installation_checked = True
            env.override_prefix = "dummy"

            env.lock_data = {
                "dependencies": [
                    "{}=1.0=0".format(server1.dummy_name),
                ],
                "channels": [
                    "nodefaults",
                    server1.channel_url,
                    server2.channel_url,
                ],
                "subdir": "linux-64",
            }
            with self.assertRaises(AssertionError):
                env.create_env()
