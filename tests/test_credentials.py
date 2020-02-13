import os
import tempfile
import unittest
from unittest.mock import patch

from scripts.zwik_client import ZwikCredentials


class TestCredentials(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        store_path = os.path.join(self._tmpdir.name, "credentials.json")
        with patch.dict(
            os.environ,
            {
                "ZWIK_CREDENTIAL_STORE": store_path,
            },
        ):
            self.credentials = ZwikCredentials()

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_set_credentials(self):
        self.credentials.set("https://foobar.com/", "bar", "bar123")
        self.credentials.set("https://foobar.com/special/", "foo", "foo456")

        expected_store_values = {
            "foobar.com": {
                "bar": "bar123",
                "foo": "foo456",
            },
        }
        self.assertDictEqual(self.credentials.credential_data, expected_store_values)

        self.credentials.set(
            "https://foobar.com/special/deep/channel/noarch/repodata.json",
            "foo",
            "foo321",
        )
        expected_store_values["foobar.com"]["foo"] = "foo321"
        self.assertDictEqual(self.credentials.credential_data, expected_store_values)

        self.credentials.set(
            "https://foobar.com/special/deep/channel/noarch/repodata.json",
            "new",
            "new_psw",
        )
        expected_store_values["foobar.com"]["new"] = "new_psw"
        self.assertDictEqual(self.credentials.credential_data, expected_store_values)

        self.credentials.set(
            "https://test.com/install-data/test.exe",
            "me",
            "pws",
        )
        expected_store_values["test.com"] = {
            "me": "pws",
        }
        self.assertDictEqual(self.credentials.credential_data, expected_store_values)

    @patch("scripts.zwik_client.ZwikCredentials.read_credential_interactively")
    @patch("scripts.zwik_client.ZwikCredentials.validate")
    def test_default_url_with_single_user(self, mock_validate, mock_inter):
        self.credentials.credential_data = {
            "dummy1.org": {
                "usr": "psw",
            },
        }

        mock_validate.side_effect = [True]
        self.assertEqual(None, self.credentials.obtain(url="https://dummy1.org/"))

        mock_validate.side_effect = [False, True]
        self.assertEqual(
            ("usr", "psw"), self.credentials.obtain(url="https://dummy1.org/")
        )

        mock_validate.side_effect = [False, False, True]
        mock_inter.return_value = ("interx", "intery")
        self.assertEqual(
            ("interx", "intery"),
            self.credentials.obtain(url="https://dummy1.org/"),
        )

        self.assertDictEqual(
            self.credentials.credential_data,
            {
                "dummy1.org": {
                    "usr": "psw",
                    "interx": "intery",
                },
            },
        )

    @patch("scripts.zwik_client.ZwikCredentials.read_credential_interactively")
    @patch("scripts.zwik_client.ZwikCredentials.validate")
    def test_default_url_with_multiple_users(self, mock_validate, mock_inter):
        self.credentials.credential_data = {
            "dummy1.org": {
                "usr1": "psw1",
                "usr2": "psw2",
            }
        }

        mock_validate.side_effect = [True]
        self.assertEqual(None, self.credentials.obtain(url="https://dummy1.org/"))
        mock_validate.side_effect = [False, True]
        self.assertEqual(
            ("usr1", "psw1"), self.credentials.obtain(url="https://dummy1.org/")
        )

        mock_validate.side_effect = [False, False, True]
        self.assertEqual(
            ("usr2", "psw2"), self.credentials.obtain(url="https://dummy1.org/")
        )

        mock_validate.side_effect = [False, False, False, True]
        mock_inter.return_value = ("interx", "intery")
        self.assertEqual(
            ("interx", "intery"),
            self.credentials.obtain(url="https://dummy1.org/"),
        )

        self.assertDictEqual(
            self.credentials.credential_data,
            {
                "dummy1.org": {
                    "usr1": "psw1",
                    "usr2": "psw2",
                    "interx": "intery",
                },
            },
        )

    @patch("scripts.zwik_client.ZwikCredentials.read_credential_interactively")
    @patch("scripts.zwik_client.ZwikCredentials.set")
    @patch("scripts.zwik_client.ZwikCredentials.validate")
    def test_multiple_urls_with_single_user(self, mock_validate, mock_set, mock_inter):
        self.credentials.credential_data = {
            "dummy1.org": {"dummy1_usr": "dummy1_psw"},
            "dummy2.org": {"dummy2_usr": "dummy2_psw"},
        }

        mock_validate.side_effect = [True]
        self.assertEqual(None, self.credentials.obtain(url="https://dummy1.org/"))
        mock_validate.side_effect = [True]
        self.assertEqual(None, self.credentials.obtain(url="https://dummy2.org/"))

        mock_validate.side_effect = [False, True]
        self.assertEqual(
            ("dummy1_usr", "dummy1_psw"),
            self.credentials.obtain(url="https://dummy1.org/"),
        )
        mock_validate.side_effect = [False, True]
        self.assertEqual(
            ("dummy2_usr", "dummy2_psw"),
            self.credentials.obtain(url="https://dummy2.org/"),
        )

        mock_set.reset_mock()
        mock_validate.side_effect = [False, False, False, True]
        mock_inter.return_value = (
            "dummy2_usr",
            "dummy2_psw2",
        )
        self.assertEqual(
            ("dummy2_usr", "dummy2_psw2"),
            self.credentials.obtain(url="https://dummy2.org/"),
        )
        mock_set.assert_called_once()

        mock_set.reset_mock()
        mock_validate.side_effect = [False, False, False, True]
        mock_inter.return_value = (
            "dummy2_usr",
            "dummy2_psw2",
        )
        self.assertEqual(
            ("dummy2_usr", "dummy2_psw2"),
            self.credentials.obtain(url="https://dummy2.org/packages/conda"),
        )
        mock_set.assert_called_once()

    @patch("scripts.zwik_client.ZwikCredentials.read_credential_interactively")
    @patch("scripts.zwik_client.ZwikCredentials.set")
    @patch("scripts.zwik_client.ZwikCredentials.validate")
    def test_multi_urls_with_multi_users(self, mock_validate, mock_set, mock_inter):
        self.credentials.credential_data = {
            "dummy1.org": {
                "dummy1_usr1": "dummy1_psw1",
                "dummy1_usr2": "dummy1_psw2",
            },
            "dummy2.org": {
                "dummy2_usr1": "dummy2_psw1",
                "dummy2_usr2": "dummy2_psw2",
            },
        }

        mock_validate.side_effect = [True]
        self.assertEqual(None, self.credentials.obtain(url="https://dummy1.org/"))
        mock_validate.side_effect = [True]
        self.assertEqual(None, self.credentials.obtain(url="https://dummy2.org/"))

        mock_validate.side_effect = [False, True]
        self.assertEqual(
            ("dummy1_usr1", "dummy1_psw1"),
            self.credentials.obtain(url="https://dummy1.org/"),
        )
        mock_validate.side_effect = [False, False, True]
        self.assertEqual(
            ("dummy1_usr2", "dummy1_psw2"),
            self.credentials.obtain(url="https://dummy1.org/"),
        )

        mock_validate.side_effect = [False, True]
        self.assertEqual(
            ("dummy2_usr1", "dummy2_psw1"),
            self.credentials.obtain(url="https://dummy2.org/"),
        )
        mock_validate.side_effect = [False, False, True]
        self.assertEqual(
            ("dummy2_usr2", "dummy2_psw2"),
            self.credentials.obtain(url="https://dummy2.org/"),
        )

        mock_set.reset_mock()
        mock_validate.side_effect = [False, False, False, True]
        mock_inter.return_value = (
            "dummy2_usr2",
            "updated_psw2",
        )
        self.assertEqual(
            ("dummy2_usr2", "updated_psw2"),
            self.credentials.obtain(url="https://dummy2.org/"),
        )
        mock_set.assert_called_once()

        mock_set.reset_mock()
        mock_validate.side_effect = [False, False, False, False, True]
        mock_inter.return_value = (
            "dummy2_usr4",
            "dummy2_psw4",
        )
        self.assertEqual(
            ("dummy2_usr4", "dummy2_psw4"),
            self.credentials.obtain(url="https://dummy2.org/packages/conda"),
        )
        mock_set.assert_called_once()

    def test_adding_to_and_retrieve_from_credential_store(self):
        test_credentials = {
            "dummy1.org": {
                "dummy1_usr1": "dummy1_psw1",
                "dummy1_usr2": "dummy1_psw2",
            },
            "dummy2.org": {
                "dummy2_usr1": "dummy2_psw1",
                "dummy2_usr2": "dummy2_psw2",
            },
        }
        self.credentials.credential_data = test_credentials.copy()
        self.credentials.store()
        self.credentials.credential_data = {}
        self.credentials.read_credentials()
        self.assertEqual(
            self.credentials.credential_data,
            test_credentials,
        )

    @patch("getpass.getuser")
    @patch("getpass.getpass")
    @patch("builtins.input")
    def test_read_credential_interactively(self, mock_input, mock_pass, mock_user):
        mock_user.return_value = "foobar"

        mock_pass.return_value = "password"
        mock_input.return_value = ""
        cred = self.credentials.read_credential_interactively()
        self.assertEqual(cred, ("foobar", "password"))
        mock_pass.assert_called_once()
        mock_input.assert_called_once()
        self.assertIn("foobar", mock_input.call_args_list[0][0][0])
        self.assertIn("foobar", mock_pass.call_args_list[0][0][0])

        mock_input.reset_mock()
        mock_input.return_value = "barfoo"
        mock_pass.reset_mock()

        cred = self.credentials.read_credential_interactively("dummy")
        self.assertEqual(cred, ("barfoo", "password"))
        mock_pass.assert_called_once()
        mock_input.assert_called_once()
        self.assertIn("dummy", mock_input.call_args_list[0][0][0])
        self.assertIn("barfoo", mock_pass.call_args_list[0][0][0])

    @patch("scripts.zwik_client.get_hooks_module")
    @patch("scripts.zwik_client.ZwikCredentials.validate")
    def test_credential_hook(self, mock_validate, mock_hook):
        mock_validate.side_effect = [False, True]

        mock_hook().obtain_credentials_hook.return_value = ("hook_usr", "hook_psw")

        self.assertEqual(
            ("hook_usr", "hook_psw"),
            self.credentials.obtain(url="https://dummy2.org/packages/foobar"),
        )
