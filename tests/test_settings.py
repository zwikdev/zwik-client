import os
import pathlib
import tempfile
import unittest
from unittest import mock

from scripts.zwik_client import ZwikSettings


@mock.patch(
    "scripts.zwik_client.ZwikCredentials.obtain",
    new=lambda x, y: None,
)
class TestSettings(unittest.TestCase):
    def test_resolve_channel(self):
        settings = ZwikSettings()
        settings.channel_alias = "https://domain.com"
        self.assertEqual(
            settings.resolve_channel("dummy"),
            "https://domain.com/dummy",
        )

        settings.channel_alias = "https://domain.com/"
        self.assertEqual(
            settings.resolve_channel("dummy"),
            "https://domain.com/dummy",
        )

        self.assertEqual(
            settings.resolve_channel("https://foobar.com/test_channel"),
            "https://foobar.com/test_channel",
        )

        with mock.patch("scripts.zwik_client.ZwikCredentials.obtain") as mock_cred:
            mock_cred.return_value = ("xyz@x1", "abc#d/")
            self.assertEqual(
                settings.resolve_channel("https://foobar.com/test_channel"),
                "https://xyz%40x1:abc%23d%2F@foobar.com/test_channel",
            )

    def test_resolve_channel_with_label(self):
        settings = ZwikSettings()
        self.assertEqual(
            settings.resolve_channel(
                channel="https://dummy.com/test_channel",
                label="main",
            ),
            "https://dummy.com/test_channel/labels/main",
        )

    def test_resolve_channels(self):
        settings = ZwikSettings()
        settings.channel_alias = "https://dummy.org"
        settings.default_channels = ["foo", "bar"]
        self.assertListEqual(
            settings.resolve_channels(
                [
                    "defaults",
                ],
            ),
            [
                "https://dummy.org/foo",
                "https://dummy.org/bar",
            ],
        )

        self.assertListEqual(
            settings.resolve_channels(
                [
                    "defaults",
                    "special",
                ],
            ),
            [
                "https://dummy.org/foo",
                "https://dummy.org/bar",
                "https://dummy.org/special",
            ],
        )

        self.assertListEqual(
            settings.resolve_channels(
                [
                    "special",
                    "defaults",
                ],
            ),
            [
                "https://dummy.org/special",
                "https://dummy.org/foo",
                "https://dummy.org/bar",
            ],
        )

        self.assertListEqual(
            settings.resolve_channels(
                [
                    "nodefaults",
                    "special",
                ],
            ),
            [
                "https://dummy.org/special",
            ],
        )

    def test_resolve_channels_with_labels(self):

        settings = ZwikSettings()
        settings.channel_alias = "https://dummy.org"
        settings.default_channels = ["foobar"]
        self.assertListEqual(
            settings.resolve_channels(
                channels=[
                    "defaults",
                    "https://special_domain.com/foobar",
                ],
                labels=[
                    "",
                    "main",
                    "unsafe",
                ],
            ),
            [
                "https://dummy.org/foobar",
                "https://special_domain.com/foobar",
                "https://dummy.org/foobar/labels/main",
                "https://special_domain.com/foobar/labels/main",
                "https://dummy.org/foobar/labels/unsafe",
                "https://special_domain.com/foobar/labels/unsafe",
            ],
        )

    def test_add_default_zwik_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = os.path.join(tmpdir, "credentials.json")
            with mock.patch.dict(
                os.environ,
                {
                    "ZWIK_CREDENTIAL_STORE": store_path,
                    "ZWIK_DEFAULT_USERNAME": "foo",
                    "ZWIK_DEFAULT_PASSWORD": "bar",
                    "ZWIK_URL": "https://dummy_domain.com",
                    "ZWIK_ALIAS_URL": "https://foobar.com",
                },
            ):
                settings = ZwikSettings()
                self.assertEqual(
                    {
                        "dummy_domain.com": {"foo": "bar"},
                        "foobar.com": {"foo": "bar"},
                    },
                    settings.credentials.credential_data,
                )

    def test_resolve_file_uri_channel(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            settings = ZwikSettings()
            channel_uri = pathlib.Path(tmpdir).as_uri()
            self.assertEqual(
                channel_uri,
                settings.resolve_channel(channel_uri),
            )
