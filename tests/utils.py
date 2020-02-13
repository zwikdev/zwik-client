import hashlib
import http.server
import io
import json
import logging
import os
import pathlib
import re
import tempfile
import threading
import unittest


class DummyZwikServer(http.server.HTTPServer):
    class RequestHandler(http.server.BaseHTTPRequestHandler):
        def _send_response(self, data, content_type="text/plain"):
            self.send_response(200)
            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            assert isinstance(self.server, DummyZwikServer)

            if self.path.startswith("/install-data"):
                _, file = self.path.strip("/").split("/", maxsplit=1)
                if file == "zwik_client.py":
                    with open(self.server.client_script_path, "rb") as f:
                        self._send_response(f.read())
                elif file == "zwik_client.py.md5":
                    hash_md5 = hashlib.md5()
                    with open(self.server.client_script_path, "rb") as f:
                        hash_md5.update(f.read())
                    self._send_response(hash_md5.hexdigest().encode())
                elif file == "zwik_client_settings.py":
                    with open(self.server.settings_script_path, "rb") as f:
                        self._send_response(f.read())
                elif file == "zwik_client_settings.py.md5":
                    hash_md5 = hashlib.md5()
                    with open(self.server.settings_script_path, "rb") as f:
                        hash_md5.update(f.read())
                    self._send_response(hash_md5.hexdigest().encode())
                elif file == "dummy.py.md5":
                    self._send_response(b"0" * 32)
                else:
                    self.send_error(404)
                return

            channel, path = self.path.strip("/").split("/", maxsplit=1)

            if path.startswith("labels"):
                _, label, arch, file = path.split("/")
            else:
                arch, file = path.split("/")
                label = None

            dummy_chan = self.server.dummy_channel
            dummy_fn = "{}-1.0-0.tar.bz2".format(self.server.dummy_name)
            dummy_lbl = self.server.dummy_label
            dummy_arch = self.server.dummy_arch
            dummy_data = self.server.dummy_data
            dummy_size = dummy_data.seek(0, io.SEEK_END)
            dummy_data.seek(0)

            if file == "repodata.json":
                packages = {}

                if label == dummy_lbl and arch == dummy_arch and channel == dummy_chan:
                    packages[dummy_fn] = {
                        "build": "0",
                        "build_number": 0,
                        "depends": [],
                        "license": "BSD",
                        "license_family": "BSD",
                        "md5": hashlib.md5(dummy_data.getbuffer()).hexdigest(),
                        "name": self.server.dummy_name,
                        "sha256": hashlib.sha256(dummy_data.getbuffer()).hexdigest(),
                        "size": dummy_size,
                        "subdir": arch,
                        "timestamp": 1616161616161,
                        "version": "1.0",
                    }
                    if arch == "noarch":
                        packages[dummy_fn]["noarch"] = "generic"

                repodata = {
                    "info": {"subdir": arch},
                    "packages": packages,
                    "packages.conda": {},
                    "removed": [],
                    "repodata_version": 1,
                }
                self._send_response(
                    json.dumps(repodata).encode(),
                    "application/json",
                )
            else:
                if label == dummy_lbl and arch == dummy_arch and file == dummy_fn:
                    self._send_response(
                        dummy_data.getvalue(),
                        "application/tar+gzip",
                    )
                else:
                    self.send_error(404)

        def do_HEAD(self):
            assert isinstance(self.server, DummyZwikServer)

            self._send_response(data=b"")

    def __init__(self, channel=None):
        super().__init__(("0.0.0.0", 0), self.RequestHandler)
        self.thread = threading.Thread(target=self.serve_forever)
        self.client_script_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "scripts",
                "zwik_client.py",
            )
        )
        self.settings_script_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "scripts",
                "zwik_client_settings.py",
            )
        )
        self._dummy_channel = channel or "dummy-zwik-channel"
        self.dummy_label = None
        self.dummy_arch = "noarch"
        self.dummy_name = "dummy-package"
        self.dummy_content = b"a" * 30
        self.dummy_content_path = "foobar.txt"
        self._data = None

    @property
    def server_url(self):
        return "http://127.0.0.1:{}/".format(self.server_port)

    @property
    def dummy_channel(self):
        return self._dummy_channel

    @dummy_channel.setter
    def dummy_channel(self, channel):
        if self.thread.is_alive():
            raise RuntimeError("Channel of server can't be changed after starting")
        self._dummy_channel = channel

    @property
    def channel_url(self):
        return self.server_url + self._dummy_channel

    @property
    def dummy_data(self):
        if not self._data:
            import io
            import tarfile

            self._data = io.BytesIO()
            with tarfile.open(fileobj=self._data, mode="w:bz2") as tar:
                tarinfo = tarfile.TarInfo("info/repodata_record.json")
                tarinfo.size = 3
                tar.addfile(tarinfo, io.BytesIO(b"{}\n"))

                tarinfo = tarfile.TarInfo("info/index.json")
                tarinfo.size = 3
                tar.addfile(tarinfo, io.BytesIO(b"{}\n"))

                tarinfo = tarfile.TarInfo("info/files")
                tarinfo.size = len(self.dummy_content_path)
                tar.addfile(tarinfo, io.BytesIO(self.dummy_content_path.encode()))

                tarinfo = tarfile.TarInfo(self.dummy_content_path)
                tarinfo.size = len(self.dummy_content)
                tar.addfile(tarinfo, io.BytesIO(self.dummy_content))
        return self._data

    def start(self):
        self.thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()
        self.thread.join()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


class DummyServerEnvironmentTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._old_env = None

    def setUp(self):
        self._old_env = os.environ.copy()

        self._tmp_dir_obj = tempfile.TemporaryDirectory()
        self.working_dir = self._tmp_dir_obj.name
        os.environ["ZWIK_ROOT"] = self.working_dir

        boot_script_name = "zwik_environment"
        project_root = pathlib.Path(__file__).parent.parent
        boot_script_path = project_root / "bootstrap" / boot_script_name
        os.environ["ZWIK_BOOT_SCRIPT"] = str(boot_script_path)

        boot_script_version = None
        for path in boot_script_path.parent.glob(boot_script_name + "*"):
            match = re.search(r"ZWIK_BOOT_VERSION=(\d)", path.read_text())
            if match:
                if boot_script_version is None:
                    boot_script_version = match.group(1)
                elif boot_script_version != match.group(1):
                    raise ValueError("Version mismatch in bootstrap scripts")

        if not boot_script_version:
            raise ValueError("No bootstrap script version found")

        os.environ["ZWIK_BOOT_VERSION"] = boot_script_version

        self.dummy_server = DummyZwikServer()
        self.dummy_server.start()
        os.environ["ZWIK_URL"] = self.dummy_server.server_url
        os.environ["ZWIK_ALIAS_URL"] = self.dummy_server.server_url
        os.environ["ZWIK_DEFAULT_CHANNELS"] = self.dummy_server.dummy_channel
        unset_vars = (
            "ZWIK_CLIENT_URL",
            "ZWIK_LOCK_FILE",
            "SKIP_INSTALLATION_CHECK",
            "JENKINS_HOME",
            "ZWIK_ENVS_PATH",
            "CONDA_ENVS_PATH",
            "CONDA_PKGS_DIRS",
        )
        for var in unset_vars:
            if var in os.environ:
                del os.environ[var]

    def tearDown(self):
        self.dummy_server.stop()

        # Make sure all logging files are closed before removing tmp dir
        handlers = logging.root.handlers[:]
        for handler in handlers:
            if isinstance(handler, logging.FileHandler):
                if handler.baseFilename.startswith(self._tmp_dir_obj.name):
                    handler.close()
                    logging.root.removeHandler(handler)

        self._tmp_dir_obj.cleanup()

        if self._old_env:
            os.environ.clear()
            os.environ.update(self._old_env)
