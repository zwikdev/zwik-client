"""
Zwik client script for managing Conda environments

This script is able to manage the Conda environments. Every environment is
based on a yaml file containing the needed packages. The environments are
stored globally on the system, and therefore can be shared between projects.
If an environment already exists for a given yaml file, it will not be created
again but reused.

When the environment does not exist, it will be created. After creating the
environment a new yaml file will be created to lock the versions of the
packages and their dependencies. If a valid lock-file already exists during the
creation of the environment, this file is used to base the environment on.

It must be able to run this script concurrently. If another process is already
creating the same environment, this process will wait for it to complete.
"""

import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from typing import Optional

__version__ = "5.15"
min_supported_conda_version = "4.5.4"
max_supported_conda_version = "24.3.0"
min_supported_bootstrap_version = 7

log = logging.getLogger("zwik_client")

export_formats = ("yaml", "csv")

_example_yaml = """# This is an example environment
dependencies:
- python
"""


def create_link(link_dir: str, target_dir: str):
    log.debug("make link: %s => %s", link_dir, target_dir)
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(target_dir, link_dir)
    else:
        os.symlink(target_dir, link_dir)


def get_prefix_path_dirs(prefix):
    if os.name == "nt":  # pragma: unix no cover
        yield prefix.rstrip("\\")
        yield os.path.join(prefix, "Library", "mingw-w64", "bin")
        yield os.path.join(prefix, "Library", "usr", "bin")
        yield os.path.join(prefix, "Library", "bin")
        yield os.path.join(prefix, "Scripts")
    yield os.path.join(prefix, "bin")


def do_wait(timeout=60):
    import time

    log.warning(
        "Waiting for %d seconds to keep the message shown\n"
        "  (press a key to proceed)",
        timeout,
    )
    # noinspection PyBroadException
    try:
        if os.name == "nt":
            import msvcrt

            for _ in range(timeout * 10):
                time.sleep(0.1)
                if msvcrt.kbhit():
                    break
        else:
            import select

            _, _, _ = select.select([sys.stdin], [], [], timeout)
    except Exception:
        time.sleep(timeout)


class LockfileError(Exception):
    pass


class UrlNotFoundError(OSError):
    pass


class ZwikSettings:
    def __init__(self):
        self._initialized = False
        self._overrides = {}
        # noinspection PyDictCreation
        self._defaults = {}
        self._defaults["website_url"] = os.environ.get(
            "ZWIK_URL",
            "https://https://zwikdev.github.io",
        ).rstrip("/")
        self._defaults["client_url"] = "{}/install-data/zwik_client.py".format(
            self.website_url,
        )
        settings_url = "{}/install-data/zwik_client_settings.py".format(
            self.website_url,
        )
        self._defaults["settings_url"] = settings_url
        self._defaults["channel_alias"] = os.environ.get(
            "ZWIK_ALIAS_URL",
            "https://conda.anaconda.org",
        )
        self._defaults["default_channels"] = ["conda-forge"]
        self._defaults["bootstrap_version"] = os.environ.get("ZWIK_BOOT_VERSION")
        self._defaults["bootstrap_script"] = os.environ.get(
            "ZWIK_BOOT_SCRIPT",
            "./zwik_environment",
        )

        if "ZWIK_CLIENT_URL" in os.environ:
            self.client_url = os.environ["ZWIK_CLIENT_URL"]

        # Set the default channel while using bootstrap v3
        if "ZWIK_DEFAULT_CHANNELS" in os.environ:
            self.default_channels = os.environ["ZWIK_DEFAULT_CHANNELS"].split(";")

        self.credentials = ZwikCredentials()
        default_user = os.getenv("ZWIK_DEFAULT_USERNAME")
        default_password = os.getenv("ZWIK_DEFAULT_PASSWORD")
        if default_user and default_password:
            self.credentials.set(self.website_url, default_user, default_password)
            if not self.channel_alias.startswith(self.website_url):
                self.credentials.set(self.channel_alias, default_user, default_password)

        self._initialized = True

    def __getattr__(self, item):
        return self._overrides.get(
            item,
            self._defaults[item],
        )

    def __setattr__(self, key, value):
        if not key.startswith("_") and key in self._defaults:
            if self._initialized:
                log.debug("Setting '%s' is overrriden to: %s", key, value)
            else:
                log.warning(
                    "CAUTION: The setting '%s' is overridden to: %s",
                    key,
                    value,
                )
            self._overrides[key] = value

        super().__setattr__(key, value)

    @property
    def default_pkg_dir_suffix(self):
        if "default_channels" in self._overrides:
            import hashlib
            import re

            pkgs_dir_suffix = re.sub(
                r"\W+",
                "-",
                ",".join(self.default_channels),
            )
            hash_md5 = hashlib.md5()
            hash_md5.update(pkgs_dir_suffix.encode())
            return "pkg{}".format(
                hash_md5.hexdigest()[:6],
            )
        return "pkg_zwik"

    def run_hook(self):
        # noinspection PyBroadException
        try:
            hooks_module = get_hooks_module()
            if hooks_module:
                settings_hook = getattr(hooks_module, "settings_hook", None)
                if settings_hook:
                    return settings_hook(self)
        except Exception:
            log.exception("Error while running settings hook")
        return False

    def resolve_channel(self, channel, label=None):
        from urllib.parse import quote, urlparse

        if label:
            channel += "/labels/" + label
        if not urlparse(channel).scheme:
            channel = self.channel_alias.rstrip("/") + "/" + channel
        credential = self.credentials.obtain(channel + "/noarch/repodata.json")
        if credential:
            parsed_url = urlparse(channel)
            hostname = parsed_url.hostname
            if parsed_url.port:
                hostname += ":{}".format(parsed_url.port)
            # noinspection PyProtectedMember
            channel = parsed_url._replace(
                netloc="{}:{}@{}".format(
                    quote(credential[0], safe=""),
                    quote(credential[1], safe=""),
                    hostname,
                )
            ).geturl()
        return channel

    def resolve_channels(self, channels=(), labels=("",)):
        expanded_channels = []
        append_default_channels = True
        for channel in channels:
            if channel == "nodefaults":
                append_default_channels = False
            elif channel == "defaults":
                if append_default_channels:
                    expanded_channels += self.default_channels
                    append_default_channels = False
            else:
                expanded_channels.append(channel)

        if append_default_channels:
            expanded_channels += self.default_channels

        resolved_channels = []
        for label in labels:
            for channel in expanded_channels:
                try:
                    resolved_channels.append(self.resolve_channel(channel, label))
                except UrlNotFoundError:
                    pass
        return resolved_channels


class ZwikCredentials:
    def __init__(self):
        self._store_path = os.getenv(
            "ZWIK_CREDENTIAL_STORE",
            "{}_credentials.json".format(os.path.splitext(__file__)[0]),
        )
        self.credential_data = {}
        self.read_credentials()

    def read_credentials(self):
        import json

        try:
            with open(self._store_path) as f:
                self.credential_data = json.load(f)
        except FileNotFoundError:
            pass

    def obtain_url_opener(self, url):
        credential = self.obtain(url)
        return self._url_opener(url, credential)

    @staticmethod
    def _url_opener(url, credential: tuple = None):
        from urllib import request

        if credential:
            username, password = credential
        else:
            username = password = None
        password_manager = request.HTTPPasswordMgrWithDefaultRealm()
        password_manager.add_password(
            None,
            url,
            username,
            password,
        )
        auth_handler = request.HTTPBasicAuthHandler(password_manager)
        opener = request.build_opener(auth_handler)
        opener.addheaders = [
            ("User-Agent", "zwik-client/{}".format(__version__)),
            ("Accept", "*/*"),
        ]
        return opener

    def validate(self, url, credential):
        from urllib.error import URLError
        from urllib.request import Request

        opener = self._url_opener(url, credential)
        request_obj = Request(url=url, method="HEAD")
        request_obj.timeout = 180
        try:
            opener.open(request_obj)
            return True
        except URLError as e:
            if getattr(e, "code", None) == 401:
                return False
            log.debug("Unable to validate url: %s", url)
            if getattr(e, "code", None) == 404:
                raise UrlNotFoundError
            raise

    @staticmethod
    def read_credential_interactively(previous_username=None):
        import getpass

        default_user = previous_username or getpass.getuser().lower()
        username = input("Username [%s]: " % default_user) or default_user
        password = getpass.getpass("Password for %s:" % username)
        credential = (username, password)
        return credential

    @staticmethod
    def _get_hostname(url_or_hostname):
        from urllib.parse import urlparse

        parsed_url = urlparse(url_or_hostname)
        if not parsed_url.scheme.startswith("http"):
            return None
        return parsed_url.hostname or url_or_hostname

    @staticmethod
    def obtain_from_hook(url, previous_username):
        hook_cred = None
        # noinspection PyBroadException
        try:
            hooks_module = get_hooks_module()
            if hooks_module:
                hook = getattr(hooks_module, "obtain_credentials_hook", None)
                if hook:
                    hook_cred = hook(url, previous_username)
        except Exception:
            log.exception("Error while running credentials hook")
        return hook_cred

    def obtain(self, url):
        cred = None
        hostname = self._get_hostname(url)
        if not hostname:
            return None
        possible_credentials = [
            (user, pwd) for user, pwd in self.credential_data.get(hostname, {}).items()
        ]
        retries_left = 3
        while True:
            if self.validate(url, cred):
                break

            if retries_left <= 0:
                raise ValueError("No valid credentials found for: %s", url)

            if possible_credentials:
                cred = possible_credentials.pop(0)
            else:
                retries_left -= 1
                cred = self.obtain_from_hook(url, cred and cred[0])
                if cred is None:
                    print("\nPlease provide the right credentials to access: " + url)
                    cred = self.read_credential_interactively(cred and cred[0])

        if cred:
            self.set(url, username=cred[0], password=cred[1])
        return cred

    def set(self, url, username, password):
        hostname = self._get_hostname(url)
        if hostname:
            hostname_creds = self.credential_data.setdefault(hostname, {})
            hostname_creds.update({username: password})
            self.store()

    def store(self):
        import json

        credential_data = json.dumps(self.credential_data)
        with open(self._store_path, "w") as f:
            f.write(credential_data)


def import_yaml():
    try:
        from ruamel.yaml import YAML
    except ModuleNotFoundError:
        from ruamel_yaml import YAML

    return YAML()


class ZwikActivationData:
    def __init__(self):
        self.env_vars = {}
        self.activate_scripts = ()
        self.deactivate_scripts = ()
        self.run_script_template = "%s"

    @classmethod
    def from_prefix(cls, prefix):
        obj = cls()

        try:
            from conda.activate import Activator

            shell = "cmd.exe" if os.name == "nt" else "posix"
            activator = Activator(shell)
        except ImportError:
            if os.name == "nt":
                from conda.activate import CmdExeActivator as Activator
            else:
                from conda.activate import PosixActivator as Activator
            activator = Activator(["activate"])
            activator.stack = False
        activator.env_name_or_prefix = prefix
        activate_data = activator.build_activate(prefix)
        env = getattr(activator, "environ", os.environ)
        env["CONDA_PREFIX"] = prefix
        env["CONDA_SHLVL"] = "1"
        deactivate_data = activator.build_deactivate()

        obj.env_vars = {}
        for key in sorted(activate_data.get("unset_vars", ())):
            obj.env_vars[key] = None
        set_vars = activate_data.get("set_vars", {})
        for key, value in sorted(iter(set_vars.items())):
            obj.env_vars[key] = str(value)
        export_vars = activate_data.get("export_vars", {})
        for key, value in sorted(iter(export_vars.items())):
            obj.env_vars[key] = str(value)

        obj.activate_scripts = activate_data.get("activate_scripts", ())
        obj.deactivate_scripts = deactivate_data.get("deactivate_scripts", ())
        obj.run_script_template = activator.run_script_tmpl

        return obj


class CustomFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None):
        super().__init__(fmt, datefmt)

    def format(self, record):
        result = super().format(record)
        if "zwik_pat_" in result:
            result = re.sub("zwik_pat_[a-zA-Z0-9_-]{5,}", "zwik_pat_******", result)
        return result


class EnvironmentDependencies:
    def __init__(self, dep_list):
        from conda.exports import MatchSpec

        self.specs = []
        self.pkg_channels = {}
        for dep in dep_list:
            spec = MatchSpec(dep)
            self.specs.append(spec)
            if "channel" in spec:
                self.pkg_channels[spec.name] = spec.get("channel").name

    def get_specs(self, settings) -> list:
        from conda.exports import MatchSpec

        specs = []
        for ms in self.specs:
            spec = str(ms)
            if "::" in spec:
                channel, spec = spec.split("::")
                ms = MatchSpec(
                    spec,
                    channel=settings.resolve_channel(channel),
                )
            specs.append(ms)
        return specs

    def get_lock_file_dependencies(self, solved_dep_list) -> list:
        lockfile_dependencies = []
        for rec in solved_dep_list:
            dependency = rec.name + "=" + rec.version + "=" + rec.build
            if rec.name in self.pkg_channels:
                dependency = "{}::{}".format(self.pkg_channels[rec.name], dependency)
            lockfile_dependencies.append(dependency)
        return lockfile_dependencies


class EnvironmentExecutor:
    script_args = ()

    def __init__(self, prefix, env):
        self.prefix = prefix
        self.activation_data = ZwikActivationData.from_prefix(self.prefix)
        self.env = env or os.environ.copy()

        env_tmpfile = tempfile.NamedTemporaryFile(
            mode="w",
            prefix="zwik_orig_env_",
            suffix=".json",
            delete=False,
        )
        json.dump(self.env, env_tmpfile)
        env_tmpfile.close()
        self.orig_env_file = env_tmpfile.name

        for key, value in self.activation_data.env_vars.items():
            if value is None:
                self.env.pop(key, None)
            else:
                self.env[key] = str(value)

        self.env["PATH"] = self._remove_conda_from_path(self.env["PATH"])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for script in self.activation_data.deactivate_scripts:
            log.debug('Run deactivate script: "%s"', script)
            subprocess.call(
                ["zwik-client_deactivate", *self.script_args, script],
                executable=self.get_shell(),
                env=self.env,
            )
        if os.path.exists(self.orig_env_file):
            os.unlink(self.orig_env_file)

    def _remove_conda_from_path(self, path_env_var_value):
        clean_path = path_env_var_value.split(os.path.pathsep)
        if sys.base_exec_prefix != self.prefix:
            for path_dir in get_prefix_path_dirs(sys.base_exec_prefix):
                if path_dir in clean_path:
                    log.debug('Remove base prefix "%s" from PATH', path_dir)
                    clean_path.remove(path_dir)
        for path_dir in clean_path:
            if path_dir.endswith("condabin"):
                log.debug('Remove condabin dir "%s" from PATH', path_dir)
                clean_path.remove(path_dir)
        return os.path.pathsep.join(clean_path)

    def get_shell(self):
        raise NotImplementedError()

    def _call_shell(self, args):
        shell = self.get_shell()
        log.debug(
            "> %s %s",
            os.path.basename(shell),
            " ".join(['"{}"'.format(x) if " " in x else x for x in args]),
        )
        result = subprocess.call(
            ["zwik-client", *args],
            executable=shell,
            env=self.env,
        )
        return result

    def execute(self, cmd_args, write_dot_env=False):
        raise NotImplementedError()


class UnixEnvironmentExecutor(EnvironmentExecutor):
    def __init__(self, prefix, env):
        super().__init__(prefix, env)

    def get_shell(self):
        shell = os.environ.get("SHELL", "/bin/bash")
        if not os.path.exists(shell):
            # If given shell is not found, fallback on sh
            shell = "/usr/bin/sh"
        return shell

    def execute(self, cmd_args, write_dot_env=False):
        rc_file_fd, rc_file_path = tempfile.mkstemp(suffix=".sh", prefix="ps1_")
        log.debug("Using rc file at %s", rc_file_path)
        try:
            rc_file_contents = ""
            for script in self.activation_data.activate_scripts:
                script_cmd = self.activation_data.run_script_template % script
                rc_file_contents += "{}\n".format(script_cmd)

            if write_dot_env:
                rc_file_contents += self._get_dot_env_cmd()

            if cmd_args is None:
                shell = self.get_shell()
                is_bash = shell.endswith("/bash")
                if is_bash:
                    # Run .bashrc as part of new rc-script if it exists
                    bashrc = os.path.expanduser("~/.bashrc")
                    if os.path.exists(bashrc):
                        rc_file_contents += '. "{}"\n'.format(bashrc)
                    args = ["--rcfile", rc_file_path]
                elif shell.endswith("zsh"):
                    rc_file_contents += 'export RPROMPT="(zwik)"\n'

                rc_file_contents += 'export PS1="(zwik) $PS1"\n'
                if not is_bash:
                    rc_file_contents += shell + "\n"
                    args = [rc_file_path]
            else:
                rc_file_contents += self._get_cmd_line(cmd_args)
                args = [rc_file_path]
            os.write(rc_file_fd, rc_file_contents.encode())
            os.close(rc_file_fd)

            return self._call_shell(args)
        finally:
            if rc_file_path:
                os.unlink(rc_file_path)

    def _get_cmd_line(self, cmd_args):
        if len(cmd_args) == 1:
            cmd_line = cmd_args[0].replace("\\", "\\\\")
        else:
            # Escape double quotes and replace \ with \\ as single \
            # get removed during execution
            cmd_line = '"{}"'.format(
                '" "'.join(
                    [x.replace("\\", "\\\\").replace('"', '\\"') for x in cmd_args]
                )
            )
        return cmd_line

    def _get_dot_env_cmd(self):
        return "{} {} {} {}\n".format(
            sys.executable,
            __file__,
            "--write-env-file",
            self.orig_env_file,
        )


class WindowsEnvironmentExecutor(EnvironmentExecutor):
    script_args = ("/C",)

    def __init__(self, prefix, env):
        super().__init__(prefix, env)

    def get_shell(self):
        shell = os.environ.get("ComSpec", "C:\\Windows\\System32\\cmd.exe")
        return shell

    def execute(self, cmd_args, write_dot_env=False):
        args = list(self.script_args)

        if cmd_args is None:
            # Keep prompt open when not executing a command
            args = ["/K"]

        # Don't show the commands specified inside the activate scripts
        args += ["@ECHO", "OFF", "&"]

        # Execute all activate script before executing the actual command
        for script in self.activation_data.activate_scripts:
            args += ["@CALL", script, "&"]

        if write_dot_env:
            args += [
                "@CALL",
                sys.executable,
                __file__,
                "--write-env-file",
                self.orig_env_file,
                "&",
            ]

        if cmd_args is None:
            # If no command is given, just change the prompt and continue
            args += ["@SET", "PROMPT=(zwik) %PROMPT%", "&"]
            # Make sure the prompt is correctly shown
            args += ["@ECHO", "ON", "&"]
        else:
            if len(cmd_args) == 1:
                import re
                import shlex

                # If a path contains a single \ (e.g. test\dir\file.txt),
                # then the single \ get removed after shlex. The re.sub()
                # function will replace one \ with \\ unless it is
                # escaping a double quote.
                cmd = re.sub(r'\\([^"])', r"\\\\\1", cmd_args[0])
                cmd_args = shlex.split(cmd)
            args += cmd_args

        return self._call_shell(args)


class ZwikEnvironment(object):
    def __init__(self, zwik_settings: ZwikSettings):
        self.settings = zwik_settings
        self._yaml_hash = None
        self.override_prefix = None
        self.working_dir = None
        self.wait = True
        self.alias = None
        self.channels = ["defaults"]
        self.env_data = {}
        self.lock_data = None
        self.yaml_path = None
        self.lockfile_hash = None
        self._installation_checked = False

    @classmethod
    def from_yaml(cls, zwik_settings, yaml_file, working_dir=None):
        log.debug("Use yaml file for conda environment: %s", yaml_file)
        obj = cls(zwik_settings)
        obj.working_dir = working_dir
        if os.path.isabs(yaml_file):
            obj.yaml_path = yaml_file
            if not obj.working_dir:
                obj.working_dir = os.path.dirname(yaml_file)
        else:
            if not obj.working_dir:
                obj.working_dir = os.getcwd()
            obj.yaml_path = os.path.join(obj.working_dir, yaml_file)

        yaml = import_yaml()

        with open(obj.yaml_path) as fp:
            obj.env_data = yaml.load(fp)
        if obj.env_data:
            if "channels" in obj.env_data:
                channels = obj.env_data["channels"]
                for index, chan in enumerate(channels):
                    if chan in ("defaults", "nodefaults"):
                        continue
                    comment = (
                        cls.get_yaml_comment(
                            channels,
                            index,
                        )
                        or ""
                    )
                    if not comment.strip().startswith("# CAUTION: "):
                        log.warning(
                            "CAUTION: Specifying channels in environment file"
                            " without clear comment is not supported!"
                            " Only use custom channels if you know what"
                            " you're doing!"
                        )
                        break
                obj.channels = list(channels)
            if "name" in obj.env_data:
                obj.alias = obj.env_data["name"]

        try:
            obj.lock_data = obj.read_version_lock()
        except LockfileError as e:
            log.warning("Reading lock-file failed: %s", e)
        return obj

    @classmethod
    def from_package_list(cls, zwik_settings, package_specs):
        import hashlib
        import re

        log.debug("Use specs for conda environment: %s", ", ".join(package_specs))
        obj = cls(zwik_settings)
        obj.working_dir = os.getcwd()
        obj.yaml_path = os.path.join(
            obj.conda_envs_dir, re.sub("\\W+", "_", "_".join(package_specs)) + ".yaml"
        )
        hash_md5 = hashlib.md5()
        for spec in package_specs:
            hash_md5.update(spec.encode())
        obj._yaml_hash = hash_md5.hexdigest()
        obj.env_data = {
            "dependencies": package_specs,
        }
        obj.lock_data = obj.read_version_lock()
        return obj

    @classmethod
    def from_prefix(cls, zwik_settings, prefix):
        log.debug("Use prefix for conda environment: %s", prefix)
        obj = cls(zwik_settings)
        obj.working_dir = os.getcwd()
        obj.lock_data = {
            "dependencies": [],
        }
        if not os.path.isabs(prefix):
            prefix = os.path.join(obj.conda_envs_dir, prefix)
        obj.override_prefix = prefix
        return obj

    @property
    def prefix(self):
        if self.override_prefix:
            return self.override_prefix
        return os.path.join(self.conda_envs_dir, self.env_name)

    @property
    def conda_envs_dir(self):
        env_dir = os.environ.get("ZWIK_ENVS_PATH", os.environ.get("CONDA_ENVS_PATH"))
        if not env_dir and "ZWIK_ROOT" in os.environ:
            # if ZWIK_ROOT is given, check if writable
            try:
                from conda.exports import root_writable
            except ImportError:
                root_writable = True
            if root_writable:
                env_dir = os.path.join(os.environ["ZWIK_ROOT"], "envs")
        if not env_dir:
            # use conda's `envs_dirs` list as fallback
            from conda.exports import envs_dirs

            assert len(envs_dirs) > 0, "No suitable environment dir found!"
            env_dir = envs_dirs[0]
        return env_dir

    @property
    def yaml_hash(self):
        if not self._yaml_hash:
            import hashlib

            hash_md5 = hashlib.md5()
            with open(self.yaml_path, "r") as f:
                for line in f.readlines():
                    hash_md5.update(line.encode("utf-8"))
            self._yaml_hash = hash_md5.hexdigest()
        return self._yaml_hash

    @property
    def env_name(self):
        return self.lockfile_hash

    def is_created(self):
        return os.path.exists(os.path.join(self.prefix, "conda-meta", "history"))

    @property
    def version_lock_path(self):
        from pathlib import Path

        from conda.exports import subdir

        if self.yaml_path:
            yaml_path = Path(self.yaml_path)
            if yaml_path.suffix in [".yml", ".yaml"]:
                return "{}_{}.lock".format(yaml_path.with_suffix(""), subdir)
        return None

    def has_valid_lockfile(self):
        if self.lock_data is None:
            return False
        return True

    @staticmethod
    def get_file_integrity_hashes(path: str) -> [str, str]:
        import hashlib
        import re

        hash_md5 = hashlib.md5()
        expected_hash = None
        exp = re.compile("file integrity: ([0-9a-f]{32}|x{32})")
        with open(path, "r") as fp:
            for line in fp.readlines():
                m = exp.search(line)
                if expected_hash:
                    hash_md5.update(line.strip().encode())
                elif m:
                    expected_hash = m.group(1)
        if not expected_hash:
            raise AssertionError("No file integrity hash found in file")
        actual_hash = hash_md5.hexdigest()
        return [actual_hash, expected_hash]

    @classmethod
    def check_file_integrity(cls, path: str) -> bool:
        actual_hash, expected_hash = cls.get_file_integrity_hashes(path)
        return actual_hash == expected_hash

    def read_version_lock(self):
        yaml = import_yaml()

        path = self.version_lock_path
        if path and os.path.exists(path):
            try:
                actual_hash, expected_hash = self.get_file_integrity_hashes(path)
            except AssertionError as e:
                raise LockfileError(str(e))
            self.lockfile_hash = actual_hash
            if actual_hash != expected_hash:
                raise LockfileError("lock file seems corrupt")
            with open(path, "r") as fp:
                data = yaml.load(fp)
                if "yaml_hash" not in data:
                    raise LockfileError("lock file seems incomplete")
                if data["yaml_hash"] == self.yaml_hash:
                    channel_alias = (
                        data.get("channel_alias"),
                        data.get("channel_alias").replace("http:", "https:"),
                    )
                    if self.settings.channel_alias not in channel_alias:
                        raise LockfileError("lock file conda alias mismatch")
                    lock_file_channels = ";".join(data.get("channels", []))
                    env_channels = ";".join(self.channels)
                    # also compare with list of default channels
                    #  for backwards compatibility
                    def_channels = ";".join(self.settings.default_channels)
                    if lock_file_channels not in (env_channels, def_channels):
                        raise LockfileError("lock file conda channel mismatch")
                    return data
                log.info(
                    "The lock file is not aligned with the actual environment file"
                )
                return None
        log.info("No version lock file found")
        return None

    def write_version_lock(self, lock_dep, obsolete_pkgs=(), unsafe_pkgs=()):
        import getpass
        import hashlib
        import io

        from conda.exports import subdir

        yaml = import_yaml()

        path = self.version_lock_path
        if not path:
            return

        data = {
            "script_version": __version__,
            "subdir": subdir,
            "yaml_hash": self.yaml_hash,
            "channel_alias": self.settings.channel_alias,
            "channels": self.channels,
            "dependencies": sorted(lock_dep),
        }

        labels = {}
        for p in obsolete_pkgs:
            labels[p] = "obsolete"
        for p in unsafe_pkgs:
            labels[p] = "unsafe"
        if labels:
            data["labels"] = labels

        stream = io.StringIO()
        yaml.dump(data, stream)
        output = stream.getvalue()
        new_hash = hashlib.md5()
        for line in output.splitlines():
            new_hash.update(line.strip().encode())
        new_yaml_hash = new_hash.hexdigest()

        log.info("Write version lock file")
        if os.path.exists(path):
            os.unlink(path)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fp:
            fp.write(
                "# This file belongs to the Zwik client\n"
                "# it locks dependencies of your project to a known state\n"
                "# please commit this file to your version control system\n"
                "# \n"
                "# This file is generated automatically, do not change it!\n"
                "# file is created on {} by {}\n".format(
                    datetime.datetime.now(), getpass.getuser()
                )
            )
            fp.write("# lockfile integrity: %s\n" % new_yaml_hash)
            fp.write(output)

    def _check_installation(self):
        if self._installation_checked:
            return

        if os.environ.get("SKIP_INSTALLATION_CHECK", False):
            log.warning("Installation check skipped on request")
        else:
            if not check_installation(self.settings, False):
                log.error(
                    "Try to continue, but to solve the issue, run:\n\n %s --fix\n",
                    os.path.basename(
                        os.environ.get("ZWIK_BOOT_SCRIPT", "zwik_environment")
                    ),
                )
                if self.wait:
                    do_wait(5)
        self._installation_checked = True

    @staticmethod
    def get_yaml_comment(list_data, index):
        try:
            return list_data.ca.items[index][0].value
        except (KeyError, AttributeError):
            return None

    def create_lockfile(self, additional_dependencies=()):

        assert (
            not self.override_prefix
        ), "Can't create lock-file when using --prefix argument"

        self._check_installation()

        dependencies = self.get_dependencies(additional_dependencies)

        from conda.exceptions import (
            PackagesNotFoundError,
            ResolvePackageNotFound,
            UnsatisfiableError,
        )
        from conda.exports import subdir

        obsolete_pkgs = set()
        unsafe_pkgs = set()
        last_exception = None
        # First check only the original urls, then also the obsolete labels
        #  and finally also unsafe labels
        for labels in ((), ("obsolete",), ("obsolete", "unsafe")):
            solver = self.get_solver(dependencies, labels)
            try:
                link_precs = solver.solve_final_state()

                if labels:
                    for prec in link_precs:
                        split_channel = prec.channel.name.split("/")
                        if len(split_channel) > 1:
                            # Format is <channel>/labels/<label>
                            _, _, label = split_channel
                            if label == "obsolete":
                                obsolete_pkgs.add(prec.name)
                            else:
                                unsafe_pkgs.add(prec.name)
                    if unsafe_pkgs:
                        self.handle_unsafe_pkgs(unsafe_pkgs)
                break
            except (
                PackagesNotFoundError,
                ResolvePackageNotFound,
                UnsatisfiableError,
            ) as exception:
                last_exception = exception
        else:
            raise last_exception

        if obsolete_pkgs:
            log.warning(
                "WARNING: These packages are marked as obsolete,"
                " try to update or find an alternative:\n%s"
                ", ".join(obsolete_pkgs),
            )
        if unsafe_pkgs:
            log.warning(
                "WARNING: Packages below are marked as UNSAFE."
                " Client continues because of comment in environment file.\n%s"
                ", ".join(unsafe_pkgs),
            )

        solved_dep_list = link_precs.item_list
        lockfile_deps = dependencies.get_lock_file_dependencies(solved_dep_list)

        if set(self.env_data["dependencies"]) == set(lockfile_deps):
            log.info("Skip creation of lock file as packages are already locked")
            if not self.lockfile_hash:
                self.lockfile_hash = self.yaml_hash
            self.lock_data = {
                "script_version": __version__,
                "subdir": subdir,
                "yaml_hash": self.yaml_hash,
                "channel_alias": self.settings.channel_alias,
                "channels": self.channels,
                "dependencies": sorted(self.env_data["dependencies"][:]),
            }
        else:
            self.write_version_lock(
                lockfile_deps,
                obsolete_pkgs,
                unsafe_pkgs,
            )
            self.lock_data = self.read_version_lock()
            assert self.lock_data

    def get_dependencies(self, additional_dependencies):
        if self.env_data and "dependencies" not in self.env_data:
            log.error("No dependencies specified in yaml file")
            sys.exit(1)

        dep_list = []
        import re

        from conda.exports import platform, subdir

        for index, env_dep in enumerate(self.env_data["dependencies"]):
            comment = (
                self.get_yaml_comment(
                    self.env_data["dependencies"],
                    index,
                )
                or ""
            )
            m = re.match(r"# +\[([a-z0-9-]+)]", comment)
            if m and (m.group(1) not in (platform, subdir)):
                continue
            dep_list.append(env_dep)
        dep_list += additional_dependencies
        return EnvironmentDependencies(dep_list)

    def get_solver(self, dependencies, labels):
        from conda.exports import subdir

        try:
            from conda_libmamba_solver import LibMambaSolver as Solver
        except ImportError:
            from conda.exports import Solver

        urls = self.settings.resolve_channels(
            self.channels,
            ("",) + labels,
        )
        log.debug(
            "Trying the following channels to find the packages:\n"
            "- {}".format("\n- ".join(urls))
        )
        fake_prefix = os.path.join(self.working_dir, "fake_prefix")

        return Solver(
            fake_prefix,
            urls,
            (subdir, "noarch"),
            specs_to_add=dependencies.get_specs(self.settings),
        )

    def handle_unsafe_pkgs(self, unsafe_pkgs):
        from conda.exports import MatchSpec

        for pkg_name in unsafe_pkgs:
            for index, env_dep in enumerate(self.env_data["dependencies"]):
                env_dep_spec = MatchSpec(env_dep)
                if env_dep_spec.name == pkg_name:
                    comment = self.get_yaml_comment(
                        self.env_data["dependencies"],
                        index,
                    )
                    if comment and comment.strip().startswith(
                        "# CAUTION: UNSAFE PACKAGE"
                    ):
                        break
            else:
                from conda import CondaError

                raise CondaError(
                    "ERROR: The following package is UNSAFE,"
                    " check {}/unsafe"
                    " for more info: {}".format(
                        self.settings.website_url,
                        pkg_name,
                    )
                )

    def partially_update_lockfile(self, update_list):
        from conda.exports import MatchSpec

        log.info("Update packages in lock-file matching the given pattern(s)")

        additional_deps = []

        # If everything needs to be updated, just ignore all lock-file deps
        if "*" not in update_list:
            update_specs = [MatchSpec(x) for x in update_list]
            for raw_spec in self.lock_data["dependencies"]:
                spec = MatchSpec(raw_spec)
                for update_spec in update_specs:
                    if update_spec.match(spec):
                        if "*" in update_spec.name:
                            additional_deps.append(spec.name)
                        else:
                            additional_deps.append(update_spec.dist_str())
                        break
                else:
                    additional_deps.append(raw_spec)
        self.create_lockfile(additional_deps)

    def create_env(self):
        log.info("Create new environment (%s)", self.prefix)
        from conda import __version__ as conda_version
        from conda.api import SubdirData
        from conda.core.link import PrefixSetup, UnlinkLinkTransaction

        self._check_installation()

        specs_to_add = self.lock_data["dependencies"]
        channels = self.settings.resolve_channels(
            self.lock_data["channels"],
        )
        obsolete_channels = self.settings.resolve_channels(
            self.lock_data["channels"], ("obsolete",)
        )
        default_channels = self.settings.resolve_channels(
            ["defaults"],
        )
        subdirs = [self.lock_data["subdir"], "noarch"]
        link_precs = []

        for spec in specs_to_add:
            spec_name, _ = spec.split("=", maxsplit=1)
            search_channels = channels
            label = self.lock_data.get("labels", {}).get(spec_name)
            if label:
                search_channels = self.settings.resolve_channels(
                    self.lock_data["channels"], ("", label)
                )
            result = SubdirData.query_all(spec, search_channels, subdirs)
            if not result:
                result = SubdirData.query_all(spec, obsolete_channels, subdirs)
                if result:
                    log.warning(
                        "The package '%s' is obsolete,"
                        " please review the environment",
                        spec_name,
                    )
                else:
                    raise AssertionError("Package not found: {}".format(spec))
            if len(set([x.md5 for x in result])) > 1:
                from_defaults = [x for x in result if x.schannel in default_channels]
                if len(from_defaults) == 1:
                    log.warning("Force using %s from default channel", spec)
                    result = from_defaults
                else:
                    raise AssertionError("Multiple packages found for: {}".format(spec))
            link_precs.append(result[0])
        additional_args = []
        if conda_version == "4.5.4":
            # Newer versions of Python (>=3.7) depend on python_abi
            #  which in turn depends on Python. Older versions of
            #  Conda (at least 4.5.4) don't handle this correctly
            #  which results in noarch package can't compile as
            #  Python is not yet linked. This _dirty_ fix puts Python
            #  at the beginning of the transaction list to make
            #  sure Python is available before linking noarch packages
            python_lp = None
            for lp in link_precs:
                if lp.name == "python":
                    for d in lp.combined_depends:
                        if d.name == "python_abi":
                            python_lp = lp
                            break
            if python_lp:
                log.warning(
                    "WARNING: Detected an old version of Conda"
                    " with a newer version of Python in the"
                    " environment. A workaround makes sure this"
                    " still works, but please update Conda"
                    " if possible!"
                )
                log.debug(
                    "Make sure Python is linked first"
                    " so noarch packages can be compiled"
                )
                link_precs.sort(key=lambda x: "0" if x == python_lp else "1")
        else:
            additional_args.append([])
        stp = PrefixSetup(self.prefix, [], link_precs, [], [], *additional_args)
        transaction = UnlinkLinkTransaction(stp)

        # Make sure the HOME environment variable is not set on Windows
        #  to prevent an error due to infinite recursion in
        #  `mkdir_p_sudo_safe` during Conda `unlink_link_transaction` call
        old_home = os.name == "nt" and os.environ.pop("HOME", None)

        transaction.execute()

        if old_home:
            os.environ["HOME"] = old_home

        # workaround for SSL: https://github.com/conda/conda/issues/8273
        libraries = (
            "libcrypto-1_1-x64.dll",
            "libssl-1_1-x64.dll",
        )
        for library in libraries:
            src_library_path = os.path.join(self.prefix, "Library", "bin", library)
            dest_library_path = os.path.join(self.prefix, "DLLs", library)
            if os.path.exists(src_library_path) and not os.path.exists(
                dest_library_path
            ):
                shutil.copyfile(src_library_path, dest_library_path)

    def execute(
        self,
        cmd_args: Optional[list],
        wait: bool = False,
        write_dot_env: bool = False,
    ):
        if cmd_args:
            log.info("Execute command within conda environment")
        log.debug("prefix location: {}".format(self.prefix))

        from conda.base.context import context

        context.changeps1 = False
        context.shortcuts = False

        env = os.environ.copy()

        if os.name == "nt":
            Executor = WindowsEnvironmentExecutor
        else:
            Executor = UnixEnvironmentExecutor

        with Executor(
            prefix=self.prefix,
            env=env,
        ) as executor:
            if shutil.which("conda", path=executor.env["PATH"]):
                log.warning(
                    "WARNING: Conda executable found, do NOT use Conda"
                    " within a Zwik environment!"
                )

            result = executor.execute(cmd_args, write_dot_env)

            log.debug("Deactivate and clean-up")

        if result != 0 and wait:
            do_wait()
        log.debug("Done")
        return result

    def activate(self, write_dot_env=False):
        log.info("Activating shell in Conda environment")
        try:
            self.execute(cmd_args=None, write_dot_env=write_dot_env)
        except KeyboardInterrupt:
            # ignore Ctrl-C
            pass

    @staticmethod
    def has_fixed_drive(path):
        import ctypes

        # noinspection PyBroadException
        try:
            DRIVE_FIXED = 3
            drive = os.path.splitdrive(os.path.realpath(path))[0] + "\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
            return drive_type == DRIVE_FIXED
        except Exception:
            log.exception("Error checking for local drive")
        return False

    def link_prefix(self, link_dir):
        log.info("Create link to real environment")
        if os.path.lexists(link_dir):
            # Remove existing link
            try:
                os.unlink(link_dir)
            except PermissionError:
                import stat

                status = os.lstat(link_dir)
                attribs = getattr(status, "st_file_attributes", 0)
                if not attribs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    os.rename(link_dir, link_dir + "_bak")
                    shutil.rmtree(link_dir + "_bak")
                else:
                    raise

        if os.name == "nt" and not self.has_fixed_drive(link_dir):
            log.warning("WARNING: Activating on non-NTFS drive can fail")

        create_link(link_dir, self.prefix)

    def fix_context(self):
        log.debug("Fix Conda context")
        from tempfile import TemporaryDirectory

        from conda.base.context import context, reset_context

        yaml = import_yaml()

        # Check if the yaml file contains any channel (apart from "defaults")
        if any([x != "defaults" for x in self.channels]):
            log.warning(
                "CAUTION: Custom channels are used,"
                " packages are fetched in workspace to avoid collision"
            )
            self.fix_gitignore_file()
            from conda.exports import subdir

            yaml_dir = os.path.dirname(self.yaml_path)
            pkgs_dir = os.path.abspath(
                os.path.join(
                    yaml_dir,
                    "conda_pkgs",
                    subdir,
                )
            )
        else:
            pkgs_dir = os.path.join(
                context.root_prefix,
                self.settings.default_pkg_dir_suffix,
            )
            # Write an info file which allows to
            #  identify where a packages folder is used for
            info_path = os.path.join(pkgs_dir, "zwik-info.txt")
            if not os.path.exists(info_path):
                os.makedirs(pkgs_dir, exist_ok=True)
                with open(info_path, "w") as fp:
                    fp.write(
                        "Package dir for: {}\n".format(
                            self.settings.channel_alias,
                        )
                    )
                    for c in self.settings.default_channels:
                        fp.write("- {}\n".format(c))

        zwik_config = {
            "pkgs_dirs": [pkgs_dir],
            "always_copy": context.always_copy,
            "channel_alias": self.settings.channel_alias,
        }

        os.environ["CONDA_PKGS_DIRS"] = pkgs_dir

        with TemporaryDirectory(prefix="zwik_tmp_") as tmpdir:
            rc_file = os.path.join(tmpdir, ".condarc")
            with open(rc_file, "w") as fp:
                yaml.dump(zwik_config, fp)
            reset_context((rc_file,))

        context.report_errors = False
        context.auto_update_conda = False
        context.add_pip_as_python_dependency = False
        context.use_pip = False
        context.notify_outdated_conda = False
        context.allow_softlinks = False
        context.add_anaconda_token = False
        context.create_default_packages = []
        return context

    def backup_env(self):
        p_dir = self.prefix
        if os.path.exists(p_dir):
            for i in range(20):
                bak_dir = "{}_bak{}".format(p_dir, i or "")
                if not os.path.exists(bak_dir):
                    break
            else:
                raise RuntimeError("Too many backups already exists, please cleanup")
            os.rename(p_dir, bak_dir)
            return bak_dir

    def fix_gitignore_file(self):
        gitignore_path = os.path.join(os.path.dirname(self.yaml_path), ".gitignore")
        entries = [
            "/conda_env",
            "/logs",
            "/conda_pkgs",
        ]
        with open(gitignore_path, "a+") as fp:
            fp.seek(0)
            for line in fp.readlines():
                entry = "/" + line.strip().lstrip("/")
                if entry in entries:
                    entries.remove(entry)
            if entries:
                log.warning("Add missing entries to .gitignore file")
                fp.write("\n")
                for entry in entries:
                    fp.write(entry + "\n")

    @classmethod
    def create_example_yaml(cls, yaml_file):
        yaml_dir = os.path.dirname(yaml_file)
        os.makedirs(yaml_dir, exist_ok=True)
        with open(yaml_file, "x") as fp:
            fp.write(_example_yaml)

    def export_environment(self, output_path, file_format=None):
        import glob
        import json

        if not file_format:
            _, file_extension = os.path.splitext(output_path)
            file_format = file_extension.lstrip(".")
            if file_format == "yml":
                file_format = "yaml"

        if file_format not in export_formats:
            log.warning(
                "Unsupported export file format (%s), use one of: %s",
                file_format,
                ", ".join(export_formats),
            )
            sys.exit(2)

        packages = {}
        pattern = os.path.join(self.prefix, "conda-meta", "*.json")
        for data_path in glob.iglob(pattern):
            with open(data_path) as fp:
                data = json.load(fp)
                name = data["name"]
                packages[name] = {
                    "name": name,
                    "version": data["version"],
                    "license": data.get("license", "<unknown>"),
                    "url": data["url"],
                }

        if file_format == "yaml":
            with open(output_path, "w") as fp:
                fp.write("dependencies:\n")
                for pkg_name, data in packages.items():
                    fp.write("- {name}={version}\n".format(**data))
        elif file_format == "csv":
            import csv

            with open(output_path, "w", newline="") as fp:
                writer = csv.DictWriter(
                    fp,
                    fieldnames=("name", "version", "license", "url"),
                )
                writer.writeheader()
                for pkg_name, data in packages.items():
                    writer.writerow(data)

        log.info("Environment exported to %s", output_path)


class EnvironmentLocker(object):
    def __init__(self, prefix: str, interval=10, timeout=120):
        import threading

        self.prefix = prefix
        self.interval = interval
        self.timeout = timeout
        self.lockfile_fp = None
        self.lockfile_thread = threading.Thread(target=self._keep_lock)
        self.stop_event = threading.Event()

    @property
    def lockfile(self):
        return os.path.realpath(self.prefix) + ".lock"

    def is_locked(self):
        return os.path.exists(self.lockfile)

    def _keep_lock(self):
        # Write lock file every 10 seconds to keep lock
        while not self.stop_event.wait(self.interval):
            log.debug("Keeping environment lock")
            self.lockfile_fp.write("Lock kept on {}\n".format(datetime.datetime.now()))
            self.lockfile_fp.flush()

    def is_timed_out(self):
        try:
            file_time = _get_file_last_modification_date(self.lockfile)
            now = datetime.datetime.now()
            before_timeout = now - datetime.timedelta(seconds=self.timeout)
            return file_time < before_timeout
        except FileNotFoundError:
            return False

    def _try_lock(self):
        try:
            os.makedirs(os.path.join(os.path.dirname(self.lockfile)), exist_ok=True)
            self.lockfile_fp = open(self.lockfile, "x")
            return True
        except FileExistsError:
            return False

    def __enter__(self):
        log.debug("Lock the environment (%s)", self.lockfile)
        show_warning = True
        while not self._try_lock():
            if show_warning:
                log.warning(
                    "Another process is creating the environment (%s),"
                    " waiting for it to complete",
                    self.prefix,
                )
                show_warning = False
            if self.is_timed_out():
                log.warning(
                    "Another process failed to create environment!" " Try recovery"
                )
                os.unlink(self.lockfile)
            else:
                # this will always wait, as the event will never trigger here
                self.stop_event.wait(self.interval)

        self.lockfile_fp.write(
            "Lock environment on {}\n".format(datetime.datetime.now())
        )
        self.lockfile_fp.flush()
        self.lockfile_thread.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_event.set()
        self.lockfile_thread.join()
        self.lockfile_fp.close()

        os.unlink(self.lockfile)
        log.debug("Environment unlocked (%s)", self.lockfile)


def current_conda_version():
    import conda.exports

    return conda.exports.VersionOrder(conda.__version__)


def fetch_script(zwik_settings, url, target_path, check_only=False):
    import hashlib
    from urllib.error import URLError

    script_name, _ = os.path.splitext(os.path.basename(target_path))

    installation_ok = True

    url_timeout = 180  # Make timeout long enough to support slow networks

    hash_md5 = hashlib.md5()
    with open(target_path, "rb") as f:
        hash_md5.update(f.read())
    local_md5 = hash_md5.hexdigest()

    try:
        md5_url = "{}.md5".format(url)
        opener = zwik_settings.credentials.obtain_url_opener(md5_url)
        opener.addheaders = [("Pragma", "no-cache")]
        with opener.open(md5_url, timeout=url_timeout) as fp:
            remote_md5 = fp.read().decode()

        if local_md5 != remote_md5:
            installation_ok = False
            log.warning("%s seems to be corrupt or outdated!", script_name)
            if not check_only:
                log.info("Download latest version of the %s", script_name)
                with open(target_path, "wb") as f:
                    opener = zwik_settings.credentials.obtain_url_opener(url)
                    opener.addheaders = [("Pragma", "no-cache")]
                    with opener.open(url, timeout=url_timeout) as fp:
                        latest_client = fp.read()
                    f.write(latest_client)
                log.warning("Next time the latest script version will be used!")
    except URLError as e:
        if getattr(e, "code", None) == 404:
            msg = (
                "{} not found on server ({})."
                " Please check if the correct server is specified"
                "".format(script_name, url)
            )
        else:
            msg = (
                "Check for {} failed, {}."
                " Please check the network connection.".format(
                    script_name,
                    getattr(e, "reason", "reason is unknown"),
                )
            )

        if not check_only:
            log.exception(msg)
            sys.exit(1)
        else:
            log.warning(msg)
            installation_ok = False

    return installation_ok


def check_installation(zwik_settings: ZwikSettings, fix: bool = False):
    log.info("Checking Zwik installation")

    installation_ok = True

    try:
        bootstrap_version_as_int = int(zwik_settings.bootstrap_version)
    except ValueError:
        bootstrap_version_as_int = 0

    if bootstrap_version_as_int < min_supported_bootstrap_version:
        log.info(
            'REMARK: the client script "%s" is outdated,'
            " get the latest version from %s"
            " for the best user experience",
            zwik_settings.bootstrap_script,
            zwik_settings.website_url,
        )

    if not fetch_script(
        zwik_settings,
        zwik_settings.client_url,
        __file__,
        check_only=not fix,
    ):
        installation_ok = False

    client_name, _ = os.path.splitext(__file__)
    settings_file_path = client_name + "_settings.py"
    if not fetch_script(
        zwik_settings,
        zwik_settings.settings_url,
        settings_file_path,
        check_only=not fix,
    ):
        installation_ok = False

    import conda.exports

    act_ver = current_conda_version()
    min_ver = conda.exports.VersionOrder(min_supported_conda_version)
    max_ver = conda.exports.VersionOrder(max_supported_conda_version)

    if act_ver < min_ver:
        log.warning("Conda version too old %s", act_ver)
        installation_ok = False

        if fix:
            # noinspection PyUnresolvedReferences
            import conda.config as conda_config

            uninstall_lock = conda_config.root_dir + ".uninstall"
            if os.path.exists(uninstall_lock):
                log.error("Conda uninstall already in progress")
                sys.exit(1)
            log.warning(
                "Unable to update conda, so try to uninstall it."
                " Please redo your action afterwards!"
            )
            with open(uninstall_lock, "w") as fp:
                fp.write(
                    "Conda uninstall in progress,"
                    " please delete this file if it's the only file"
                    " in this directory"
                )
            os.unlink(__file__)
            import time

            time.sleep(30)
            uninstaller = os.path.join(conda_config.root_dir, "Uninstall-Anaconda.exe")
            if os.path.exists(uninstaller):
                os.system("{} /S".format(uninstaller))
                log.warning(
                    "Uninstaller will continue in background!"
                    " This can take some time."
                )
                sys.exit(1)
            else:
                log.error(
                    "Please delete this folder manually: %s", conda_config.root_dir
                )
    elif act_ver > max_ver:
        log.warning(
            "Conda version (%s) might be too new. Latest supported version is %s",
            act_ver,
            max_ver,
        )
    else:
        log.info("Conda version (%s) is ok", act_ver)
        if act_ver != max_ver:
            log.info(
                "To update to latest supported version (%s),"
                " first remove existing Conda installation"
                " manually and then rerun the client script",
                max_ver,
            )

    return installation_ok


def apply_workarounds():
    # workaround to find missing python module (SSL)
    paths = os.environ.get("PATH", "").split(os.path.pathsep)
    for path_dir in get_prefix_path_dirs(sys.base_exec_prefix):
        if path_dir not in paths:
            paths.append(path_dir)
            log.debug("Add to PATH: %s", path_dir)
    os.environ["PATH"] = os.path.pathsep.join(paths)


def _get_file_last_modification_date(file_path):
    return datetime.datetime.fromtimestamp(os.path.getmtime(file_path))


def _update_lockfile(env, args):
    try:
        do_update = True
        if args.update_interval:
            file_time = _get_file_last_modification_date(env.version_lock_path)
            now = datetime.datetime.now()
            update_threshold = now - datetime.timedelta(hours=args.update_interval)
            if file_time > update_threshold:
                log.debug("Lock-file still up-to-date, skipping update")
                do_update = False
        if do_update:
            env.partially_update_lockfile(args.update)
    except Exception:
        if not args.update_interval:
            raise
        log.exception("Updating failed, continue now and retry next time")


def _create_or_recreate_env(env, args):
    if args.recreate or args.fix or not env.is_created():
        bak_dir = env.backup_env()
        try:
            env.create_env()
            if bak_dir:
                log.info("Delete old environment")
                shutil.rmtree(bak_dir, ignore_errors=True)
                bak_dir = None
        finally:
            if bak_dir:
                failed_env = env.backup_env()
                log.error(
                    "ERROR: Environment creation failure, see %s",
                    failed_env,
                )
                os.rename(bak_dir, env.prefix)
    else:
        log.info("Using already existing Conda environment")


def _activate_environment(env, args, environment_location, unattended):
    if not args.single_package and not args.prefix:
        env_link = args.env_link
        if env_link is None and not unattended:
            env_link = os.path.join(os.path.dirname(environment_location), "conda_env")
        if env_link:
            env.link_prefix(env_link)
    if env.alias and isinstance(env.alias, str) and not unattended:
        alias_path = os.path.join(env.conda_envs_dir, env.alias)
        env.link_prefix(alias_path)

    current_prefix = os.environ.get("CONDA_PREFIX", None)
    if current_prefix == env.prefix:
        log.warning("Environment already activated!")
    elif current_prefix:
        log.warning("Environment %s was already activated!", current_prefix)
        log.warning("Activating %s now!", env.prefix)
        env.activate()
    else:
        write_dot_env = True
        if args.prefix:
            write_dot_env = False
        env.activate(write_dot_env=write_dot_env)


def handle_environment(zwik_settings, environment_location, args, unattended):
    if args.fix and not check_installation(zwik_settings=zwik_settings, fix=True):
        return

    if args.prefix:
        env = ZwikEnvironment.from_prefix(zwik_settings, args.prefix)
    elif args.single_package:
        env = ZwikEnvironment.from_package_list(zwik_settings, args.single_package)
    else:
        if not os.path.exists(environment_location):
            ZwikEnvironment.create_example_yaml(environment_location)
        env = ZwikEnvironment.from_yaml(zwik_settings, environment_location)

    if not args.wait:
        env.wait = False
    env.fix_context()

    if not env.has_valid_lockfile():
        if not args.single_package:
            if unattended and not args.recreate:
                raise LockfileError(
                    "Valid lock-file is required when running unattended, "
                    "please commit lock-file to version control"
                )
            env.fix_gitignore_file()
        env.create_lockfile()
    elif args.update:
        _update_lockfile(env, args)

    with EnvironmentLocker(env.prefix):
        _create_or_recreate_env(env, args)

    _set_lock_file_env_var(env)

    if args.export:
        env.export_environment(output_path=args.export, file_format=args.export_format)
    elif args.execute:
        sys.exit(env.execute(cmd_args=args.execute, wait=args.wait))
    elif args.activate:
        _activate_environment(env, args, environment_location, unattended)
    else:
        print("CONDA_PREFIX={}".format(env.prefix))


def _set_lock_file_env_var(env):
    if env.version_lock_path:
        os.environ["ZWIK_LOCK_FILE"] = (
            env.version_lock_path
            if os.path.isfile(env.version_lock_path)
            else env.yaml_path
        )


def get_hooks_module():
    import importlib.util

    module = None
    client_name, _ = os.path.splitext(__file__)
    file_name = client_name + "_settings.py"
    try:
        spec = importlib.util.spec_from_file_location("zwik_settings", file_name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except FileNotFoundError:
        log.debug("No hooks module found")
    return module


def configure_logging(log_dir, log_level):
    custom_formatter = CustomFormatter(
        fmt="%(asctime)s %(message)s", datefmt="%H:%M:%S"
    )
    std_out_handler = logging.StreamHandler(sys.stdout)
    std_out_handler.setLevel(log_level)
    std_out_handler.setFormatter(custom_formatter)
    logging.root.addHandler(std_out_handler)

    if log_dir:
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir)
        log_file_handler = RotatingFileHandler(
            filename=os.path.join(log_dir, "zwik.log"),
            maxBytes=1024 * 1024,  # 1 MB
            backupCount=10,
            encoding="utf-8",
        )

        custom_formatter = CustomFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )

        log_file_handler.setFormatter(custom_formatter)
        log_file_handler.setLevel(logging.DEBUG)
        logging.root.addHandler(log_file_handler)

    logging.root.setLevel(logging.DEBUG)
    logging.getLogger("conda.core.link").setLevel(log_level + 10)
    logging.getLogger("conda.conda_libmamba_solver.solver").setLevel(log_level + 10)
    logging.getLogger("conda.gateways").setLevel(log_level + 10)


def write_env_file(orig_env_file):
    prefix = os.getenv("CONDA_PREFIX", sys.prefix)

    orig_env_data = {}
    if orig_env_file != "-":
        import json

        with open(orig_env_file) as fp:
            orig_env_data = json.load(fp)

    env_file = os.path.join(prefix, ".env")
    log.debug("Write .env to %s", env_file)
    with open(env_file, "w") as fp:

        for key, var in os.environ.items():
            if orig_env_data.get(key, "") != var:
                fp.write(
                    "{}={}\n".format(
                        key,
                        var,
                    )
                )

    sys.exit(0)


def get_unattended_msg(args):
    unattended_msg = None
    if args.unattended:
        unattended_msg = "Unattended mode requested via command-line"
    elif os.environ.get("JENKINS_HOME", None):
        unattended_msg = "Jenkins environment detected, running unattended"
    return unattended_msg


def log_env_vars():
    log.debug("Environment variables (for security reasons only keys are printed):")
    for key in os.environ:
        log.debug("ENV var: %s", key)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        prog="zwik_environment",
        add_help=False,
        usage="",
    )
    parser.usage = parser.prog

    parser.add_argument(
        "--help",
        "-h",
        action="store_true",
        help="show this help message and exit",
    )
    parser.add_argument(
        "--long-help",
        action="help",
        default=argparse.SUPPRESS,
        help="show this help including advanced options",
    )
    parser.add_argument(
        "--version",
        action="version",
        default=argparse.SUPPRESS,
        version=__version__,
        help="print the Zwik client version",
    )
    parser.add_argument(
        "--execute",
        "--exec",
        nargs=argparse.REMAINDER,
        help="execute the given command using the environment",
    )
    parser.add_argument(
        "--check-installation",
        action="store_true",
        help="verify the current Conda installation",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="try to fix installation issues (if needed)",
    )

    advanced = parser.add_argument_group("advanced arguments")
    advanced.add_argument(
        "--update",
        metavar="PATTERN",
        action="append",
        help="update specified package and its dependencies, accepts * as wildcard",
    )
    advanced.add_argument(
        "--update-all",
        action="append_const",
        const="*",
        dest="update",
        help="update all packages (creates new lock-file)",
    )
    advanced.add_argument(
        "--update-interval",
        metavar="HOURS",
        type=int,
        help="try updating when lockfile is older than given amount of hours",
    )
    advanced.add_argument(
        "--no-wait",
        dest="wait",
        action="store_false",
        help="exit immediately when an error occurs",
    )
    advanced.add_argument(
        "--verbose",
        "-v",
        default=0,
        action="count",
        help="increase the log level",
    )
    advanced.add_argument(
        "--quiet",
        "-q",
        default=0,
        action="count",
        help="decrease the log level",
    )
    advanced.add_argument(
        "--environment",
        metavar="PATH",
        help=(
            "use environment based on given yaml file"
            " (and create if it doesn't exists)"
        ),
    )
    advanced.add_argument(
        "--single-package",
        metavar="SPEC",
        action="append",
        help="use environment based on given package",
    )
    advanced.add_argument(
        "--prefix",
        metavar="PATH",
        help="use environment based on existing prefix path or hash",
    )
    advanced.add_argument(
        "--recreate",
        action="store_true",
        help="create new environment (even if already exists)",
    )
    advanced.add_argument(
        "--unattended",
        action="store_true",
        help="run the script in unattended mode",
    )
    advanced.add_argument(
        "--env-link",
        default=None,
        metavar="PATH",
        help=(
            "create link to env"
            " (create conda_env by default, if not running on unattended)"
        ),
    )
    advanced.add_argument(
        "--write-env-file",
        nargs="?",
        default=None,
        const="-",
        metavar="ORIG_ENV",
        help="generate .env file",
    )
    advanced.add_argument(
        "--skip-activate",
        dest="activate",
        action="store_false",
        help="skip conda activate after creating env",
    )
    advanced.add_argument(
        "--log-dir",
        help="specify a directory to write the log to",
    )
    advanced.add_argument(
        "--export",
        metavar="PATH",
        help="export environment data to the given file",
    )
    advanced.add_argument(
        "--export-format",
        choices=export_formats,
        help="force the format of the export file",
    )

    args = parser.parse_args(argv)

    if args.help:
        # noinspection PyProtectedMember
        parser._action_groups.remove(advanced)
        parser.print_help()
        parser.exit()

    if args.write_env_file:
        write_env_file(args.write_env_file)

    env_without_yaml = args.single_package or args.prefix

    log_level = logging.INFO + (args.quiet - args.verbose) * 10

    # check if running Unattended (e.g. on Jenkins)
    unattended_msg = get_unattended_msg(args)

    # decrease log level if using execute command
    #  (except when running unattended)
    if args.execute and not unattended_msg:
        log_level += 10

    # make log level available for scripts inside environment
    os.environ["ZWIK_LOG_LEVEL"] = str(log_level)

    log_dir = args.log_dir
    boot_script = os.environ.get("ZWIK_BOOT_SCRIPT")
    environment_location = args.environment or os.environ.get("ZWIK_ENVIRONMENT_PATH")

    if boot_script:
        boot_dir = os.path.dirname(boot_script)
        if not environment_location:
            environment_location = os.path.join(
                boot_dir,
                ".zwik",
                "zwik_environment.yaml",
            )
        if not log_dir and not env_without_yaml:
            log_dir = os.path.join(
                os.path.dirname(environment_location),
                "logs",
            )

    configure_logging(log_dir, log_level)

    log.info("Zwik client v%s (https://zwikdev.github.io)", __version__)

    apply_workarounds()

    zwik_settings = ZwikSettings()
    if zwik_settings.run_hook() is False and not args.fix:
        log.warning(
            "No settings hook found, client might misbehave!"
            " Try running with --fix to solve the issue."
        )

    log_env_vars()

    if boot_script:
        if not ZwikEnvironment.check_file_integrity(boot_script):
            log.warning(
                "WARNING: The environment script (%s) seems corrupt!",
                os.path.basename(boot_script),
            )

    if unattended_msg:
        log.info(unattended_msg)
        if os.environ.get("SKIP_INSTALLATION_CHECK", False):
            log.warning("Installation check skipped while running unattended")
        elif not args.check_installation:
            check_installation(zwik_settings=zwik_settings, fix=True)
        args.wait = False
        args.ignore_invalid_lockfile = False
    elif not args.check_installation:
        try:
            is_admin = getattr(os, "getuid")() == 0
        except AttributeError:
            import ctypes

            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        if is_admin:
            log.warning(
                "CAUTION: Activating the conda environment"
                " as admin/root can cause (permission) issues"
                " when activated as normal user afterwards"
            )
            input(
                "Do you accept potential (permission) issues?"
                " Press enter to proceed as admin/root\n"
            )

    # noinspection PyBroadException
    try:
        if args.check_installation:
            check_installation(zwik_settings, args.fix)
        elif environment_location or env_without_yaml:
            handle_environment(
                zwik_settings,
                environment_location,
                args,
                unattended_msg is not None,
            )
        else:
            parser.error("No environment path provided")
    except KeyboardInterrupt:
        exit(1)
    except Exception:
        if args.wait:
            log.exception("Internal error")
            do_wait()
        else:
            raise


if __name__ == "__main__":
    main()
