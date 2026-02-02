import datetime
import glob
import hashlib
import json
import logging
import os
import sys
import tempfile
from unittest import TestCase, mock

from scripts.zwik_client import (
    LockfileError,
    ZwikEnvironment,
    ZwikSettings,
    check_installation,
    do_wait,
    main,
)
from tests.utils import DummyServerEnvironmentTest, DummyZwikServer


class TestZwikEnvironment(DummyServerEnvironmentTest):
    def setUp(self):
        super().setUp()
        self.yaml_file = os.path.join(
            self.working_dir,
            ".zwik",
            "zwik_environment.yml",
        )

        ZwikEnvironment.create_example_yaml(self.yaml_file)
        self.dummy_server.dummy_name = "python"

    @staticmethod
    def create_env(env):
        env.fix_context()
        env.create_lockfile()
        if not env.is_created():
            env.create_env()

    def test_old_conda_version(self):
        with mock.patch("conda.__version__", "4.5.4"):
            with mock.patch("conda.core.link.UnlinkLinkTransaction"):
                with mock.patch("conda.core.link.PrefixSetup") as ps:
                    env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
                    self.create_env(env)
                    ps.assert_called_once()
                    link_precs = ps.call_args[0][2]
                    self.assertEqual(link_precs[0].name, "python")

    def test_default_channels_override(self):
        os.environ["ZWIK_DEFAULT_CHANNELS"] = "dummy"

        with self.assertLogs(level=logging.WARNING):
            env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        context = env.fix_context()

        hash_md5 = hashlib.md5()
        hash_md5.update(b"dummy")
        pkgs_dir_suffix = hash_md5.hexdigest()[:6]
        self.assertTupleEqual(
            context.pkgs_dirs,
            (
                os.path.join(
                    context.root_prefix,
                    "pkg{}".format(pkgs_dir_suffix),
                ),
            ),
        )

        with mock.patch.dict(os.environ, {"ZWIK_DEFAULT_CHANNELS": "a" * 200}):
            with self.assertLogs(level=logging.WARNING):
                env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
            context = env.fix_context()

        hash_md5 = hashlib.md5()
        hash_md5.update(b"a" * 200)
        pkgs_dir_suffix = hash_md5.hexdigest()[:6]
        self.assertTupleEqual(
            context.pkgs_dirs,
            (
                os.path.join(
                    context.root_prefix,
                    "pkg{}".format(pkgs_dir_suffix),
                ),
            ),
        )

    def test_obj_from_yaml(self):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        env.fix_context()

        self.assertEqual(env.has_valid_lockfile(), False)
        env.create_lockfile()

        self.assertEqual(env.yaml_path, self.yaml_file)
        self.assertEqual(env.has_valid_lockfile(), True)
        self.assertEqual(env.working_dir, os.path.join(self.working_dir, ".zwik"))
        self.assertEqual(env.env_name, env.lockfile_hash)
        self.assertEqual(env.conda_envs_dir, os.path.join(self.working_dir, "envs"))
        self.assertEqual(
            env.prefix, os.path.join(self.working_dir, "envs", env.lockfile_hash)
        )

    @mock.patch(
        "scripts.zwik_client.ZwikEnvironment.version_lock_path",
        new_callable=mock.PropertyMock,
    )
    def test_invalid_lock_file(self, mock_lock_path):
        dummy_lock_file = os.path.join(self.working_dir, ".zwik", "dummy.lock")
        with open(dummy_lock_file, "w") as fp:
            fp.write("foobar")
        mock_lock_path.return_value = dummy_lock_file
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.assertIsNone(env.lock_data)

    def test_envs_dir_override(self):
        env = ZwikEnvironment.from_prefix(ZwikSettings(), "abcde")
        self.assertEqual(
            env.conda_envs_dir,
            os.path.join(self.working_dir, "envs"),
        )
        with mock.patch.dict(os.environ, {"ZWIK_ROOT": "dummy_root"}):
            self.assertEqual(
                env.conda_envs_dir,
                os.path.join("dummy_root", "envs"),
            )
        with mock.patch.dict(os.environ, {"CONDA_ENVS_PATH": "dummy"}):
            self.assertEqual(
                env.conda_envs_dir,
                "dummy",
            )
            with mock.patch.dict(os.environ, {"ZWIK_ENVS_PATH": "zwik_dummy"}):
                self.assertEqual(
                    env.conda_envs_dir,
                    "zwik_dummy",
                )

    def test_obj_from_package_list(self):
        env = ZwikEnvironment.from_package_list(ZwikSettings(), ["python"])
        env.fix_context()

        self.assertEqual(env.has_valid_lockfile(), False)
        env.create_lockfile()
        self.assertEqual(env.has_valid_lockfile(), True)

        self.assertEqual(
            env.conda_envs_dir,
            os.path.join(self.working_dir, "envs"),
        )
        from conda.exports import subdir

        self.assertEqual(
            env.version_lock_path,
            os.path.join(env.conda_envs_dir, "python_{}.lock".format(subdir)),
        )
        self.assertEqual(
            env.prefix,
            os.path.join(self.working_dir, "envs", env.lockfile_hash),
        )

    def test_obj_from_prefix_hash(self):
        env = ZwikEnvironment.from_prefix(ZwikSettings(), "abcde")
        self.assertEqual(
            env.conda_envs_dir,
            os.path.join(self.working_dir, "envs"),
        )
        self.assertEqual(
            env.prefix,
            os.path.join(self.working_dir, "envs", "abcde"),
        )

    def test_obj_from_prefix_path(self):
        env = ZwikEnvironment.from_prefix(
            ZwikSettings(),
            "/path/to/existing/prefix",
        )
        self.assertEqual(
            env.prefix,
            "/path/to/existing/prefix",
        )

    def test_yaml_with_custom_channels(self):
        yaml_file = os.path.join(self.working_dir, ".zwik", "custom_channels.yml")
        with open(yaml_file, "w") as fp:
            fp.writelines(
                [
                    "channels:\n",
                    "  - http://foobar.com  # CAUTION: foobar\n",
                    "  - defaults\n",
                ]
            )
        env = ZwikEnvironment.from_yaml(ZwikSettings(), yaml_file)
        self.assertListEqual(["http://foobar.com", "defaults"], env.channels)
        with open(yaml_file, "w") as fp:
            fp.writelines(
                [
                    "channels:\n",
                    "  - nodefaults\n",
                    "  - http://no_caution\n",
                ]
            )
        with self.assertLogs(level=logging.WARNING):
            env = ZwikEnvironment.from_yaml(ZwikSettings(), yaml_file)
            context = env.fix_context()

        from conda.exports import subdir

        expected_pkg_dir = os.path.join(
            self.working_dir,
            ".zwik",
            "conda_pkgs",
            subdir,
        )
        self.assertTupleEqual(context.pkgs_dirs, (expected_pkg_dir,))

    def test_aaa_create_lockfile_with_channel_specified(self):
        # This test starts with `aaa` as it currently requires a specific order
        # TODO: update to mamba >=2.0.0 to solve issues when changing alias
        #   after the solver has run before

        yaml_file = os.path.join(self.working_dir, ".zwik", "channel_specified.yml")
        with open(yaml_file, "w") as fp:
            fp.writelines(
                [
                    "dependencies:\n",
                    "  - {}::{}\n".format(
                        self.dummy_server.dummy_channel,
                        self.dummy_server.dummy_name,
                    ),
                ]
            )
        env = ZwikEnvironment.from_yaml(ZwikSettings(), yaml_file)
        env._installation_checked = True
        env.fix_context()
        env.create_lockfile()

    def test_lockfile_not_needed(self):
        yaml_file = os.path.join(self.working_dir, ".zwik", "packages_locked.yml")
        with open(yaml_file, "w") as fp:
            fp.writelines(
                [
                    "dependencies:\n",
                    "  - {}=1.0=0\n".format(self.dummy_server.dummy_name),
                ]
            )
        env = ZwikEnvironment.from_yaml(ZwikSettings(), yaml_file)
        env.fix_context()
        with mock.patch(
            "scripts.zwik_client.ZwikEnvironment.write_version_lock"
        ) as patch_write_lockfile:
            env.create_lockfile()
            patch_write_lockfile.assert_not_called()

    def test_env_is_created(self):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        env._installation_checked = True

        env.fix_context()
        env.create_lockfile()

        self.assertEqual(env.is_created(), False)
        self.create_env(env)
        self.assertEqual(env.is_created(), True)

        backup_dir = env.backup_env()
        self.assertEqual(os.path.exists(env.prefix), False)
        self.assertEqual(env.is_created(), False)
        self.assertEqual(os.path.exists(backup_dir), True)

    def test_dot_env_file(self):
        if "FOOBAR_ENV" in os.environ:
            del os.environ["FOOBAR_ENV"]

        os.environ["BARFOO_ENV"] = "dummy"

        if sys.platform == "win32":
            self.dummy_server.dummy_content_path = (
                "etc/conda/activate.d/python_activate.bat"
            )
            self.dummy_server.dummy_content = b"set FOOBAR_ENV=42\n"
        else:
            self.dummy_server.dummy_content_path = (
                "etc/conda/activate.d/python_activate.sh"
            )
            self.dummy_server.dummy_content = b"export FOOBAR_ENV=42\n"

        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        env._installation_checked = True
        self.create_env(env)
        env.execute(["whoami"], write_dot_env=True)

        dot_env_path = os.path.join(env.prefix, ".env")
        self.assertTrue(os.path.exists(dot_env_path))
        with open(dot_env_path) as fp:
            dot_env_data = fp.read()
        self.assertIn("FOOBAR_ENV", dot_env_data)
        self.assertNotIn("BARFOO_ENV", dot_env_data)

        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["CONDA_PREFIX"] = tmpdir
            with self.assertRaises(SystemExit) as cm:
                main(
                    [
                        "--write-env-file",
                    ]
                )
            self.assertEqual(cm.exception.code, 0)

            dot_env_path = os.path.join(tmpdir, ".env")
            self.assertTrue(os.path.exists(dot_env_path))
            with open(dot_env_path) as fp:
                dot_env_data = fp.read()
            self.assertIn("BARFOO_ENV", dot_env_data)

            orig_env_file = os.path.join(tmpdir, "orig.json")
            with open(orig_env_file, "w") as fp:
                json.dump(
                    {
                        "BARFOO_ENV": "dummy",
                    },
                    fp,
                )
            with self.assertRaises(SystemExit) as cm:
                main(
                    [
                        "--write-env-file",
                        orig_env_file,
                    ]
                )
            self.assertEqual(cm.exception.code, 0)

            with open(dot_env_path) as fp:
                dot_env_data = fp.read()
            self.assertNotIn("BARFOO_ENV", dot_env_data)

    def test_home_env_var_is_preserved_in_environment(self):
        with mock.patch.dict(
            os.environ,
            {
                "HOME": "fake_home_dir",
            },
        ):
            if os.name == "nt":
                test_cmd = 'IF "%HOME%"=="fake_home_dir" (exit 42) ELSE (exit 43)'
            else:
                test_cmd = '[ "$HOME" = "fake_home_dir" ] && exit 42 || exit 43'

            with self.assertRaises(SystemExit) as cm:
                main(
                    [
                        "--prefix",
                        sys.prefix,
                        "--no-wait",
                        "-q",
                        "--unattended",
                        "--exec",
                        test_cmd,
                    ]
                )

            self.assertEqual(cm.exception.code, 42)

    def test_execute(self):
        env = ZwikEnvironment.from_prefix(ZwikSettings(), sys.prefix)

        result = env.execute(["python", "--version"])
        self.assertEqual(result, 0)

        result = env.execute(["python", "-c", "exit(1)"])
        self.assertEqual(result, 1)

        result = env.execute(['python -c "a = 6 + 2; exit(a)"'])
        self.assertEqual(result, 8)

        result = env.execute(['python -c "exit(int(6/2))"'])
        self.assertEqual(result, 3)

        # The following cases test how \\ are parse. By default \ are already
        # escaped before the call to execute()\ (e.g. print("a\\b") will
        # be passed as print("a\\\\b") to execute)

        # Windows
        if os.name == "nt":
            result = env.execute(["python -c \"print('a\\\\b'); exit(1)\""])
            self.assertEqual(result, 1)

            result = env.execute(["python -c \"exit(len('a\\\\b'))\""])
            self.assertEqual(result, 3)

            result = env.execute(["python -c \"assert len('a\\\\b') == 3\""])
            self.assertEqual(result, 0)

            result = env.execute(["python", "-c", "exit(len('a\\\\b'))"])
            self.assertEqual(result, 3)
        else:
            # Unix
            result = env.execute(["python -c 'print(\"a\\bc\"); exit(1)'"])
            self.assertEqual(result, 1)

            result = env.execute(["python -c 'exit(len(\"a\\b\"))'"])
            self.assertEqual(result, 3)

            result = env.execute(["python -c 'assert len(\"a\\b\") == 3'"])
            self.assertEqual(result, 0)

            result = env.execute(["python", "-c", 'exit(len("c\\d"))'])
            self.assertEqual(result, 3)

    @mock.patch("subprocess.call")
    def test_activate(self, process_mock):
        env = ZwikEnvironment.from_prefix(ZwikSettings(), sys.prefix)

        if os.name == "nt":
            env.activate()
            args = process_mock.call_args_list[0][0][0]
            self.assertTrue(any(x for x in args if "PROMPT=(zwik)" in x))
        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                bash_bin_path = os.path.join(tmpdir, "bash")
                with open(bash_bin_path, "w") as fp:
                    fp.write("# dummy bash executable")
                bash_rc_path = os.path.join(tmpdir, ".bashrc")
                with open(bash_rc_path, "w") as fp:
                    fp.write("# dummy rc file")

                def check_bash_process_call(cmd_args, executable, **kwargs):
                    if cmd_args[0] != "zwik-client":
                        return

                    self.assertListEqual(
                        cmd_args,
                        [mock.ANY, "--rcfile", mock.ANY],
                    )
                    zwik_rc_path = cmd_args[2]
                    with open(zwik_rc_path) as fp:
                        script_data = fp.read()
                    self.assertIn(
                        bash_rc_path,
                        script_data,
                    )
                    self.assertEqual(
                        executable,
                        bash_bin_path,
                    )

                with mock.patch.dict(
                    os.environ,
                    {
                        "HOME": tmpdir,
                        "SHELL": bash_bin_path,
                    },
                ):
                    process_mock.side_effect = check_bash_process_call
                    env.activate()

                zsh_bin_path = os.path.join(tmpdir, "zsh")
                with open(zsh_bin_path, "w") as fp:
                    fp.write("# dummy zsh executable")

                def check_zsh_process_call(cmd_args, executable, env, **kwargs):
                    if cmd_args[0] != "zwik-client":
                        return

                    self.assertEqual(2, len(cmd_args))
                    zwik_rc_path = cmd_args[1]
                    with open(zwik_rc_path) as fp:
                        script_data = fp.read()

                    self.assertIn(
                        zsh_bin_path,
                        script_data,
                    )
                    self.assertEqual(
                        executable,
                        zsh_bin_path,
                    )
                    self.assertIn(
                        'export RPROMPT="(zwik)"',
                        script_data,
                    )

                with mock.patch.dict(os.environ, {"SHELL": zsh_bin_path}):
                    process_mock.side_effect = check_zsh_process_call
                    env.activate()

                non_existing_bin_path = os.path.join(tmpdir, "non-existing")

                def check_sh_process_call(cmd_args, executable, env, **kwargs):
                    if cmd_args[0] != "zwik-client":
                        return

                    self.assertEqual(2, len(cmd_args))
                    zwik_rc_path = cmd_args[1]
                    with open(zwik_rc_path) as fp:
                        script_data = fp.read()
                    self.assertIn(
                        "(zwik)",
                        script_data,
                    )
                    self.assertEqual(
                        executable,
                        "/usr/bin/sh",
                    )

                with mock.patch.dict(
                    os.environ,
                    {
                        "ENV": "",
                        "SHELL": non_existing_bin_path,
                    },
                ):
                    process_mock.side_effect = check_sh_process_call
                    env.activate()

    @mock.patch("subprocess.call")
    @mock.patch("scripts.zwik_client.ZwikActivationData.from_prefix")
    def test_activation_data(self, activator_mock, process_mock):
        activator_mock.return_value.env_vars = {
            "FOO": "BAR",
        }
        activator_mock.return_value.activate_scripts = ("activate_script",)
        activator_mock.return_value.deactivate_scripts = ("deactivate_script",)
        activator_mock.return_value.run_script_template = "barfoo=%s"

        def check_process_call(cmd_args, executable, env, **kwargs):
            if cmd_args[0] == "zwik-client":
                if os.name == "nt":
                    self.assertIn("activate_script", cmd_args)
                else:
                    self.assertEqual(2, len(cmd_args))
                    zwik_rc_path = cmd_args[1]
                    with open(zwik_rc_path) as fp:
                        script_data = fp.read()
                    self.assertIn(
                        "barfoo=activate_script",
                        script_data,
                    )
            elif cmd_args[0] == "zwik-client_deactivate":
                self.assertEqual("deactivate_script", cmd_args[-1])
            else:
                raise AssertionError("invalid call")

        process_mock.side_effect = check_process_call

        env = ZwikEnvironment.from_prefix(ZwikSettings(), sys.prefix)
        env.execute(["whoami"])

        self.assertEqual(2, process_mock.call_count)

    def test_export(self):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        export_path = os.path.join(self.working_dir, "export_file.csv")
        export_format = "csv"
        env.export_environment(export_path, export_format)
        self.assertTrue(os.path.exists(export_path))

        export_path = os.path.join(self.working_dir, "export_file.yaml")
        export_format = "yaml"
        env.export_environment(export_path, export_format)
        self.assertTrue(os.path.exists(export_path))

    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.apply_workarounds")
    @mock.patch("scripts.zwik_client.handle_environment")
    @mock.patch("builtins.input", return_value="\n")
    def test_non_admin(self, mock_input, handle_env, workarounds, check):
        main(["--environment", self.yaml_file])
        check.assert_not_called()

    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.apply_workarounds")
    @mock.patch("scripts.zwik_client.handle_environment")
    def test_workarounds_are_always_applied(self, handle_env, workarounds, check):
        # in jenkins, the tests are run as admin so mock the input call
        with mock.patch("builtins.input", return_value="\n"):
            main(["--environment", self.yaml_file])
            workarounds.assert_called_once()

        workarounds.reset_mock()
        main(
            [
                "--environment",
                self.yaml_file,
                "--unattended",
            ]
        )
        workarounds.assert_called_once()

    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.apply_workarounds")
    @mock.patch("scripts.zwik_client.handle_environment")
    def test_unattended_is_set_by_env_ver(
        self, handle_env, workarounds, check_installation
    ):
        # in jenkins, the tests are run as admin so mock the input call
        with mock.patch("builtins.input", return_value="\n"):
            main(["--environment", self.yaml_file])
            check_installation.assert_not_called()

        with mock.patch.dict(os.environ, {"JENKINS_HOME": "fake_dir"}):
            main(["--environment", self.yaml_file])
            check_installation.assert_called_once()

    def test_create_lockfile_with_invalid_installation(self):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        with mock.patch("scripts.zwik_client.check_installation") as ci_patch:
            with mock.patch("scripts.zwik_client.do_wait") as do_wait:
                do_wait.side_effect = RuntimeError
                ci_patch.return_value = False
                with self.assertRaises(RuntimeError):
                    env.create_lockfile()

    def test_short_help(self):
        with mock.patch("argparse.ArgumentParser._print_message") as patch:
            with self.assertRaises(SystemExit):
                main(["--help"])
            patch.assert_called_once()
            help_lines = patch.call_args[0][0].split("\n")
            self.assertLess(len(help_lines), 15)

    @mock.patch("builtins.input", return_value="\n")
    def test_lockfile_integrity(self, _):
        os.environ["SKIP_INSTALLATION_CHECK"] = "1"
        with DummyZwikServer() as server2:
            self.dummy_server.dummy_name = "python"
            server2.dummy_name = "foobar"
            channels = ";".join(
                [
                    self.dummy_server.channel_url,
                    server2.channel_url,
                ]
            )
            with mock.patch.dict(os.environ, {"ZWIK_DEFAULT_CHANNELS": channels}):
                env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
                env.fix_context()
                env.create_lockfile()

                new_env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
                self.assertEqual(new_env.has_valid_lockfile(), True)

                # Add new package to yaml file
                with open(new_env.yaml_path, "a") as fp:
                    fp.write("- foobar")
                new_env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
                self.assertEqual(new_env.has_valid_lockfile(), False)
                new_env.create_lockfile()
                self.assertEqual(new_env.has_valid_lockfile(), True)

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_env_creation_in_unattended_mode(self, check, execute, create_env):
        non_existing = os.path.join(self.working_dir, "non_existing.yaml")
        with self.assertRaises(LockfileError):
            main(
                [
                    "--environment",
                    non_existing,
                    "--unattended",
                ]
            )
        main(
            [
                "--environment",
                non_existing,
                "--recreate",
                "--unattended",
            ]
        )

        lock_files = glob.glob(os.path.join(self.working_dir, "*.lock"))
        self.assertEqual(len(lock_files), 1)

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_single_package_in_unattended(self, check, execute, create_env):
        main(
            [
                "--single-package",
                "python",
                "--unattended",
            ]
        )
        lock_files = glob.glob(os.path.join(self.working_dir, "envs", "*.lock"))
        self.assertEqual(len(lock_files), 1)

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_export_environment_in_unattended(self, check, execute, create_env):
        export_path = os.path.join(self.working_dir, "test_export.yml")
        main(
            [
                "--single-package",
                "python",
                "--export",
                export_path,
                "--unattended",
            ]
        )
        self.assertTrue(os.path.exists(export_path))

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_execute_existing_env_by_prefix_arg(self, check, execute, create_env):
        main(
            [
                "--prefix",
                "existing_env_name",
                "--unattended",
            ]
        )
        execute.assert_called_once()

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.partially_update_lockfile")
    def test_env_with_lock_file_doesnt_update_env(
        self, mock_update_lock, check, execute, create_env
    ):
        # unattended mode requires an existing environment, so we create one
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)
        main(
            [
                "--environment",
                self.yaml_file,
                "--unattended",
            ]
        )
        mock_update_lock.assert_not_called()

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.partially_update_lockfile")
    def test_update_env_with_a_package_in_unattended(
        self, mock_update_lock, check, execute, create_env
    ):
        # unattended mode requires an existing environment, so we create one
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        main(
            [
                "--environment",
                self.yaml_file,
                "--update",
                "foobar",
                "--unattended",
            ]
        )
        mock_update_lock.assert_called_once_with(["foobar"])

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.partially_update_lockfile")
    @mock.patch("scripts.zwik_client._get_file_last_modification_date")
    def test_env_update_all_with_time_interval(
        self,
        mock_get_mod_date,
        mock_update_lock,
        check,
        execute,
        create_env,
    ):
        from freezegun import freeze_time

        # Create an environment so it doesn't require an update
        with freeze_time("Jan 1th, 2020") as frozen_datetime:
            mock_get_mod_date.return_value = datetime.datetime(2020, 1, 1)
            env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
            self.create_env(env)
            interval_in_hours = 500
            main(
                [
                    "--environment",
                    self.yaml_file,
                    "--update-all",
                    "--update-interval",
                    str(interval_in_hours),
                    "--unattended",
                ]
            )
            mock_update_lock.assert_not_called()

            one_hour_over_the_interval_in_seconds = (interval_in_hours + 1) * 3600
            frozen_datetime.tick(one_hour_over_the_interval_in_seconds)
            main(
                [
                    "--environment",
                    self.yaml_file,
                    "--update-all",
                    "--update-interval",
                    str(interval_in_hours),
                    "--unattended",
                ]
            )
            mock_update_lock.assert_called_once_with(["*"])

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.partially_update_lockfile")
    def test_env_update_all_immediately(
        self,
        mock_update_lock,
        check,
        execute,
        create_env,
    ):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        main(
            [
                "--environment",
                self.yaml_file,
                "--update-all",
                "--update-interval",
                "0",  # this value can overflow
                "--unattended",
            ]
        )
        mock_update_lock.assert_called_once_with(["*"])
        mock_update_lock.reset_mock()
        main(
            [
                "--environment",
                self.yaml_file,
                "--update-all",
                "--update-interval",
                "-9999",
                "--unattended",
            ]
        )
        mock_update_lock.assert_called_once_with(["*"])

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.partially_update_lockfile")
    def test_failed_update_without_time_interval_breaks(
        self,
        mock_update_lock,
        check,
        execute,
        create_env,
    ):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        mock_update_lock.side_effect = RuntimeError()
        with self.assertRaises(RuntimeError):
            main(
                [
                    "--environment",
                    self.yaml_file,
                    "--update-all",
                    "--unattended",
                ]
            )

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.partially_update_lockfile")
    def test_failed_update_with_time_interval_still_executes(
        self,
        mock_update_lock,
        check,
        execute,
        create_env,
    ):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        mock_update_lock.side_effect = RuntimeError()
        main(
            [
                "--environment",
                self.yaml_file,
                "--update-all",
                "--update-interval",
                "-1",
                "--unattended",
            ]
        )
        execute.assert_called_once()

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_activate_environment_without_any_other_env(
        self, check, execute, create_env
    ):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        with mock.patch.dict(os.environ, {"CONDA_PREFIX": ""}):
            with self.assertLogs() as logs:
                main(
                    [
                        "--environment",
                        self.yaml_file,
                        "--unattended",
                    ]
                )
                self.assertFalse(
                    any([x for x in logs.output if "already activated" in x])
                )

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_activate_environment_inside_other_env(self, check, execute, create_env):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        with mock.patch.dict(os.environ, {"CONDA_PREFIX": "other_prefix"}):
            with self.assertLogs() as logs:
                main(
                    [
                        "--environment",
                        self.yaml_file,
                        "--unattended",
                    ]
                )
                self.assertIn(
                    "WARNING:zwik_client:Environment other_prefix"
                    " was already activated!",
                    logs.output,
                )

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_activate_environment_in_itself(self, check, execute, create_env):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        prefix = os.path.join(self.working_dir, "envs", env.lockfile_hash)
        with mock.patch.dict(os.environ, {"CONDA_PREFIX": prefix}):
            with self.assertLogs() as logs:
                main(
                    [
                        "--environment",
                        self.yaml_file,
                        "--unattended",
                    ]
                )
                self.assertIn(
                    "WARNING:zwik_client:Environment already activated!",
                    logs.output,
                )

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_fix_env_in_unattended(self, check, execute, create_env):
        # unattended mode requires an existing environment, so we create one
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        main(
            [
                "--environment",
                self.yaml_file,
                "--fix",
                "--unattended",
            ]
        )
        check.assert_called()

    @mock.patch("scripts.zwik_client.do_wait")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_environment_exception_handling(self, check, do_wait):
        non_existing = os.path.join(self.working_dir, "non_existing.yaml")

        check.side_effect = KeyboardInterrupt
        with self.assertRaises(SystemExit):
            main(
                [
                    "--environment",
                    non_existing,
                    "--check-installation",
                    "--unattended",
                ]
            )

        check.side_effect = RuntimeError
        with self.assertRaises(RuntimeError):
            main(
                [
                    "--environment",
                    non_existing,
                    "--check-installation",
                    "--unattended",
                ]
            )

        check.side_effect = RuntimeError
        do_wait.reset_mock()
        main(
            [
                "--environment",
                non_existing,
                "--check-installation",
            ]
        )
        do_wait.assert_called_once()

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_lockfile")
    def test_partially_update_lockfile(self, create_lock: mock.MagicMock):
        env = ZwikEnvironment(ZwikSettings())
        env.lock_data = {
            "dependencies": [
                "py-foobar=1.0=py_0",
                "python=3.7=2",
            ]
        }

        env.partially_update_lockfile(["*"])
        create_lock.assert_called_once_with([])

        create_lock.reset_mock()
        env.partially_update_lockfile(["non-existing"])
        create_lock.assert_called_once_with(["py-foobar=1.0=py_0", "python=3.7=2"])

        create_lock.reset_mock()
        env.partially_update_lockfile(["python"])
        create_lock.assert_called_once_with(["py-foobar=1.0=py_0", "python"])

        create_lock.reset_mock()
        env.partially_update_lockfile(["py*"])
        create_lock.assert_called_once_with(["py-foobar", "python"])

        create_lock.reset_mock()
        env.partially_update_lockfile(["python", "*foobar"])
        create_lock.assert_called_once_with(["py-foobar", "python"])

        create_lock.reset_mock()
        env.partially_update_lockfile(["python<4"])
        create_lock.assert_called_once_with(
            ["py-foobar=1.0=py_0", "python[version='<4']"]
        )

    def test_check_installation(self):
        log_msg = "get the latest version from {}".format(
            self.dummy_server.server_url.rstrip("/")
        )
        with self.assertLogs() as logs:
            result = check_installation(ZwikSettings())
            self.assertTrue(result)
            self.assertFalse(
                any([x for x in logs.output if log_msg in x]),
                (log_msg, logs.output),
            )

            with mock.patch.dict(os.environ, {"ZWIK_BOOT_VERSION": "0"}):
                result = check_installation(ZwikSettings())
                self.assertTrue(result)
                self.assertTrue(
                    any([x for x in logs.output if log_msg in x]),
                    (log_msg, logs.output),
                )

        url = "{}install-data/zwik_client.py".format(self.dummy_server.server_url)
        with mock.patch.dict(os.environ, {"ZWIK_CLIENT_URL": url}):
            with self.assertLogs() as logs:
                result = check_installation(ZwikSettings())
                self.assertTrue(result)
                self.assertTrue(any(["is overridden" in x for x in logs.output]))

        url = "{}install-data/dummy.py".format(self.dummy_server.server_url)
        with mock.patch.dict(os.environ, {"ZWIK_CLIENT_URL": url}):
            with self.assertLogs() as logs:
                result = check_installation(ZwikSettings())
                self.assertFalse(result)
                self.assertTrue(
                    any(["corrupt or outdated" in x for x in logs.output]),
                    logs.output,
                )

        url = "{}install-data/non-existing.py".format(self.dummy_server.server_url)
        with mock.patch.dict(os.environ, {"ZWIK_CLIENT_URL": url}):
            with self.assertLogs() as logs:
                result = check_installation(ZwikSettings())
                self.assertFalse(result)
                log_msg = "not found on server"
                self.assertTrue(
                    any([log_msg in x for x in logs.output]),
                    logs.output,
                )

        url = "foobar://non-existing/test"
        with mock.patch.dict(os.environ, {"ZWIK_CLIENT_URL": url}):
            with self.assertLogs() as logs:
                result = check_installation(ZwikSettings())
                self.assertFalse(result)
                log_msg = "Check for zwik_client failed"
                self.assertTrue(
                    any([x for x in logs.output if log_msg in x]),
                    logs.output,
                )

    def test_wait(self):
        start = datetime.datetime.now()
        do_wait(2)
        end = datetime.datetime.now()
        self.assertGreater(end - start, datetime.timedelta(milliseconds=1700))

    def test_backup_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            prefix = os.path.join(tmpdir, "dummy_prefix")
            env = ZwikEnvironment(ZwikSettings())
            env.override_prefix = prefix

            self.assertIsNone(env.backup_env())

            os.mkdir(prefix)
            self.assertIsNotNone(env.backup_env())

            with self.assertRaises(RuntimeError):
                for i in range(200):
                    os.mkdir(prefix)
                    env.backup_env()

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_lock_file_env_var_available_from_lock(
        self, check_install, execute, create_env
    ):
        env = ZwikEnvironment.from_yaml(ZwikSettings(), self.yaml_file)
        self.create_env(env)

        main(
            [
                "--environment",
                self.yaml_file,
                "--unattended",
            ]
        )

        lock_files = glob.glob(os.path.join(self.working_dir, ".zwik", "*.lock"))
        self.assertEqual(os.environ["ZWIK_LOCK_FILE"], lock_files[0])

    @mock.patch("scripts.zwik_client.ZwikEnvironment.create_env")
    @mock.patch("scripts.zwik_client.ZwikEnvironment.execute")
    @mock.patch("scripts.zwik_client.check_installation")
    def test_lock_file_env_var_not_available_from_prefix(
        self, check_install, execute, create_env
    ):
        main(
            [
                "--prefix",
                "dummy",
                "--unattended",
            ]
        )

        self.assertNotIn("ZWIK_LOCK_FILE", os.environ)


class TestZwikMultiplePackages(TestCase):
    def test_prefer_default_channels_when_multiple_packages(self):
        spec = "my-package=0.0.0=py_0"
        default_channels = [
            "https://user:token@zwik.dev.bosch.com/packages/bios",
            "https://user:token@zwik.dev.bosch.com/packages/third-party",
            "https://user:token@zwik.dev.bosch.com/packages/conda-forge",
        ]

        class FakePackageRecord:
            def __init__(self, schannel):
                self.schannel = schannel

        result = (
            FakePackageRecord(schannel="bios"),
            FakePackageRecord(
                schannel="https://some.server.com/conda/custom-channel"
            ),
        )

        try:
            ZwikEnvironment._filter_package_from_default_channels(
                result=result, default_channels=default_channels, spec=spec
            )
        except AssertionError:
            self.fail("Should not have raised AssertionError.")
