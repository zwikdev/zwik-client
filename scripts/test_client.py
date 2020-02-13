import os

if __name__ == "__main__":
    boot_script = os.path.join(
        os.path.dirname(__file__), "..", "bootstrap", "zwik_environment"
    )
    assert os.path.exists(boot_script)
    os.environ["ZWIK_BOOT_SCRIPT"] = boot_script
    os.environ["SKIP_INSTALLATION_CHECK"] = "1"
    os.environ.pop("CONDA_PREFIX", "")
    os.environ.pop("CONDA_SHLVL", "")

    from scripts import zwik_client

    zwik_client.main(["--recreate", "--no-wait", "-v", "--exec", "python", "--version"])
