# Your one-click Development Environment solution

## About Zwik  <!-- omit in toc -->

Zwik is a powerful solution that allows you to create reproducible Development Environments to build, test, and deploy software. It ensures that you and your team are using the same tools and versions, promoting consistency and collaboration. Even your CI/CD pipeline will utilize the exact set of tools, streamlining your software development process. Zwik is compatible with Windows, Linux, and MacOS, making it accessible to developers on various platforms. With Zwik, you can effortlessly create environments by running a single shell script, eliminating the need for pre-installed dependencies.

## Table of Contents  <!-- omit in toc -->

- [Getting Started](#getting-started)
- [Check the installation and/or environment](#check-installation-env)
- [Developer notes](#building-and-testing)
- [License](#license)

## Getting Started <a name="getting-started"></a>

If a project is already using Zwik, it usually contains a file called `zwik_environment(.bat)` in the root of the project directory. If the files are not there yet, copy the files inside the `bootstrap` directory of this repository to the root of your project repository.

To use the environment, execute the `zwik_environment` script (e.g. by double-clicking on the (.bat) script in the Explorer or via `./zwik_environment` on the command line). This will create an environment with all packages specified in `zwik_environment.yaml` (or creates this file if it doesn't exist). If packages (or the client itself) are not already installed, everything will be installed automatically. After installing and activating, a command prompt will be shown, prefixed with `(zwik)`. Now you can execute applications inside the environment (e.g. Python).  

To see the available arguments for the script, run it with the `--help` argument in the console.

The `zwik_environment.yml` file can be changed to contain all the packages needed to build the project. After creating the environment a new `.lock` file will be created to lock the versions of the packages and their dependencies. If a valid lock-file already exists during the creation of the environment, the packages/versions in this file are used to create the environment.

Check the [list of available packages](https://conda-forge.org/packages/) which can be used in the yaml file.

Check the [PyCharm](docs/conda_env_in_pycharm.md) page to see how to use the Conda environment in PyCharm.

## Check the installation and/or environment <a name="check-installation-env"></a>

The Conda script allows you to verify your current Conda installation. Use the following steps for this:

1. Start the environment using the `zwik_environment` script
2. Type the following command and press enter  
   `./zwik_environment --check-installation --fix` (Remove the `./` at the front on Windows)
3. The output will tell you if your installation is ok, if it's not, the script will try to fix this.

If an environment seems corrupt, you can use the following steps to recreate the environment:

1. Start the environment using the `zwik_environment` script
2. Type the following command and press enter  
   `./zwik_environment --recreate`
3. The current environment will be deleted and automatically recreated
4. After recreating the environment, the following message will be shown:  
   `Environment already activated!`
   This message can be ignored!

### Developer notes <a name="building-and-testing"></a>

When testing the scripts locally, read this:

- Use the `test_environment.bat/sh` script to run the client script using
  the local versions of the scripts. This will use the following files:
  - The bootstrap script `bootstrap/zwik_environment(.bat)`
  - The install script `scripts/zwik-install.bat/sh` if conda is
    not yet installed
  - The client script `scripts/zwik_client.py`
- To debug the client script, run the `test_client.py` script using e.g.
  PyCharm. This will of course not run the bootstrap or install scripts.
- The shell scripts in the `bootstrap/` folder have a checksum for integrity
  checks. Run `python tasks.py update-hashes` to update those checksums before
  committing. So called "single package" scripts can also be placed in this
  folder to get updated by this command.
  - __WARNING__: don't give the same name to the single-package.bat as the argument passed in --exec, it will cause a recursive call on itself.
- You can use the recommended Mambaforge installation, or any other already
  installed version of Anaconda, Miniconda or Mamba. Just make
  sure that the `ZWIK_ROOT` environment variable points to the root dir of it.

### License <a name="license"></a>

This project is licensed under the BSD-3-Clause License - see the [LICENSE](LICENSE) file for details.
