#!/usr/bin/env python
import glob
import os

import click

cli = click.Group()


@cli.command()
def unittest():
    """
    Run unit tests with coverage
    """
    import unittest

    import coverage

    cov = coverage.Coverage(
        data_suffix=os.name,
        branch=True,
        omit=["./tests/*", "./**/__init__.py"],
    )
    cov.config.paths["source"] = [
        "scripts",
        "**/scripts",
        "**\\scripts",
    ]
    cov.start()
    tests = unittest.defaultTestLoader.discover(
        start_dir="tests",
        pattern="test_*.py",
    )
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    cov.stop()
    if result.wasSuccessful():
        cov.combine()
        cov.save()
        cov.xml_report(outfile="coverage_report.xml")
        print("\nCoverage Report")
        cov.report()
        return 0
    else:
        exit(1)


@cli.command()
@click.pass_context
def update_hashes(ctx):
    """
    Updates hashes in bootstrap scripts
    """
    from scripts.zwik_client import ZwikEnvironment

    boot_script_dir = os.path.join(
        os.path.dirname(__file__),
        "bootstrap",
    )

    for path in glob.glob(os.path.join(boot_script_dir, "*")):
        if os.path.isdir(path):
            continue
        actual_hash, expected_hash = ZwikEnvironment.get_file_integrity_hashes(path)
        print("Checking integrity of file: {}".format(os.path.basename(path)))
        if actual_hash != expected_hash:
            with open(path) as fp:
                content = fp.read()
            content = content.replace(expected_hash, actual_hash)
            with open(path, "w") as fp:
                fp.write(content)
            print("Updated hash: {}".format(actual_hash))
        else:
            print("Valid hash exists already.")


if __name__ == "__main__":
    cli()
