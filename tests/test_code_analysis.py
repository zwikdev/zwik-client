import sys
from unittest import TestCase


class CodeAnalysisTest(TestCase):
    @classmethod
    def setUpClass(cls):
        from pathlib import Path

        base_dir = Path(__file__).absolute().parent.parent
        sources = set()
        for p in ["scripts"] + ["tests"]:
            sources.add(base_dir / p)
        sources.update(base_dir.glob("*.py"))
        cls.base_dir = base_dir
        cls.sources = sources

    def get_python_sources(self):
        sources = set()
        for path in self.sources:
            if path.is_dir():
                sources.update(path.rglob("*.py"))
            else:
                sources.add(path)
        return sources

    def test_black(self):
        import black
        from black.concurrency import reformat_many

        mode = black.Mode()
        report = black.Report(
            check=True,
        )

        reformat_many(
            sources=self.get_python_sources(),
            fast=False,
            write_back=black.WriteBack.DIFF,
            mode=mode,
            report=report,
            workers=None,
        )

        self.assertFalse(report.return_code, report)

    def test_isort(self):
        import isort

        unsorted_paths = []
        for path in self.get_python_sources():
            imports_sorted = isort.check_file(
                path,
                src_paths=[self.base_dir],
                show_diff=True,
                profile="black",
            )
            if not imports_sorted:
                unsorted_paths.append("{}:0".format(path))
        if unsorted_paths:
            raise AssertionError("Check imports:\n" + "\n".join(unsorted_paths))

    def test_flake8(self):
        from flake8.main import cli

        args = [
            "--max-complexity", "23",
            "--max-line-length", "88",
            "--extend-ignore", "E203",
        ]  # fmt: skip
        for path in self.sources:
            with self.subTest(path):
                with self.assertRaises(SystemExit) as cm:
                    sys.exit(cli.main(args + [str(path)]))
                self.assertFalse(cm.exception.code)
