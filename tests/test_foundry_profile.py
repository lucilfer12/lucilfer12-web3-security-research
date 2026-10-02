import tempfile
import time
import unittest
from pathlib import Path

from w3sec.verification import _copy_tree, _foundry_profile, _hashable_files, _reproducer_destination, suggested_command, workspace_hash

FOUNDRY_DEFAULT = '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\n'
FOUNDRY_CUSTOM = '[profile.default]\nsrc = "contracts"\ntest = "tests"\nout = "build-out"\ncache_path = "cache_forge"\n'


def _make_project(root: Path, foundry_toml: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "foundry.toml").write_text(foundry_toml, encoding="utf-8")
    (root / "contracts").mkdir(parents=True, exist_ok=True)
    (root / "contracts" / "A.sol").write_text("contract A {}\n", encoding="utf-8")


class FoundryProfileDefaults(unittest.TestCase):
    def test_no_foundry_toml_yields_foundrys_own_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual({"test": "test", "out": "out", "cache_path": "cache"}, _foundry_profile(Path(td)))

    def test_custom_values_are_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_project(root, FOUNDRY_CUSTOM)
            self.assertEqual(
                {"test": "tests", "out": "build-out", "cache_path": "cache_forge"}, _foundry_profile(root)
            )

    def test_malformed_toml_falls_back_to_defaults_without_raising(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "foundry.toml").write_text("this is not [ valid toml", encoding="utf-8")
            self.assertEqual({"test": "test", "out": "out", "cache_path": "cache"}, _foundry_profile(root))

    def test_non_string_value_falls_back_to_default_for_that_key(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "foundry.toml").write_text(
                "[profile.default]\ntest = 7\nout = \"build\"\n", encoding="utf-8"
            )
            profile = _foundry_profile(root)
            self.assertEqual("test", profile["test"])  # bad type -> default, not a crash
            self.assertEqual("build", profile["out"])


class ReproducerDestinationRespectsProjectConfig(unittest.TestCase):
    def test_default_foundry_project_uses_test(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_project(root, FOUNDRY_DEFAULT)
            dest = _reproducer_destination(root, Path("Repro.t.sol"))
            self.assertEqual(root / "test" / "Repro.t.sol", dest)

    def test_project_with_plural_tests_directory_is_respected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_project(root, FOUNDRY_CUSTOM)
            dest = _reproducer_destination(root, Path("Repro.t.sol"))
            self.assertEqual(root / "tests" / "Repro.t.sol", dest)
            self.assertNotEqual(root / "test" / "Repro.t.sol", dest)

    def test_suggested_command_uses_plural_tests_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_project(root, FOUNDRY_CUSTOM)
            repro = Path(td) / "Repro.t.sol"
            repro.write_text("pragma solidity ^0.8.20;\n", encoding="utf-8")
            from unittest.mock import patch
            with patch("w3sec.verification.shutil.which", return_value=r"C:\Tools\forge.exe"):
                self.assertEqual(
                    ("forge", "test", "--offline", "-vv", "--match-path", "tests/Repro.t.sol"),
                    suggested_command(root, repro),
                )


class CopyTreePreservesDependenciesAndSkipsCustomCache(unittest.TestCase):
    def test_node_modules_is_copied_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            src, dst = Path(td) / "src", Path(td) / "dst"
            (src / "node_modules" / "@openzeppelin" / "contracts").mkdir(parents=True)
            (src / "node_modules" / "@openzeppelin" / "contracts" / "Foo.sol").write_text("x", encoding="utf-8")
            (src / "A.sol").write_text("contract A {}\n", encoding="utf-8")
            _copy_tree(src, dst)
            self.assertTrue(
                (dst / "node_modules" / "@openzeppelin" / "contracts" / "Foo.sol").is_file(),
                "node_modules must survive the copy or npm-dependency Solidity projects cannot compile",
            )

    def test_custom_cache_dir_is_still_skipped_during_copy(self):
        with tempfile.TemporaryDirectory() as td:
            src, dst = Path(td) / "src", Path(td) / "dst"
            _make_project(src, FOUNDRY_CUSTOM)
            (src / "cache_forge").mkdir()
            (src / "cache_forge" / "solidity-files-cache.json").write_text("{}", encoding="utf-8")
            _copy_tree(src, dst)
            self.assertFalse((dst / "cache_forge").exists())

    def test_default_cache_dir_still_skipped_for_a_plain_foundry_project(self):
        with tempfile.TemporaryDirectory() as td:
            src, dst = Path(td) / "src", Path(td) / "dst"
            _make_project(src, FOUNDRY_DEFAULT)
            (src / "cache").mkdir()
            (src / "cache" / "x.json").write_text("{}", encoding="utf-8")
            _copy_tree(src, dst)
            self.assertFalse((dst / "cache").exists())


class WorkspaceHashIgnoresCustomCacheDir(unittest.TestCase):
    def test_hash_is_stable_across_a_customcache_only_change(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_project(root, FOUNDRY_CUSTOM)
            before = workspace_hash(root)
            (root / "cache_forge").mkdir()
            (root / "cache_forge" / "solidity-files-cache.json").write_text('{"a": 1}', encoding="utf-8")
            after_create = workspace_hash(root)
            self.assertEqual(before, after_create, "creating the project's own cache dir must not change the hash")
            time.sleep(0.01)
            (root / "cache_forge" / "solidity-files-cache.json").write_text('{"a": 2, "b": 3}', encoding="utf-8")
            after_mutate = workspace_hash(root)
            self.assertEqual(before, after_mutate, "mutating the project's own cache dir must not change the hash")

    def test_hash_still_changes_when_real_source_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_project(root, FOUNDRY_CUSTOM)
            before = workspace_hash(root)
            (root / "contracts" / "A.sol").write_text("contract A { uint x; }\n", encoding="utf-8")
            after = workspace_hash(root)
            self.assertNotEqual(before, after, "a real contract change must still be detected")

    def test_ignored_files_helper_excludes_custom_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _make_project(root, FOUNDRY_CUSTOM)
            (root / "cache_forge").mkdir()
            (root / "cache_forge" / "x.json").write_text("{}", encoding="utf-8")
            names = {p.name for p in _hashable_files(root)}
            self.assertIn("A.sol", names)
            self.assertIn("foundry.toml", names)
            self.assertNotIn("x.json", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
