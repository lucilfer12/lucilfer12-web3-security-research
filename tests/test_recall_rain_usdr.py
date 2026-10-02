import hashlib
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

from w3sec.proof_verifier import run_proof_verification

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "corpus" / "recall" / "rain-usdr"
MANIFEST = FIXTURE / "manifest.yaml"
SOURCE_ZIP = FIXTURE / "rain-usdr-source.zip"
REPRODUCER = FIXTURE / "DifferentialShadowPath.t.sol"
PATCH = FIXTURE / "vault-engine-fix.patch"
VENDOR = FIXTURE / "vendor" / "@openzeppelin" / "contracts"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
def extract_source(destination: Path) -> Path:
    with zipfile.ZipFile(SOURCE_ZIP) as archive:
        archive.extractall(destination)
    roots = [p for p in destination.iterdir() if p.is_dir()]
    if len(roots) != 1:
        raise AssertionError("recall archive must contain one project root")
    return roots[0]


def install_vendor(project: Path) -> None:
    destination = project / "node_modules" / "@openzeppelin" / "contracts"
    shutil.copytree(VENDOR, destination, dirs_exist_ok=True)


def prepare_focused_target(project: Path) -> None:
    tests = project / "tests"
    for path in tests.iterdir():
        if path.is_file() and path.name != "AtlasBaseline.t.sol":
            path.unlink()
        elif path.is_dir() and path.name not in {"shared", "mocks"}:
            shutil.rmtree(path)
    shutil.copy2(
        ROOT / "corpus" / "recall" / "rain-usdr" / "AtlasBaseline.t.sol",
        tests / "AtlasBaseline.t.sol",
    )


def apply_fixture_fix(project: Path) -> None:
    target = project / "contracts" / "core" / "VaultEngine.sol"
    source = target.read_text(encoding="utf-8")
    old = """        // Solvency gate (HARD breach): risk-increasing changes (drawing debt or withdrawing collateral) against
        // VOLATILE collateral are blocked while the reserve invariant is breached. The invariant is RECOMPUTED here
        // rather than trusting the keeper-maintained flag: a stale flag (keeper down during a price collapse) would
        // otherwise let a draw slip through against reserves that can no longer cover the stressed loss. Repayment
        // (dart < 0) and collateral top-ups (dink > 0) always remain available because they reduce risk. Stable (PSM)
        // ilks are exempt: PSM inflows are reserve-increasing and must never be gated, while PSM redemptions are gated
        // inside the PSM itself.
        if (
            (dart > 0 || dink < 0) && solvencyEngine != address(0) && ISolvencyEngine(solvencyEngine).isVolatile(ilkId)
        ) {"""
    new = """        // Solvency gate (HARD breach): risk-increasing volatile changes and collateral withdrawals from
        // no-fee (PSM-backed) stable ilks are blocked while the reserve invariant is breached. PSM inflows remain
        // available because they increase the reserve; the stable-ilk withdrawal leg must nevertheless be gated here
        // because CollateralAdapter.exit exposes the same economic redemption path outside the PSM.
        if (
            solvencyEngine != address(0)
                && (
                    ((dart > 0 || dink < 0) && ISolvencyEngine(solvencyEngine).isVolatile(ilkId))
                    || (dink < 0 && noFee[ilkId])
                )
        ) {"""
    if old not in source:
        raise AssertionError("vulnerable VaultEngine block not found")
    target.write_text(source.replace(old, new, 1), encoding="utf-8")


class RainUsdrRecallFixture(unittest.TestCase):
    def test_fixture_is_pinned_and_complete(self):
        manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual("rain-usdr-shadow-redemption", manifest["fixture_id"])
        self.assertEqual("ATLAS", manifest["product_under_test"])
        self.assertEqual("33517D733A5C17AE3F25B13CCA6B02DB4943B7B1EF9D6C8FF9D78309D191D74D".lower(), sha256(SOURCE_ZIP))
        self.assertTrue(REPRODUCER.is_file())
        self.assertTrue(PATCH.is_file())
        self.assertTrue((VENDOR / "access" / "AccessControl.sol").is_file())
        self.assertEqual("tests", manifest["foundry_profile_test_dir"])

    def test_fixture_patch_declares_the_expected_gate(self):
        patch = PATCH.read_text(encoding="utf-8")
        self.assertIn("|| (dink < 0 && noFee[ilkId])", patch)
        self.assertIn("CollateralAdapter.exit", patch)

    @unittest.skipUnless(
        os.environ.get("ATLAS_RECALL_RAIN_USDR") == "1",
        "set ATLAS_RECALL_RAIN_USDR=1 to run the Foundry recall integration",
    )
    def test_proof_verifier_recalls_vulnerable_vs_fixed_behavior(self):
        forge = shutil.which("forge")
        if forge is None:
            self.skipTest("forge is not installed")

        with tempfile.TemporaryDirectory(prefix="atlas-rain-usdr-recall-") as td:
            root = Path(td)
            vulnerable = extract_source(root / "vulnerable")
            fixed = extract_source(root / "fixed")
            install_vendor(vulnerable)
            install_vendor(fixed)
            prepare_focused_target(vulnerable)
            prepare_focused_target(fixed)
            apply_fixture_fix(fixed)

            finding = {
                "id": "rain-usdr-shadow-redemption",
                "file": "contracts/core/VaultEngine.sol",
                "line": 456,
                "effect_witness": {
                    "vulnerable": {
                        "breach": True,
                        "shadow_path": True,
                        "user_asset_delta": 100000000,
                    },
                    "fixed": {
                        "breach": True,
                        "shadow_path": False,
                        "user_asset_delta": 0,
                    },
                },
            }
            result = run_proof_verification(
                vulnerable,
                fixed,
                finding,
                (
                    "forge",
                    "test",
                    "--offline",
                    "-vv",
                    "--match-path",
                    "tests/DifferentialShadowPath.t.sol",
                ),
                vulnerable_expected_exit=1,
                fixed_expected_exit=0,
                baseline_expected_exit=0,
                security_property=(
                    "a declared solvency breach must block the shadow stablecoin redemption path"
                ),
                reproducer=REPRODUCER,
                baseline_command=(
                    "forge",
                    "test",
                    "--offline",
                    "-vv",
                    "--match-path",
                    "tests/AtlasBaseline.t.sol",
                ),
                timeout_seconds=300,
                trusted_target_code=True,
            )
            self.assertTrue(result.confirmed, result.as_dict())
            self.assertEqual("confirmed", result.outcome)
            self.assertTrue(result.effect_comparison["vulnerable_valid"])
            self.assertTrue(result.effect_comparison["fixed_valid"])
            self.assertEqual(100000000, result.effect_comparison["vulnerable"]["user_asset_delta"])
            self.assertEqual(0, result.effect_comparison["fixed"]["user_asset_delta"])
            self.assertTrue(result.vulnerable_marker_present)
            self.assertTrue(result.fixed_marker_present)
            self.assertTrue(result.vulnerable_baseline_healthy)
            self.assertTrue(result.fixed_baseline_healthy)
            self.assertEqual("reproduced", result.vulnerable.outcome)
            self.assertEqual("reproduced", result.fixed.outcome)


if __name__ == "__main__":
    unittest.main()
