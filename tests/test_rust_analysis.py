import unittest

from w3sec.rust_analysis import (
    RustIndex,
    analyse_gas,
    cast_report,
    function_regions,
    line_depths,
    size_bound_proofs,
)
from w3sec.intake import _mask_non_code
from w3sec.scanner import _rust_semantic_findings
from w3sec.contract_audit import _triage_score


class RustAnalysisTests(unittest.TestCase):
    def test_rust_lifetimes_are_not_masked_as_char_literals(self):
        source = "fn get_memory<'a>(x: &'a [u8]) -> &'a [u8] { x }"
        masked = _mask_non_code(source)
        self.assertIn("fn get_memory", masked)
        regions = function_regions(masked)
        self.assertEqual(1, len(regions))
        self.assertEqual("get_memory", regions[0]["name"])
        self.assertIn("&'a [u8]", regions[0]["params"])

    def test_function_regions_and_types(self):
        source = """
pub fn decode(input: &[u8]) -> Result<(), ()> {
    let len = input.len();
    let v = Vec::with_capacity(len);
    Ok(())
}
"""
        regions = function_regions(source)
        self.assertEqual(1, len(regions))
        self.assertEqual("decode", regions[0]["name"])
        self.assertIn("input: &[u8]", regions[0]["params"])
    def test_size_bound_constant_and_guarded_length_are_proven(self):
        lines = [
            "{",
            "if input.len() > MAX_CHUNK { return Err(()); }",
            "let v = Vec::with_capacity(MAX_CHUNK);",
            "let w = Vec::with_capacity(input.len());",
            "}",
        ]
        depths = line_depths(lines)
        self.assertEqual("constant-size",
                         size_bound_proofs(lines, depths, 2, lines[2], {"input"})[0]["kind"])
        self.assertEqual("length-upper-bound",
                         size_bound_proofs(lines, depths, 3, lines[3], {"input"})[0]["kind"])

    def test_size_bound_early_return_guard_is_proven(self):
        lines = [
            "{",
            "if len > MAX_CHUNK { return Err(()); }",
            "let v = Vec::with_capacity(len);",
            "}",
        ]
        proofs = size_bound_proofs(lines, line_depths(lines), 2, lines[2], {"len"})
        self.assertEqual("early-return-upper-bound", proofs[0]["kind"])
    def test_size_bound_without_guard_is_unproven(self):
        lines = [
            "{",
            "let v = Vec::with_capacity(len);",
            "}",
        ]
        self.assertEqual([], size_bound_proofs(lines, line_depths(lines), 1, lines[1], {"len"}))

    def test_separate_clamp_variable_does_not_prove_original_input_safe(self):
        lines = [
            "{",
            "let capped = input.min(MAX_CHUNK);",
            "let v = Vec::with_capacity(input);",
            "}",
        ]
        self.assertEqual([], size_bound_proofs(lines, line_depths(lines), 2, lines[2], {"input"}))

    def test_cast_report_distinguishes_lossless_and_narrowing(self):
        types = {"wide": "u64", "small": "u8"}
        proven, unproven = cast_report("let x = wide as u128;", types)
        self.assertEqual([], unproven)
        self.assertTrue(proven)
        _, unproven = cast_report("let x = wide as u32;", types)
        self.assertEqual(["wide as u32"], unproven)
    def test_gas_summary_requires_charge_on_all_paths(self):
        charging = "fn charge(ctx: &mut HostCtx) { pay_base(ctx); }"
        conditional = "fn conditional_charge(ctx: &mut HostCtx, ok: bool) { if ok { pay_base(ctx); } }"
        index = RustIndex()
        index.add_file("a.rs", function_regions(charging))
        index.add_file("b.rs", function_regions(conditional))
        index.finalize()
        self.assertIn("charge", index.charge_proof)
        self.assertNotIn("conditional_charge", index.charge_proof)

    def test_analyse_gas_finds_work_before_direct_charge(self):
        body = "{ read_memory(ptr); pay_base(ctx); }"
        result = analyse_gas(body, None)
        self.assertEqual("ordering", result["status"])
        self.assertIsNotNone(result["work"])

    def test_semantic_allocation_requires_real_bound(self):
        unsafe = """
pub fn decode(input: &[u8]) {
    let v = Vec::with_capacity(input.len());
}
"""
        safe = """
pub fn decode(input: &[u8]) {
    if input.len() > MAX_CHUNK {
        return;
    }
    let v = Vec::with_capacity(input.len());
}
"""
        unsafe_hits = _rust_semantic_findings("src/decode.rs", unsafe, "production")
        safe_hits = _rust_semantic_findings("src/decode.rs", safe, "production")
        self.assertTrue(any(x["signal"] == "input_sized_resource" for x in unsafe_hits))
        self.assertFalse(any(x["signal"] == "input_sized_resource" for x in safe_hits))

    def test_semantic_cast_only_flags_narrowing_tainted_cast(self):
        source = "pub fn validate_transaction(input: u64) { let a = input as u128; let b = input as u32; }"
        hits = _rust_semantic_findings("src/transaction.rs", source, "production")
        arithmetic = [x for x in hits if x["signal"] == "unchecked_input_arithmetic"]
        self.assertEqual(1, len(arithmetic))
        self.assertIn("input as u32", arithmetic[0]["matched_text"])

    def test_gas_analysis_tracks_effective_charge_through_helper(self):
        source = """
fn charge(ctx: &mut HostCtx) {
    pay_base(ctx);
}

pub fn process(ctx: &mut HostCtx, input: &[u8]) {
    read_memory(input.as_ptr());
    charge(ctx);
}
"""
        hits = _rust_semantic_findings(
            "runtime/near-vm-runner/src/logic/host.rs", source, "production"
        )
        gas_hits = [x for x in hits if x["signal"] == "gas_ordering"]
        self.assertEqual(1, len(gas_hits))
        self.assertIn("read_memory", gas_hits[0]["matched_text"])

    def test_triage_score_uses_security_signal_and_guard_evidence(self):
        base = {
            "confidence": "high",
            "reachability": "entry-point-direct",
            "scope": "production",
            "entry_point_reason": "boundary-function-or-boundary-path",
            "taint": ["input"],
            "evidence_type": "taint-and-control-flow-analysis",
        }
        consensus = _triage_score({**base, "signal": "consensus_invariant_gap"})
        panic = _triage_score({**base, "signal": "panic_on_input"})
        guarded = _triage_score({**base, "signal": "uncapped_deserialization", "guards": ["MAX_"]})
        unguarded = _triage_score({**base, "signal": "uncapped_deserialization", "guards": []})
        self.assertGreater(consensus, panic)
        self.assertGreater(unguarded, guarded)

if __name__ == "__main__":
    unittest.main()
