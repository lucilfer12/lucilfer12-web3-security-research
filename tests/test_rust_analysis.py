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
from w3sec.contract_audit import _triage_lane, _triage_score


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

    def test_semantic_finding_line_maps_to_real_source_after_multiline_signature(self):
        source = """
pub fn decode(
    input: u64,
) {
    let value = input as u8;
    consume(value);
}
"""
        hits = _rust_semantic_findings("src/decode.rs", source, "production")
        cast_hits = [x for x in hits if x["signal"] == "unchecked_input_arithmetic"]
        self.assertEqual(1, len(cast_hits))
        self.assertEqual(5, cast_hits[0]["line"])
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
        both = """fn both(ctx: &mut HostCtx, ok: bool) {
    if ok {
        pay_base(ctx);
    } else {
        use_gas(ctx);
    }
}"""
        one_branch = """fn one_branch(ctx: &mut HostCtx, ok: bool) {
    if ok {
        pay_base(ctx);
    } else {
        read_memory(ptr);
    }
}"""
        index = RustIndex()
        index.add_file("a.rs", function_regions(charging))
        index.add_file("b.rs", function_regions(conditional))
        index.add_file("c.rs", function_regions(both))
        index.add_file("d.rs", function_regions(one_branch))
        index.finalize()
        self.assertIn("charge", index.charge_proof)
        self.assertNotIn("conditional_charge", index.charge_proof)
        self.assertIn("both", index.charge_proof)
        self.assertNotIn("one_branch", index.charge_proof)

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

    def test_register_get_is_recognized_as_gas_charged_work(self):
        source = """
fn read_memory(gas_counter: &mut GasCounter, memory: &[u8]) -> Result<&[u8]> {
    gas_counter.pay_base(read_memory_base)?;
    Ok(memory)
}

fn get_memory_or_register(
    gas_counter: &mut GasCounter,
    memory: &[u8],
    registers: &Registers,
    ptr: u64,
    len: u64,
) -> Result<&[u8]> {
    if len == u64::MAX {
        registers.get(gas_counter, ptr)
    } else {
        read_memory(gas_counter, memory)
    }
}
"""
        index = RustIndex()
        index.add_file("host.rs", function_regions(_mask_non_code(source)))
        index.finalize()
        self.assertIn("get_memory_or_register", index.charge_proof)
        self.assertIn("registers.get", index.charge_proof["get_memory_or_register"])
        self.assertIn("read_memory", index.charge_proof["get_memory_or_register"])
        self.assertIn("pay_base", index.charge_proof["get_memory_or_register"])

    def test_nearcore_memory_helper_is_not_reported_as_gas_ordering(self):
        source = """
fn read_memory(
    gas_counter: &mut GasCounter,
    memory: &[u8],
    ptr: u64,
    len: u64,
) -> Result<&[u8]> {
    gas_counter.pay_base(read_memory_base)?;
    gas_counter.pay_per(read_memory_byte, len)?;
    read_memory_for_free(memory, ptr, len)
}

fn get_memory_or_register(
    gas_counter: &mut GasCounter,
    memory: &[u8],
    registers: &Registers,
    ptr: u64,
    len: u64,
) -> Result<&[u8]> {
    if len == u64::MAX {
        registers.get(gas_counter, ptr)
    } else {
        read_memory(gas_counter, memory, ptr, len)
    }
}

pub fn read_and_parse_account_id(
    gas_counter: &mut GasCounter,
    memory: &[u8],
    registers: &Registers,
    ptr: u64,
    len: u64,
) -> Result<()> {
    let buf = get_memory_or_register(gas_counter, memory, registers, ptr, len)?;
    gas_counter.pay_base(utf8_decoding_base)?;
    Ok(())
}
"""
        hits = _rust_semantic_findings(
            "runtime/near-vm-runner/src/logic/host.rs", source, "production"
        )
        self.assertFalse(any(x["signal"] == "gas_ordering" for x in hits))

    def test_nearcore_gas_wrapper_is_not_reported_as_ordering_bug(self):
        source = """
fn read_memory(gas_counter: &mut GasCounter, memory: &[u8], ptr: u64, len: u64) -> Result<&[u8]> {
    gas_counter.pay_base(read_memory_base)?;
    gas_counter.pay_per(read_memory_byte, len)?;
    read_memory_for_free(memory, ptr, len)
}

fn get_memory_or_register<'a>(
    gas_counter: &mut GasCounter,
    memory: &'a [u8],
    registers: &'a Registers,
    ptr: u64,
    len: u64,
) -> Result<&'a [u8]> {
    if len == u64::MAX {
        registers.get(gas_counter, ptr)
    } else {
        read_memory(gas_counter, memory, ptr, len)
    }
}

fn read_and_parse_account_id(
    gas_counter: &mut GasCounter,
    memory: &[u8],
    registers: &Registers,
    ptr: u64,
    len: u64,
) -> Result<AccountId> {
    let buf = get_memory_or_register(gas_counter, memory, registers, ptr, len)?;
    gas_counter.pay_base(utf8_decoding_base)?;
    String::from_utf8(buf.into()).map_err(|_| HostError::BadUTF8)
}
"""
        hits = _rust_semantic_findings(
            "runtime/near-vm-runner/src/logic/host.rs", source, "production"
        )
        self.assertFalse(any(x["signal"] == "gas_ordering" for x in hits))

    def test_semantic_flags_input_division_and_shift(self):
        source = """
#[no_mangle]
pub fn calc(input: u64, len: u64) {
    let x = input / len;
    let y = input << input;
}
"""
        hits = _rust_semantic_findings("src/calc.rs", source, "production")
        division = [
            x for x in hits if x["signal"] == "unchecked_input_division"
        ]
        self.assertEqual(2, len(division))
        self.assertTrue(any("input / len" in x["matched_text"] for x in division))
        self.assertTrue(any("input << input" in x["matched_text"] for x in division))

    def test_semantic_suppresses_value_independent_unwraps(self):
        source = """
pub fn unwraps(input: &[u8]) {
    let _a = Some(input).unwrap();
    let _b = Ok(input).unwrap();
    let _c = std::sync::Mutex::new(input).lock().unwrap();
}
"""
        hits = _rust_semantic_findings("src/unwraps.rs", source, "production")
        self.assertFalse(any(x["signal"] == "panic_on_input" for x in hits))

    def test_semantic_retains_input_sensitive_unwraps(self):
        source = """
#[no_mangle]
pub fn parse(input: &str) {
    let _a: u64 = input.parse().unwrap();
    let _b = input.len().checked_add(1).unwrap();
}
"""
        hits = _rust_semantic_findings("src/parse.rs", source, "production")
        panic_hits = [x for x in hits if x["signal"] == "panic_on_input"]
        self.assertEqual(2, len(panic_hits))

    def test_semantic_flags_tainted_index_expression(self):
        source = """
pub fn read(input: &[u8], idx: usize) -> u8 {
    input[idx]
}
"""
        hits = _rust_semantic_findings("src/read.rs", source, "production")
        panic_hits = [x for x in hits if x["signal"] == "panic_on_input"]
        self.assertEqual(1, len(panic_hits))
        self.assertIn("input[idx]", panic_hits[0]["matched_text"])

    def test_semantic_suppresses_index_with_dominating_bound_check(self):
        source = """
pub fn read(input: &[u8], idx: usize) -> u8 {
    if idx >= input.len() {
        return 0;
    }
    input[idx]
}
"""
        hits = _rust_semantic_findings("src/read.rs", source, "production")
        self.assertFalse(any(x["signal"] == "panic_on_input" for x in hits))

    def test_triage_lanes_make_medium_candidates_actionable(self):
        self.assertEqual("VERIFY_FIRST", _triage_lane(90))
        self.assertEqual("DEEP_REVIEW", _triage_lane(67))
        self.assertEqual("CONTEXT", _triage_lane(33))

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
