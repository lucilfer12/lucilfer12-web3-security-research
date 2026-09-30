"""ATLAS Rust analysis layer: function regions, interprocedural gas summaries,
dominating-guard proofs and type-aware cast checks.

Design rule: a candidate leaves the primary findings ONLY with a machine-checkable proof
attached, and every removal is reported in `dismissed_with_evidence`. Nothing is silently
dropped, so precision improves without hiding recall.
"""
from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from typing import Any

# ---------------------------------------------------------------------------
# Function regions (generics/lifetimes supported, body-less declarations skipped)
# ---------------------------------------------------------------------------
_FN_HEAD = re.compile(r"\bfn\s+(?P<name>[A-Za-z_]\w*)")
_BRACES = {"{": re.compile(r"[{}]"), "(": re.compile(r"[()]")}
_KEYWORDS = frozenset({"if", "while", "match", "for", "loop", "fn", "return", "in", "as", "let",
                       "else", "unsafe", "move", "where", "impl", "dyn"})


def match_close(text: str, pos: int, open_ch: str = "{") -> int:
    depth = 0
    for m in _BRACES[open_ch].finditer(text, pos):
        depth += 1 if m.group() == open_ch else -1
        if depth == 0:
            return m.start()
    return -1


def _skip_generics(text: str, pos: int) -> int:
    n = len(text)
    while pos < n and text[pos].isspace():
        pos += 1
    if pos < n and text[pos] == "<":
        depth = 0
        for i in range(pos, min(n, pos + 2000)):
            c = text[i]
            if c == "<":
                depth += 1
            elif c == ">" and text[i - 1] != "-":
                depth -= 1
                if depth == 0:
                    pos = i + 1
                    break
        else:
            return -1
    while pos < n and text[pos].isspace():
        pos += 1
    return pos


def _find_body_start(text: str, pos: int) -> int:
    """First `{` at bracket depth 0; a `;` at depth 0 first means a body-less declaration."""
    depth = 0
    for i in range(pos, min(len(text), pos + 4000)):
        c = text[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth <= 0 and c == ";":
            return -1
        elif depth <= 0 and c == "{":
            return i
    return -1


def function_regions(masked: str) -> list[dict[str, Any]]:
    newlines = [m.start() for m in re.finditer(r"\n", masked)]
    regions: list[dict[str, Any]] = []
    for m in _FN_HEAD.finditer(masked):
        pos = _skip_generics(masked, m.end())
        if pos < 0 or pos >= len(masked) or masked[pos] != "(":
            continue
        close = match_close(masked, pos, "(")
        if close < 0:
            continue
        body_start = _find_body_start(masked, close + 1)
        if body_start < 0:
            continue
        end = match_close(masked, body_start, "{")
        end = len(masked) if end < 0 else end + 1
        head = masked[max(0, m.start() - 48):m.start()]
        regions.append({
            "name": m.group("name"),
            "params": masked[pos + 1:close],
            "line": bisect_left(newlines, m.start()) + 1,
            "start": m.start(),
            "body_start": body_start,
            "end": end,
            "body": masked[body_start:end],
            "is_pub": bool(re.search(r"\bpub\b[^;{}]*$", head)),
        })
    return regions


class DepthMap:
    """Brace depth at any offset of a masked body (top-level statements have depth 1)."""

    def __init__(self, body: str):
        self.pos: list[int] = []
        self.after: list[int] = []
        depth = 0
        for m in re.finditer(r"[{}]", body):
            depth += 1 if m.group() == "{" else -1
            self.pos.append(m.start())
            self.after.append(depth)

    def depth(self, p: int) -> int:
        i = bisect_right(self.pos, p) - 1
        return self.after[i] if i >= 0 else 0


_CALL_HEAD = re.compile(r"(?P<dot>\.\s*)?(?P<name>[A-Za-z_]\w*)\s*(?:::<[^>()]*>)?\s*\(")


def iter_calls(body: str):
    for m in _CALL_HEAD.finditer(body):
        name = m.group("name")
        if name in _KEYWORDS:
            continue
        open_pos = m.end() - 1
        close = match_close(body, open_pos, "(")
        if close < 0:
            continue
        yield name, body[open_pos + 1:close], m.start("name"), bool(m.group("dot"))


# ---------------------------------------------------------------------------
# Interprocedural gas-charge summaries
# ---------------------------------------------------------------------------
_CHARGE_DIRECT = re.compile(
    r"\b(?:pay_base|pay_per|pay_unless_ext|pay_gas_for_new_receipt|pay_action_base|"
    r"pay_action_per_byte|pay_action_accumulated|burn_gas|use_gas)\s*\("
)
_GAS_ARG = re.compile(r"\bgas_counter\b|\bGasCounter\b|\bctx\b|\bresult_state\b")
_TAKES_GAS = re.compile(r"\bGasCounter\b|\bgas_counter\b|\bHostCtx\b|\bctx\b|\bResultState\b|\bresult_state\b")
_WORK = re.compile(
    r"\b(?:read_memory|write_memory|get_memory_or_register|Vec::(?!new\b|default\b)\w+|to_vec|"
    r"deserialize|serialize|hash|crypto|copy_from_slice|extend_from_slice)\b"
)
_LEGACY_WORK = re.compile(
    r"\b(?:read_memory|write_memory|get_memory_or_register|Vec::|to_vec|"
    r"deserialize|serialize|hash|crypto|copy_from_slice|extend_from_slice)\b"
)


class RustIndex:
    """Cross-file function index with a fixpoint 'this function always charges gas' summary."""

    def __init__(self) -> None:
        self.by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.charge_proof: dict[str, list[str]] = {}

    def add_file(self, relative: str, regions: list[dict[str, Any]]) -> None:
        for r in regions:
            self.by_name[r["name"]].append(
                {"file": relative, "name": r["name"], "params": r["params"], "body": r["body"], "line": r["line"]}
            )

    def finalize(self) -> None:
        self.charge_proof = {}
        cands = {n: [f for f in fns if _TAKES_GAS.search(f["params"])] for n, fns in self.by_name.items()}
        cands = {n: c for n, c in cands.items() if c}
        for _ in range(12):
            changed = False
            for name, fns in cands.items():
                if name in self.charge_proof:
                    continue
                proofs = [self._proof(f) for f in fns]
                if all(p is not None for p in proofs):
                    self.charge_proof[name] = min(proofs, key=len)
                    changed = True
            if not changed:
                break

    def _proof(self, fn: dict[str, Any]) -> list[str] | None:
        body = fn["body"]
        inner = body[1:-1] if body.startswith("{") and body.endswith("}") else body
        return self.block_chain(inner, fn["name"])

    def block_chain(self, text: str, self_name: str = "") -> list[str] | None:
        """Proof that every path through `text` charges gas, or None."""
        dm = DepthMap(text)
        for m in _CHARGE_DIRECT.finditer(text):
            if dm.depth(m.start()) == 0:
                return [m.group(0).rstrip("( \t")]
        for name, args, pos, _ in iter_calls(text):
            if dm.depth(pos) == 0 and name != self_name and name in self.charge_proof and _GAS_ARG.search(args):
                return [name] + self.charge_proof[name]
        for m in re.finditer(r"\bif\b", text):
            if dm.depth(m.start()) == 0:
                chain = self._if_chain(text, m.start(), self_name)
                if chain:
                    return chain
        return None

    def _if_chain(self, text: str, pos: int, self_name: str) -> list[str] | None:
        chains: list[list[str]] = []
        cur = pos
        while True:
            ob = _find_block_open(text, cur)
            if ob < 0:
                return None
            cb = match_close(text, ob, "{")
            if cb < 0:
                return None
            chain = self.block_chain(text[ob + 1:cb], self_name)
            if chain is None:
                return None
            chains.append(chain)
            j = cb + 1
            while j < len(text) and text[j].isspace():
                j += 1
            if not text.startswith("else", j):
                return None
            j += 4
            while j < len(text) and text[j].isspace():
                j += 1
            if text.startswith("if", j):
                cur = j
                continue
            if j < len(text) and text[j] == "{":
                cb2 = match_close(text, j, "{")
                if cb2 < 0:
                    return None
                last = self.block_chain(text[j + 1:cb2], self_name)
                if last is None:
                    return None
                chains.append(last)
                return min(chains, key=len)
            return None


def _find_block_open(text: str, pos: int) -> int:
    depth = 0
    for i in range(pos, min(len(text), pos + 1500)):
        c = text[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "{" and depth <= 0:
            return i
    return -1


def analyse_gas(body: str, index: "RustIndex | None") -> dict[str, Any]:
    dm = DepthMap(body)
    events: list[tuple[int, int, str, list[str]]] = []
    callee_pos: set[int] = set()
    for m in _CHARGE_DIRECT.finditer(body):
        events.append((m.start(), dm.depth(m.start()), "direct", [m.group(0).rstrip("( \t")]))
    if index is not None:
        for name, args, pos, _ in iter_calls(body):
            chain = index.charge_proof.get(name)
            if chain and _GAS_ARG.search(args):
                events.append((pos, dm.depth(pos), "callee", [name] + chain))
                callee_pos.add(pos)
    events.sort(key=lambda e: e[0])
    top = [e for e in events if e[1] == 1]
    works = [m for m in _WORK.finditer(body) if m.start() not in callee_pos]
    legacy_charge = re.search(r"\bpay_(?:base|per)\s*\(", body)
    legacy_work = _LEGACY_WORK.search(body[:legacy_charge.start()]) if legacy_charge else None
    work = None
    first = None
    if top:
        first = top[0]
        work = next((w for w in works if w.start() < first[0]), None)
        status = "ordering" if work else "ok"
    else:
        all_paths = index.block_chain(body[1:-1]) if index is not None and body.startswith("{") else None
        if all_paths:
            status = "ok"
            first = (0, 1, "all-paths", all_paths)
        elif events:
            first = events[0]
            work = next((w for w in works if w.start() < first[0]), None)
            status = "conditional-charge-only" if work else "ok"
        else:
            work = works[0] if works else None
            status = "no-charge"
    return {"status": status, "work": work, "first": first, "events": events,
            "legacy_flag": bool(legacy_work), "legacy_work": legacy_work}


# ---------------------------------------------------------------------------
# Dominating guard proofs for input-sized resources
# ---------------------------------------------------------------------------
def line_depths(lines: list[str]) -> list[int]:
    depths, d = [], 0
    for ln in lines:
        depths.append(d)
        d += ln.count("{") - ln.count("}")
    return depths


def _split_args(text: str) -> list[str]:
    out, depth, cur = [], 0, []
    for c in text:
        if c in "([{<":
            depth += 1
        elif c in ")]}>":
            depth -= 1
        if c == "," and depth <= 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return out


_CONST_EXPR = re.compile(r"(?:[A-Z][A-Z0-9_]*|\d[\d_]*)(?:\s*[*+]\s*(?:[A-Z][A-Z0-9_]*|\d[\d_]*))*")
_LEN_EXPR = re.compile(r"&?[\w.\[\]()]*?\.len\(\)(?:\s*\+\s*\d+)?")
_EXIT = re.compile(r"\breturn\b|\bErr\s*\(|\bbail!|\bensure!|\bcontinue\b|\bpanic!|\bbreak\b")


def upper_bound_proofs(lines: list[str], depths: list[int], idx: int, var: str) -> list[dict[str, Any]]:
    """A guard that caps `var` from above and exits early, dominating line `idx`."""
    v = re.escape(var)
    upper = re.compile(rf"\b{v}\b\s*(?:>=|>)(?!=)|(?:<=|<)\s*\b{v}\b")
    cap_assert = re.compile(rf"\b{v}\b\s*(?:<=|<)|(?:>=|>)\s*\b{v}\b")
    for j in range(idx - 1, -1, -1):
        line = lines[j]
        if not re.search(rf"\b{v}\b", line):
            continue
        if min(depths[j:idx + 1]) < depths[j]:
            continue
        kind = None
        if re.search(r"\bif\b", line) and upper.search(line):
            text = "\n".join(lines[j:j + 8])
            ob = text.find("{")
            cb = match_close(text, ob, "{") if ob >= 0 else -1
            if cb > ob >= 0 and _EXIT.search(text[ob:cb]):
                kind = "early-return-upper-bound"
        elif re.search(r"\b(?:ensure|assert|require)!\s*\(", line) and cap_assert.search(line):
            kind = "assert-upper-bound"
        elif re.search(
            rf"(?:\blet\s+(?:mut\s+)?{v}\b\s*=\s*)?\b{v}\b\s*\.\s*(?:min|clamp)\s*\(",
            line,
        ) and re.search(rf"\b{v}\b\s*\.\s*(?:min|clamp)\s*\(", line):
            # Accept only self-clamping/reassignment. A separate variable named capped
            # does not bound later uses of the original variable.
            if re.search(rf"(?:\blet\s+(?:mut\s+)?{v}\b|\b{v}\b)\s*=\s*\b{v}\b", line):
                kind = "clamped"
        if kind:
            return [{"kind": kind, "line": j + 1, "text": line.strip()[:140], "variable": var}]
    return []


def length_upper_bound_proofs(
    lines: list[str], depths: list[int], idx: int, expr: str
) -> list[dict[str, Any]]:
    m = re.fullmatch(r"([A-Za-z_]\w*(?:\.\w+)*)\.len\(\)", expr.strip())
    if not m:
        return []
    base = m.group(1)
    target = re.escape(base)
    bound = re.compile(
        rf"\b{target}\.len\(\)\s*(?:>=|>)|(?:<=|<)\s*\b{target}\.len\(\)"
    )
    for j in range(idx - 1, -1, -1):
        line = lines[j]
        if depths[j] > depths[idx]:
            continue
        if not bound.search(line):
            continue
        if not re.search(r"\bif\b|\b(?:ensure|assert|require)!\s*\(", line):
            continue
        text = "\n".join(lines[j:min(len(lines), j + 8)])
        ob = text.find("{")
        cb = match_close(text, ob, "{") if ob >= 0 else -1
        if cb > ob >= 0 and _EXIT.search(text[ob:cb]):
            return [{
                "kind": "length-upper-bound",
                "line": j + 1,
                "text": line.strip()[:140],
                "variable": f"{base}.len()",
            }]
    return []


def size_bound_proofs(lines: list[str], depths: list[int], idx: int, line: str, taint: set[str]) -> list[dict[str, Any]]:
    m = re.search(r"\b(?:with_capacity|reserve_exact|reserve|resize)\s*\(", line)
    if not m:
        return []
    open_pos = m.end() - 1
    close = match_close(line, open_pos, "(")
    if close < 0:
        return []
    arg = _split_args(line[open_pos + 1:close])[0].strip()
    if not arg:
        return []
    if _CONST_EXPR.fullmatch(arg):
        return [{"kind": "constant-size", "text": arg}]
    if _LEN_EXPR.fullmatch(arg):
        return length_upper_bound_proofs(lines, depths, idx, arg)
    names = [t for t in sorted(taint) if re.search(rf"\b{re.escape(t)}\b", arg)]
    if not names:
        return []
    proofs: list[dict[str, Any]] = []
    for v in names:
        p = upper_bound_proofs(lines, depths, idx, v)
        if not p:
            return []
        proofs.extend(p)
    return proofs


# ---------------------------------------------------------------------------
# Type-aware casts (64-bit targets, as nearcore requires)
# ---------------------------------------------------------------------------
_INT = r"(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|bool)"
_SIGNED_WIDE = {"i16", "i32", "i64", "i128", "isize"}
_WIDEN: dict[str, set[str]] = {
    "bool": {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize"},
    "u8": {"u16", "u32", "u64", "u128", "usize", "i16", "i32", "i64", "i128", "isize"},
    "u16": {"u32", "u64", "u128", "usize", "i32", "i64", "i128", "isize"},
    "u32": {"u64", "u128", "usize", "i64", "i128"},
    "u64": {"u128", "i128"},
    "usize": {"u64", "u128"},
    "i8": {"i16", "i32", "i64", "i128", "isize"},
    "i16": {"i32", "i64", "i128", "isize"},
    "i32": {"i64", "i128", "isize"},
    "i64": {"i128"},
}
_CAST = re.compile(rf"((?:[A-Za-z_]\w*(?:\.\w+)*(?:\(\))?)|\d[\d_]*)\s+as\s+({_INT})\b")


def local_types(params: str, body: str) -> dict[str, str]:
    types: dict[str, str] = {}
    for m in re.finditer(rf"\b([a-z_]\w*)\s*:\s*(?:mut\s+)?({_INT})\b", params):
        types[m.group(1)] = m.group(2)
    for m in re.finditer(rf"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*:\s*({_INT})\b", body):
        types[m.group(1)] = m.group(2)
    for m in re.finditer(r"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*=\s*[^;=]*\.len\(\)\s*;", body):
        types.setdefault(m.group(1), "usize")
    return types


def cast_report(line: str, types: dict[str, str]) -> tuple[list[str], list[str]]:
    proven, unproven = [], []
    for m in _CAST.finditer(line):
        expr, target = m.group(1), m.group(2)
        if re.fullmatch(r"\d[\d_]*", expr):
            src = "literal"
        elif expr.endswith(".len()"):
            src = "usize"
        else:
            src = types.get(expr)
        if src == "literal" or src == target or (src and target in _WIDEN.get(src, ())):
            proven.append(f"{expr} as {target}: {src} -> {target} is lossless on 64-bit targets")
        else:
            unproven.append(f"{expr} as {target}")
    return proven, unproven


def has_binary_arithmetic(line: str) -> bool:
    stripped = _CAST.sub(lambda m: m.group(1), line)
    return bool(re.search(r"\b[A-Za-z_]\w*\b\s*(?:\+|-|\*)\s*\b[A-Za-z_]\w*\b", stripped))
