from __future__ import annotations

import json
import os
import sys
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from .audit import audit_repo
from .chronicle import build_chronicle, write_chronicle
from .coverage import build_coverage
from .federation import build_federation_snapshot, write_candidate_snapshot, write_federation_snapshot
from .graph import ResearchGraph
from .history import build_domain_evolution, build_temporal_timeline, write_domain_evolution, write_temporal_history
from .inventory import build_inventory
from .ledger import verify_chain
from .promotion import build_promotion_engine, write_promotion_report
from .query import CaseQuery, query_cases, summarize_cases
from .research_intelligence import build_research_metrics, write_longitudinal_report
from .validator import validate_repo
from .versions import build_version_diff_report, write_version_diff_report

APP_NAME = "W3Sec Research OS"
APP_VERSION = "1.1.0"

def settings_path() -> Path:
    base = Path(os.environ.get("APPDATA", Path.home()))
    return base / "W3Sec" / "settings.json"


def discover_repo() -> Path | None:
    env_repo = os.environ.get("W3SEC_REPO")
    places = [Path(env_repo)] if env_repo else []
    places += [Path.cwd(), Path(__file__).resolve().parents[2]]
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        places += [exe.parent, exe.parent.parent]
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
        places.insert(0, Path(data.get("repo", "")))
    except Exception:
        pass
    for p in places:
        if p.is_dir() and (p / "corpus").is_dir() and (p / "src").is_dir():
            return p.resolve()
    return None


def save_repo(p: Path) -> None:
    q = settings_path()
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text(json.dumps({"repo": str(p)}, indent=2), encoding="utf-8")


def dump(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)

class W3SecApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1400x900")
        self.minsize(1100, 700)
        self.repo = discover_repo()
        self.busy = False
        self._style()
        self._shell()
        self._tabs()
        self._set_repo(self.repo)
        self.after(150, self.refresh)

    def _style(self) -> None:
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Title.TLabel", font=("Segoe UI", 22, "bold"))
        s.configure("Card.TFrame", padding=14, relief="solid", borderwidth=1)
        s.configure("Value.TLabel", font=("Segoe UI", 19, "bold"))
        s.configure("Treeview", rowheight=27)

    def _shell(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)
        header = ttk.Frame(root)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text="W3SEC", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="  Evidence-first Web3 Security Research OS").pack(side="left", padx=8)
        self.repo_var = tk.StringVar()
        ttk.Entry(header, textvariable=self.repo_var).pack(side="left", fill="x", expand=True, padx=15)
        ttk.Button(header, text="Choose", command=self.choose_repo).pack(side="left")
        ttk.Button(header, text="Refresh", command=self.refresh).pack(side="left", padx=5)
        ttk.Button(header, text="FULL REFRESH", command=self.full_refresh).pack(side="left")
        self.status = tk.StringVar(value="Ready")
        ttk.Label(root, textvariable=self.status).pack(fill="x", pady=(0, 7))
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True)

    def tab(self, name: str) -> ttk.Frame:
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text=name)
        return f

    def _tabs(self) -> None:
        self.dash, self.cases, self.intel = self.tab("Dashboard"), self.tab("Cases"), self.tab("Research Intelligence")
        self.graph, self.ledger, self.promo = self.tab("Knowledge Graph"), self.tab("Temporal Ledger"), self.tab("Promotion")
        self.versions, self.reports = self.tab("Protocol Versions"), self.tab("Reports")
        self._dashboard(); self._cases(); self._text_tab(self.intel); self._graph(); self._text_tab(self.ledger)
        self._promotion(); self._text_tab(self.versions); self._reports()

    def _dashboard(self) -> None:
        cards = ttk.Frame(self.dash); cards.pack(fill="x", pady=(0, 12))
        self.card: dict[str, ttk.Label] = {}
        for i, key in enumerate(("cases", "nodes", "edges", "candidates", "evidence", "invariants")):
            cards.columnconfigure(i, weight=1)
            box = ttk.Frame(cards, style="Card.TFrame"); box.grid(row=0, column=i, padx=4, sticky="nsew")
            ttk.Label(box, text=key.upper()).pack(anchor="w")
            self.card[key] = ttk.Label(box, text="—", style="Value.TLabel"); self.card[key].pack(anchor="w")
        bar = ttk.Frame(self.dash); bar.pack(fill="x", pady=(0, 8))
        for name, fn in (("VALIDATE", self._validate), ("AUDIT", self._audit), ("FEDERATION", self._federation), ("CHRONICLE", self._chronicle), ("PROMOTION", self._promotion_run), ("LEDGER VERIFY", self._ledger_run)):
            ttk.Button(bar, text=name, command=lambda f=fn, n=name: self.run(n, f)).pack(side="left", padx=3)
        self.dash_log = ScrolledText(self.dash, font=("Consolas", 10)); self.dash_log.pack(fill="both", expand=True)

    def _cases(self) -> None:
        top = ttk.Frame(self.cases); top.pack(fill="x", pady=(0, 8))
        self.case_q = tk.StringVar()
        ttk.Label(top, text="Full-text filter").pack(side="left")
        ttk.Entry(top, textvariable=self.case_q, width=55).pack(side="left", padx=8)
        ttk.Button(top, text="Search", command=self.refresh_cases).pack(side="left")
        self.case_tree = ttk.Treeview(self.cases, columns=("id", "status", "stage", "category", "title"), show="headings")
        for c, w in (("id",190),("status",140),("stage",140),("category",190),("title",650)):
            self.case_tree.heading(c, text=c.upper()); self.case_tree.column(c, width=w, anchor="w")
        self.case_tree.pack(fill="both", expand=True)
    def _text_tab(self, frame: ttk.Frame) -> None:
        widget = ScrolledText(frame, font=("Consolas", 10)); widget.pack(fill="both", expand=True); frame._w3_text = widget

    def _graph(self) -> None:
        pane = ttk.Panedwindow(self.graph, orient="vertical"); pane.pack(fill="both", expand=True)
        up, down = ttk.Frame(pane), ttk.Frame(pane); pane.add(up, weight=3); pane.add(down, weight=2)
        self.node_tree = ttk.Treeview(up, columns=("key","type","label"), show="headings")
        for c,w in (("key",300),("type",180),("label",700)):
            self.node_tree.heading(c,text=c.upper()); self.node_tree.column(c,width=w)
        self.node_tree.pack(fill="both", expand=True)
        self.edge_text = ScrolledText(down, font=("Consolas", 9)); self.edge_text.pack(fill="both", expand=True)

    def _promotion(self) -> None:
        self.promo_tree = ttk.Treeview(self.promo, columns=("pattern","stage","decision","missing"), show="headings")
        for c,w in (("pattern",380),("stage",180),("decision",180),("missing",650)):
            self.promo_tree.heading(c,text=c.upper()); self.promo_tree.column(c,width=w)
        self.promo_tree.pack(fill="both", expand=True)

    def _reports(self) -> None:
        bar=ttk.Frame(self.reports); bar.pack(fill="x", pady=(0,8))
        ttk.Button(bar,text="Open reports",command=self.open_reports).pack(side="left")
        ttk.Button(bar,text="Open README",command=lambda: os.startfile(self._root()/"README.md")).pack(side="left",padx=6)
        ttk.Button(bar,text="Verify ledger",command=lambda:self.run("LEDGER VERIFY",self._ledger_run)).pack(side="left")
        self.report_text=ScrolledText(self.reports,font=("Consolas",10)); self.report_text.pack(fill="both",expand=True)
    def _root(self) -> Path:
        if not self.repo or not self.repo.is_dir(): raise RuntimeError("Choose a valid W3Sec repository first.")
        return self.repo

    def choose_repo(self) -> None:
        p=filedialog.askdirectory(title="Select W3Sec repository")
        if p: self._set_repo(Path(p))

    def _set_repo(self,p:Path|None)->None:
        self.repo=p.resolve() if p else None; self.repo_var.set(str(self.repo) if self.repo else "")
        if self.repo: save_repo(self.repo); self.status.set(f"Repository: {self.repo}")

    def _validate(self): return {"ok": not (e:=validate_repo(self._root())),"errors":e}
    def _audit(self): return audit_repo(self._root())
    def _federation(self):
        r=self._root(); v=build_federation_snapshot(r); write_federation_snapshot(r); write_candidate_snapshot(r); return v
    def _chronicle(self):
        r=self._root(); v=build_chronicle(r); write_chronicle(r); return v
    def _promotion_run(self):
        r=self._root(); v=build_promotion_engine(r); write_promotion_report(r); return v
    def _ledger_run(self): return {"errors":verify_chain(self._root())}
    def full_refresh(self):
        def task():
            r=self._root(); out={}
            out["federation"]=self._federation(); out["research"]=build_research_metrics(r); write_longitudinal_report(r)
            out["chronicle"]=self._chronicle(); out["history"]=build_temporal_timeline(r); write_temporal_history(r)
            out["domain"]=build_domain_evolution(r); write_domain_evolution(r); out["versions"]=build_version_diff_report(r); write_version_diff_report(r)
            out["promotion"]=self._promotion_run(); out["audit"]=audit_repo(r); return out
        self.run("FULL RESEARCH REFRESH",task)

    def run(self,name,fn):
        if self.busy: return
        self.busy=True; self.status.set(f"{name} running…")
        def worker():
            try: result=fn(); self.after(0,lambda:self.done(name,result))
            except Exception as e: self.after(0,lambda:self.fail(name,e,traceback.format_exc()))
        threading.Thread(target=worker,daemon=True).start()

    def done(self,name,result):
        self.busy=False; self.status.set(f"{name} completed")
        self.dash_log.delete("1.0","end"); self.dash_log.insert("end",dump(result))
        self.report_text.delete("1.0","end"); self.report_text.insert("end",dump(result)); self.refresh()

    def fail(self,name,e,detail):
        self.busy=False; self.status.set(f"{name} failed"); self.dash_log.delete("1.0","end"); self.dash_log.insert("end",detail)
        messagebox.showerror(f"{APP_NAME}: {name}",str(e))
    def refresh(self):
        if not self.repo: return
        def task():
            r=self._root(); return audit_repo(r),build_inventory(r),build_coverage(r),build_research_metrics(r),build_temporal_timeline(r),build_promotion_engine(r),build_version_diff_report(r)
        def worker():
            try: self.after(0,lambda:self._load(task()))
            except Exception as e: self.after(0,lambda:self.status.set(f"Load failed: {e}"))
        threading.Thread(target=worker,daemon=True).start()

    def _load(self,data):
        audit,inv,cov,intel,temporal,promo,versions=data
        self.card["cases"].configure(text=str(inv.get("case_count","—"))); self.card["nodes"].configure(text=str(audit.get("graph",{}).get("node_count","—")))
        self.card["edges"].configure(text=str(audit.get("graph",{}).get("edge_count","—"))); self.card["candidates"].configure(text=str(audit.get("federation",{}).get("candidate_record_count","—")))
        self.card["evidence"].configure(text=str(cov.get("evidence_count","—"))); self.card["invariants"].configure(text=str(inv.get("knowledge_registry_counts",{}).get("invariants","—")))
        self._set_text(self.intel,intel); self._set_text(self.ledger,temporal); self._set_text(self.versions,versions); self._load_cases(); self._load_graph(); self._load_promo(promo)
        self.status.set(f"Loaded {self.repo}")

    def _set_text(self,frame,value): frame._w3_text.delete("1.0","end"); frame._w3_text.insert("end",dump(value))
    def _load_cases(self):
        items=summarize_cases(query_cases(self.repo,CaseQuery(text=self.case_q.get().strip() or None)))
        for x in self.case_tree.get_children(): self.case_tree.delete(x)
        for v in items: self.case_tree.insert("","end",values=(v.get("id"),v.get("status"),v.get("stage"),v.get("category"),v.get("title")))
    def refresh_cases(self):
        try:self._load_cases()
        except Exception as e:self.status.set(f"Case query failed: {e}")
    def _load_graph(self):
        g=ResearchGraph.from_repo(self.repo)
        for x in self.node_tree.get_children(): self.node_tree.delete(x)
        for k,n in g.nodes.items(): self.node_tree.insert("","end",values=(k,n.type.value,n.label))
        self.edge_text.delete("1.0","end")
        self.edge_text.insert("end",dump([{"from":e.source.key,"to":e.target.key,"type":e.type} for e in g.edges]))
    def _load_promo(self,v):
        for x in self.promo_tree.get_children(): self.promo_tree.delete(x)
        for d in v.get("decisions",[]): self.promo_tree.insert("","end",values=(d.get("pattern"),d.get("computed_stage"),d.get("decision"),", ".join(d.get("missing_requirements",[]))))
    def open_reports(self): os.startfile(self._root()/"reports")


def run_self_test()->int:
    root=discover_repo()
    log_dir=settings_path().parent; log_dir.mkdir(parents=True,exist_ok=True)
    log_file=log_dir/"self-test.log"
    if not root:
        log_file.write_text("SELF-TEST: repository not found\n",encoding="utf-8"); return 2
    errors=validate_repo(root)
    if errors:
        log_file.write_text("SELF-TEST: validation failed\n"+"\n".join(errors),encoding="utf-8"); return 1
    audit=audit_repo(root)
    if not audit.get("ok"):
        log_file.write_text("SELF-TEST: audit failed\n"+dump(audit),encoding="utf-8"); return 1
    inv=build_inventory(root)
    text=f"SELF-TEST: OK\ncases={inv['case_count']} nodes={audit['graph']['node_count']} edges={audit['graph']['edge_count']}\n"
    log_file.write_text(text,encoding="utf-8")
    if sys.stdout: sys.stdout.write(text)
    return 0


def main()->int:
    if "--self-test" in sys.argv: return run_self_test()
    try:
        app=W3SecApp(); app.mainloop(); return 0
    except Exception:
        crash=settings_path().parent/"crash.log"; crash.parent.mkdir(parents=True,exist_ok=True); crash.write_text(traceback.format_exc(),encoding="utf-8")
        try: messagebox.showerror(APP_NAME,"Startup failed. See %APPDATA%\\W3Sec\\crash.log")
        except Exception: pass
        return 1
