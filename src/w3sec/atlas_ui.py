from __future__ import annotations

import json
import os
import queue
import threading
import traceback
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText

from .audit import audit_repo
from .chronicle import build_chronicle, write_chronicle
from .contract_audit import build_contract_audit, write_contract_audit
from .coverage import build_coverage
from .federation import build_federation_snapshot, write_candidate_snapshot, write_federation_snapshot
from .graph import ResearchGraph
from .history import build_domain_evolution, build_temporal_timeline, write_domain_evolution, write_temporal_history
from .intake import build_intake, list_intakes, write_intake_report
from .inventory import build_inventory
from .ledger import verify_chain
from .promotion import build_promotion_engine, write_promotion_report
from .query import CaseQuery, query_cases, summarize_cases
from .research_intelligence import build_research_metrics, write_longitudinal_report
from .validator import validate_repo
from .versions import build_version_diff_report, write_version_diff_report

APP_NAME = "ATLAS"
APP_TAGLINE = "Web3 Security Research OS"
def settings_path() -> Path:
    return Path(os.environ.get("APPDATA", Path.home())) / "ATLAS" / "settings.json"


def crash_path() -> Path:
    return settings_path().parent / "crash.log"


def save_repo(repo: Path) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"repo": str(repo)}, indent=2), encoding="utf-8")


def discover_repo() -> Path | None:
    places: list[Path] = []
    env = os.environ.get("ATLAS_REPO") or os.environ.get("W3SEC_REPO")
    if env:
        places.append(Path(env))
    try:
        places.insert(0, Path(json.loads(settings_path().read_text(encoding="utf-8")).get("repo", "")))
    except Exception:
        pass
    places.extend([Path.cwd(), Path(__file__).resolve().parents[2]])
    if getattr(__import__("sys"), "frozen", False):
        exe = Path(__import__("sys").executable).resolve()
        places.extend([exe.parent, exe.parent.parent])
    for repo in places:
        if repo.is_dir() and (repo / "corpus").is_dir():
            return repo.resolve()
    return None


def resource_path(relative: str) -> Path:
    import sys
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
    return base / relative


def pretty(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def read_report(root: Path, relative: str, default: object = {}) -> object:
    path = root / relative
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


class AtlasApp(tk.Tk):
    def __init__(self, initial_target: Path | None = None) -> None:
        super().__init__()
        self.title("ATLAS — Web3 Security Research OS")
        self.geometry("1540x940")
        self.minsize(1180, 740)
        self.configure(bg="#06121f")
        self.repo = discover_repo()
        self.initial_target = initial_target
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="atlas-worker")
        self.busy = False
        self.task_name = ""
        self.last_audit: dict[str, object] = {}
        self.task_started: float | None = None
        self.job_history: list[dict[str, object]] = []
        self._build_shell()
        self._build_pages()
        self._set_repo(self.repo)
        self.show_page("Dashboard")
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(250, self.refresh_views)
        if self.initial_target:
            self.after(500, lambda: self.start_target_import(self.initial_target))



    def _build_shell(self) -> None:
        self.sidebar = tk.Frame(self, bg="#071522", highlightthickness=1, highlightbackground="#46677b")
        self.sidebar.place(x=16, y=16, width=220, relheight=1, height=-32)
        self.brand = tk.Label(self.sidebar, text="◈  ATLAS", fg="#eef7ff", bg="#101f2a",
                              font=("Segoe UI", 24, "bold"), anchor="w")
        self.brand.pack(fill="x", padx=18, pady=(18, 0))
        tk.Label(self.sidebar, text=APP_TAGLINE, fg="#83a5b9", bg="#071522",
                 font=("Segoe UI", 9), anchor="w").pack(fill="x", padx=20, pady=(0, 20))
        self.nav = tk.Frame(self.sidebar, bg="#071522")
        self.nav.pack(fill="x", expand=False, padx=10)
        self.pages: dict[str, tk.Frame] = {}
        self.nav_buttons: dict[str, tk.Button] = {}
        nav = [
            ("Dashboard", "⌂"), ("Import / Intake", "⇪"), ("Audit Findings", "⚠"), ("Cases", "▣"),
            ("Research Intelligence", "◉"), ("Knowledge Graph", "⌘"),
            ("Temporal Ledger", "◷"), ("Promotion", "↗"), ("Protocol Versions", "◇"),
            ("Reports", "▤"), ("Settings", "⚙"),
        ]
        for name, icon in nav:
            btn = tk.Button(
                self.nav, text=f"{icon}  {name}", command=lambda n=name: self.show_page(n),
                bg="#071522", fg="#a8c2d2", activebackground="#10324b", activeforeground="#ffffff",
                relief="flat", bd=0, anchor="w", padx=14, pady=9, font=("Segoe UI", 10),
            )
            btn.pack(fill="x", pady=2)
            self.nav_buttons[name] = btn

        tk.Label(self.sidebar, text="Continuous development", fg="#66879a", bg="#071522",
                 font=("Segoe UI", 8)).pack(side="bottom", padx=18, pady=(0, 16), anchor="w")

        self.main = tk.Frame(self, bg="#06121f")
        self.main.place(x=250, y=16, relx=0, width=-266, relheight=1, height=-32)
        top = tk.Frame(self.main, bg="#101f2a", highlightthickness=1, highlightbackground="#46677b")
        top.pack(fill="x", pady=(0, 10))
        self.repo_var = tk.StringVar()
        tk.Label(top, text="REPOSITORY", fg="#7193a7", bg="#081826", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(14, 6), pady=13)
        tk.Entry(top, textvariable=self.repo_var, bg="#0a1c2a", fg="#e9f7ff", insertbackground="#ffffff",
                 relief="flat", font=("Segoe UI", 9), highlightthickness=1, highlightbackground="#22465d").pack(
                     side="left", fill="x", expand=True, ipady=7)
        self._top_button(top, "CHOOSE", self.choose_repo)
        self._top_button(top, "AUDIT", self.audit_repo)
        self._top_button(top, "FULL REFRESH", self.full_refresh)
        self._top_button(top, "SETTINGS", lambda: self.show_page("Settings"))
        self.status_bar = tk.Frame(self.main, bg="#101f2a", highlightthickness=1, highlightbackground="#46677b")
        self.status_bar.pack(fill="x", pady=(0, 10))
        self.status = tk.StringVar(value="ATLAS ready")
        tk.Label(self.status_bar, textvariable=self.status, fg="#b9d2df", bg="#071522",
                 font=("Segoe UI", 9), anchor="w").pack(side="left", padx=12, pady=8)
        self.spinner = tk.Label(self.status_bar, text="●", fg="#5de1ff", bg="#071522", font=("Segoe UI", 10))
        self.spinner.pack(side="right", padx=10)
        self.progress = tk.Canvas(self.main, height=3, bg="#071823", highlightthickness=0)
        self.progress.pack(fill="x", pady=(0, 6))
        self.progress_id = self.progress.create_rectangle(0, 0, 0, 3, fill="#33bfff", outline="")

        self.content = tk.Frame(self.main, bg="#06121f")
        self.content.pack(fill="both", expand=True)
    def _top_button(self, parent: tk.Frame, text: str, command) -> None:
        tk.Button(parent, text=text, command=command, bg="#0f3149", fg="#e9f8ff",
                  activebackground="#174b6f", activeforeground="#ffffff", relief="flat",
                  font=("Segoe UI", 8, "bold"), padx=14, pady=8, bd=0).pack(side="left", padx=4, pady=5)



    def _build_pages(self) -> None:
        names = ["Dashboard", "Import / Intake", "Audit Findings", "Cases", "Research Intelligence",
                 "Knowledge Graph", "Temporal Ledger", "Promotion", "Protocol Versions",
                 "Reports", "Settings"]
        for name in names:
            frame = tk.Frame(self.content, bg="#06121f")
            self.pages[name] = frame
        self._dashboard_page()
        self._intake_page()
        self._audit_findings_page()
        self._cases_page()
        self._reports_pages()
        self._settings_page()
    def show_page(self, name: str) -> None:
        for frame in self.pages.values():
            frame.place_forget()
        self.pages[name].place(relx=0, rely=0, relwidth=1, relheight=1)
        for key, btn in self.nav_buttons.items():
            active = key == name
            btn.configure(bg="#123a56" if active else "#071522",
                          fg="#ffffff" if active else "#a8c2d2")
        self.status.set(f"ATLAS · {name}")


    def _panel(self, parent: tk.Frame, title: str, subtitle: str | None = None, **layout) -> tk.Frame:
        panel = tk.Frame(parent, bg="#0a1825", highlightthickness=1, highlightbackground="#46677b")
        if "row" in layout or "column" in layout or "sticky" in layout:
            panel.grid(**layout)
        else:
            panel.pack(**layout)
        head = tk.Frame(panel, bg="#101f2a")
        head.pack(fill="x", padx=14, pady=(12, 4))
        tk.Label(head, text=title.upper(), fg="#dceef7", bg="#0a1825",
                 font=("Segoe UI", 10, "bold")).pack(side="left")
        if subtitle:
            tk.Label(head, text=subtitle, fg="#6f93a6", bg="#0a1825",
                     font=("Segoe UI", 8)).pack(side="right")
        return panel
    def _card(self, parent: tk.Frame, title: str, key: str, column: int) -> None:
        panel = tk.Frame(parent, bg="#0c2030", highlightthickness=1, highlightbackground="#28536b")
        panel.grid(row=0, column=column, sticky="nsew", padx=4)
        tk.Label(panel, text=title.upper(), fg="#7093a7", bg="#0c2030",
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=12, pady=(10, 0))
        value = tk.Label(panel, text="—", fg="#effaff", bg="#0c2030",
                         font=("Segoe UI", 22, "bold"))
        value.pack(anchor="w", padx=12, pady=(1, 10))
        setattr(self, f"card_{key}", value)


    def _dashboard_page(self) -> None:
        page = self.pages["Dashboard"]
        header = tk.Frame(page, bg="#06121f")
        header.pack(fill="x")
        tk.Label(header, text="Command Center", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(side="left")
        tk.Label(header, text="Evidence → Analysis → Research → Knowledge", fg="#6d96aa",
                 bg="#06121f", font=("Segoe UI", 9)).pack(side="left", padx=15, pady=(7, 0))
        cards = tk.Frame(page, bg="#06121f")
        cards.pack(fill="x", pady=(10, 10))
        for i in range(8):
            cards.columnconfigure(i, weight=1)
        for i, item in enumerate([
            ("Cases", "cases"), ("Intakes", "intakes"), ("Contracts", "contracts"),
            ("Nodes", "nodes"), ("Edges", "edges"), ("Candidates", "candidates"),
            ("Evidence", "evidence"), ("Invariants", "invariants"),
        ]):
            self._card(cards, item[0], item[1], i)

        body = tk.Frame(page, bg="#06121f")
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)
        self._dashboard_system(body)
        self._dashboard_activity(body)
    def _dashboard_system(self, parent: tk.Frame) -> None:
        panel = self._panel(parent, "System Overview", "LIVE", row=0, column=0, sticky="nsew", padx=(0, 5))
        self.system_lines = tk.Frame(panel, bg="#0a1825")
        self.system_lines.pack(fill="both", expand=True, padx=12, pady=8)
        self.system_checks: dict[str, tk.Label] = {}
        labels = ["Knowledge Graph", "Temporal Ledger", "Federation Layer", "Research Intelligence",
                  "Promotion Engine", "Protocol Versions", "Audit & Validation"]
        for label in labels:
            row = tk.Frame(self.system_lines, bg="#0a1825")
            row.pack(fill="x", pady=6)
            check = tk.Label(row, text="●", fg="#48dca8", bg="#0a1825", font=("Segoe UI", 10))
            check.pack(side="left", padx=(2, 8))
            text_label = tk.Label(row, text=label, fg="#d8ecf5", bg="#0a1825",
                                  font=("Segoe UI", 9, "bold"), anchor="w")
            text_label.pack(side="left")
            self.system_checks[label] = text_label
        tk.Label(panel, text="ATLAS keeps evidence and inference separate. Candidate data never silently becomes canonical.",
                 fg="#66899d", bg="#0a1825", justify="left", wraplength=430,
                 font=("Segoe UI", 8)).pack(fill="x", padx=14, pady=(8, 14))


    def _dashboard_activity(self, parent: tk.Frame) -> None:
        pane = tk.Frame(parent, bg="#06121f")
        pane.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        pane.rowconfigure(0, weight=1)
        pane.rowconfigure(1, weight=1)
        pane.columnconfigure(0, weight=1)
        quick = self._panel(pane, "Quick Actions", "READY", row=0, column=0, sticky="nsew")
        grid = tk.Frame(quick, bg="#0a1825")
        grid.pack(fill="both", expand=True, padx=10, pady=8)
        actions = [
            ("IMPORT CONTRACT / REPOSITORY", self.open_import),
            ("AUDIT", self.audit_repo),
            ("FULL REFRESH", self.full_refresh),
            ("FEDERATION", self.run_federation),
            ("CHRONICLE", self.run_chronicle),
            ("PROMOTION", self.run_promotion),
            ("LEDGER VERIFY", self.run_ledger_verify),
            ("REPORTS", lambda: self.show_page("Reports")),
        ]
        for i, (title, fn) in enumerate(actions):
            btn = self._action_button(grid, title, fn)
            btn.grid(row=i // 2, column=i % 2, sticky="ew", padx=4, pady=4)
        grid.columnconfigure(0, weight=1); grid.columnconfigure(1, weight=1)

        activity = self._panel(pane, "Background Activity", "NO TERMINAL", row=1, column=0, sticky="nsew", pady=(8, 0))
        self.activity_log = ScrolledText(activity, bg="#07141f", fg="#b8d4df",
                                         insertbackground="#ffffff", relief="flat",
                                         font=("Consolas", 9), height=8)
        self.activity_log.pack(fill="both", expand=True, padx=10, pady=10)
    def _intake_page(self) -> None:
        page = self.pages["Import / Intake"]
        tk.Label(page, text="Contract Intake", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(page, text="Load source files, ZIP/TAR archives, or a complete contract repository.",
                 fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 10))
        toolbar = tk.Frame(page, bg="#0a1825", highlightthickness=1, highlightbackground="#244b62")
        toolbar.pack(fill="x", pady=(0, 8), ipady=6)
        self.target_var = tk.StringVar()
        tk.Entry(toolbar, textvariable=self.target_var, bg="#091a29", fg="#e8f7ff",
                 insertbackground="#ffffff", relief="flat", highlightthickness=1,
                 highlightbackground="#254d64").pack(side="left", fill="x", expand=True, padx=10, ipady=7)
        self._toolbar_button(toolbar, "FILES", self.choose_files)
        self._toolbar_button(toolbar, "ZIP / ARCHIVE", self.choose_archive)
        self._toolbar_button(toolbar, "DIRECTORY", self.choose_directory)
        self._toolbar_button(toolbar, "AUDIT TARGET", self.audit_target)
        self._toolbar_button(toolbar, "REGISTER", self.register_target)
        tk.Label(page, text="Accepted: all file types are importable. Known smart-contract ecosystems are classified; "
                 "unknown/binary files are safely inventoried by hash rather than guessed.",
                 fg="#6f92a5", bg="#06121f", font=("Segoe UI", 8), justify="left").pack(anchor="w", pady=(0, 8))

        body = tk.Frame(page, bg="#06121f")
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)
        left = self._panel(body, "Registered Inputs", "HASHED", row=0, column=0, sticky="nsew", padx=(0, 5))
        right = self._panel(body, "Intake Snapshot", "STRUCTURAL", row=0, column=1, sticky="nsew", padx=(5, 0))
        self.intake_tree = tk.Listbox(left, bg="#07141f", fg="#b9d8e4", relief="flat",
                                      selectbackground="#12496a", selectforeground="#ffffff",
                                      font=("Consolas", 9))
        self.intake_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.intake_tree.bind("<<ListboxSelect>>", self._intake_selected)
        self.intake_detail = ScrolledText(right, bg="#07141f", fg="#b9d8e4",
                                          insertbackground="#ffffff", relief="flat",
                                          font=("Consolas", 9))
        self.intake_detail.pack(fill="both", expand=True, padx=10, pady=10)
    def _action_button(self, parent: tk.Frame, text: str, command) -> tk.Button:
        return tk.Button(parent, text=text, command=command, bg="#0e3047", fg="#e8f8ff",
                         activebackground="#154c70", activeforeground="#ffffff",
                         relief="flat", bd=0, font=("Segoe UI", 9, "bold"), pady=10)


    def _toolbar_button(self, parent: tk.Frame, text: str, command) -> tk.Button:
        return tk.Button(parent, text=text, command=command, bg="#10354c", fg="#e3f7ff",
                         activebackground="#17608a", activeforeground="#ffffff",
                         relief="flat", bd=0, font=("Segoe UI", 8, "bold"), padx=10, pady=7)


    def _intake_selected(self, _event=None) -> None:
        if not self.intake_tree.curselection():
            return
        index = self.intake_tree.curselection()[0]
        items = list_intakes(self.repo) if self.repo else []
        if 0 <= index < len(items):
            self.intake_detail.delete("1.0", "end")
            self.intake_detail.insert("end", pretty(items[index]))


    def choose_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Load contract files / artifacts")
        if not paths:
            return
        self._stage_files([Path(x) for x in paths])


    def choose_archive(self) -> None:
        path = filedialog.askopenfilename(
            title="Load archive",
            filetypes=[("Archives", "*.zip *.tar *.tgz *.tar.gz *.tar.bz2 *.tar.xz *.7z *.rar"), ("All files", "*.*")]
        )
        if path:
            self.start_target_import(Path(path))


    def choose_directory(self) -> None:
        path = filedialog.askdirectory(title="Load contract repository")
        if path:
            self.start_target_import(Path(path))
    def _audit_findings_page(self) -> None:
        page = self.pages["Audit Findings"]
        tk.Label(page, text="Audit Findings", fg="#f2fbff", bg="#06121f", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(page, text="Deterministic review leads · not automatic proof of exploitability", fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))
        body = tk.Frame(page, bg="#06121f"); body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)
        left = self._panel(body, "Findings", "PRIORITIZED", row=0, column=0, sticky="nsew", padx=(0, 5))
        right = self._panel(body, "Finding Detail", "EVIDENCE", row=0, column=1, sticky="nsew", padx=(5, 0))
        self.finding_tree = tk.Listbox(left, bg="#07141f", fg="#c3dce7", selectbackground="#6b2b38", selectforeground="#ffffff", relief="flat", font=("Consolas", 9))
        self.finding_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.finding_tree.bind("<<ListboxSelect>>", self._finding_selected)
        self.finding_detail = ScrolledText(right, bg="#07141f", fg="#b9d8e4", insertbackground="#ffffff", relief="flat", font=("Consolas", 9))
        self.finding_detail.pack(fill="both", expand=True, padx=10, pady=10)


    def load_cases(self) -> None:
        if not self.repo:
            return
        try:
            cases = summarize_cases(query_cases(self.repo, CaseQuery(text=self.case_query.get().strip() or None)))
            self.case_tree.delete(0, "end")
            for case in cases:
                self.case_tree.insert("end", f"{case.get('id')}  ·  {case.get('status')}  ·  {case.get('stage')}  ·  {case.get('title')}")
            self.status.set(f"Cases loaded · {len(cases)} records")
        except Exception as exc:
            self.status.set(f"Case search failed · {exc}")


    def _cases_page(self) -> None:
        page = self.pages["Cases"]
        tk.Label(page, text="Research Cases", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        top = tk.Frame(page, bg="#0a1825", highlightthickness=1, highlightbackground="#244b62")
        top.pack(fill="x", pady=(8, 8))
        self.case_query = tk.StringVar()
        tk.Entry(top, textvariable=self.case_query, bg="#091a29", fg="#e8f7ff",
                 insertbackground="#ffffff", relief="flat").pack(side="left", fill="x", expand=True, padx=10, ipady=8)
        self._toolbar_button(top, "SEARCH", self.load_cases)
        body = self._panel(page, "Case Corpus", "EVIDENCE-FIRST", fill="both", expand=True)
        self.case_tree = tk.Listbox(body, bg="#07141f", fg="#c0dbe6", relief="flat",
                                    selectbackground="#12496a", selectforeground="#ffffff",
                                    font=("Consolas", 9))
        self.case_tree.pack(fill="both", expand=True, padx=10, pady=10)


    def _reports_pages(self) -> None:
        page_specs = {
            "Research Intelligence": "reports/longitudinal/research-intelligence.json",
            "Temporal Ledger": "reports/longitudinal/temporal-history.json",
            "Protocol Versions": "reports/longitudinal/protocol-version-diffs.json",
            "Promotion": "reports/longitudinal/promotion-decisions.json",
        }
        for name, rel in page_specs.items():
            frame = self.pages[name]
            tk.Label(frame, text=name, fg="#f2fbff", bg="#06121f",
                     font=("Segoe UI", 20, "bold")).pack(anchor="w")
            tk.Label(frame, text=rel, fg="#6f92a5", bg="#06121f",
                     font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 8))
            text = self._panel(frame, "Report", "READ ONLY", fill="both", expand=True)
            widget = ScrolledText(text, bg="#07141f", fg="#b9d8e4", insertbackground="#ffffff",
                                  relief="flat", font=("Consolas", 9))
            widget.pack(fill="both", expand=True, padx=10, pady=10)
            setattr(self, f"text_{name.replace(' ', '_').lower()}", widget)
            setattr(self, f"rel_{name.replace(' ', '_').lower()}", rel)

        frame = self.pages["Knowledge Graph"]
        tk.Label(frame, text="Knowledge Graph", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        body = tk.Frame(frame, bg="#06121f")
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=1); body.rowconfigure(0, weight=1)
        nodes = self._panel(body, "Nodes", "TYPED", row=0, column=0, sticky="nsew", padx=(0, 5))
        edges = self._panel(body, "Lineage Edges", "DERIVED", row=0, column=1, sticky="nsew", padx=(5, 0))
        self.graph_nodes = tk.Listbox(nodes, bg="#07141f", fg="#b9d8e4", relief="flat",
                                      font=("Consolas", 8))
        self.graph_nodes.pack(fill="both", expand=True, padx=10, pady=10)
        self.graph_edges = ScrolledText(edges, bg="#07141f", fg="#b9d8e4", relief="flat",
                                        font=("Consolas", 8))
        self.graph_edges.pack(fill="both", expand=True, padx=10, pady=10)

        frame = self.pages["Reports"]
        tk.Label(frame, text="Reports", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        body = self._panel(frame, "Artifacts", "OPEN", fill="both", expand=True)
        for title, rel in [
            ("Longitudinal Intelligence", "reports/longitudinal/research-intelligence.json"),
            ("Temporal History", "reports/longitudinal/temporal-history.json"),
            ("Domain Evolution", "reports/longitudinal/domain-evolution.json"),
            ("Promotion Decisions", "reports/longitudinal/promotion-decisions.json"),
            ("Federation Snapshot", "reports/federation/snapshot.json"),
        ]:
            btn = self._action_button(body, title, lambda r=rel: self.open_report(r))
            btn.pack(fill="x", padx=10, pady=4)


    def _settings_page(self) -> None:
        page = self.pages["Settings"]
        tk.Label(page, text="ATLAS Settings", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        panel = self._panel(page, "Workspace", "PERSISTENT", fill="both", expand=True)
        tk.Label(panel, text="Repository is stored locally in %APPDATA%\\ATLAS\\settings.json.",
                 fg="#88a7b7", bg="#0a1825", font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=14)
        self._action_button(panel, "CHOOSE REPOSITORY", self.choose_repo).pack(anchor="w", padx=14, pady=5)
        self._action_button(panel, "OPEN ATLAS DATA FOLDER",
                            lambda: os.startfile(settings_path().parent)).pack(anchor="w", padx=14, pady=5)
        self._action_button(panel, "OPEN CRASH LOG",
                            lambda: os.startfile(crash_path())).pack(anchor="w", padx=14, pady=5)



    def open_import(self) -> None:
        self.show_page("Import / Intake")


    def choose_repo(self) -> None:
        path = filedialog.askdirectory(title="Choose ATLAS research repository")
        if path:
            self._set_repo(Path(path))
            self.show_page("Dashboard")


    def _set_repo(self, repo: Path | None) -> None:
        self.repo = repo.resolve() if repo else None
        self.repo_var.set(str(self.repo) if self.repo else "No repository selected")
        if self.repo:
            save_repo(self.repo)
            self.status.set(f"Repository selected · {self.repo}")
    def _stage_files(self, paths: list[Path]) -> None:
        root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ATLAS" / "imports"
        root.mkdir(parents=True, exist_ok=True)
        stage = root / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-%f")
        stage.mkdir()
        for path in paths:
            target = stage / path.name
            if target.exists():
                target = stage / f"{len(list(stage.iterdir()))}-{path.name}"
            shutil.copy2(path, target)
        self.target_var.set(str(stage))
        self.start_target_import(stage)


    def start_target_import(self, target: Path) -> None:
        if not target.exists():
            self.status.set("Import target does not exist.")
            return
        self.show_page("Import / Intake")
        self.target_var.set(str(target))
        self.status.set(f"Import queued · {target.name}")
        self._run_task("IMPORT", lambda: self._import_target(target))


    def _import_target(self, target: Path) -> dict[str, object]:
        if not self.repo:
            raise RuntimeError("Choose the ATLAS research repository first.")
        report = build_intake(target)
        path = write_intake_report(self.repo, report)
        return {"report": report, "report_path": str(path)}


    def register_target(self) -> None:
        raw = self.target_var.get().strip()
        if raw:
            self.start_target_import(Path(raw).expanduser())


    def audit_target(self) -> None:
        raw = self.target_var.get().strip()
        if not raw:
            self.status.set("Select a contract file, archive, or repository first.")
            return
        target = Path(raw).expanduser()
        self.show_page("Import / Intake")
        self._run_task("AUDIT TARGET", lambda: self._audit_target_worker(target), switch_to_import=True)


    def _audit_target_worker(self, target: Path) -> dict[str, object]:
        if not self.repo:
            raise RuntimeError("Choose the ATLAS research repository first.")
        report = build_contract_audit(target, self.repo)
        path = write_contract_audit(self.repo, report)
        return {"report": report, "report_path": str(path)}


    def _finding_selected(self, _event=None) -> None:
        if not self.finding_tree.curselection() or not isinstance(self.last_audit, dict):
            return
        report = self.last_audit
        findings = report.get("findings", [])
        index = self.finding_tree.curselection()[0]
        if 0 <= index < len(findings):
            self.finding_detail.delete("1.0", "end")
            self.finding_detail.insert("end", pretty(findings[index]))


    def open_report(self, relative: str) -> None:
        if not self.repo:
            return
        path = self.repo / relative
        if path.exists():
            os.startfile(path)
        else:
            self.status.set(f"Report not found · {relative}")
    def audit_repo(self) -> None:
        if not self.repo:
            self.status.set("Choose a repository first.")
            return
        self._run_task("AUDIT", lambda: audit_repo(self.repo))


    def full_refresh(self) -> None:
        if not self.repo:
            self.status.set("Choose a repository first.")
            return
        self._run_task("FULL REFRESH", self._full_refresh_worker)


    def _full_refresh_worker(self) -> dict[str, object]:
        root = self.repo
        result: dict[str, object] = {}
        federation = build_federation_snapshot(root)
        write_federation_snapshot(root); write_candidate_snapshot(root)
        result["federation"] = federation
        result["research"] = build_research_metrics(root); write_longitudinal_report(root)
        result["chronicle"] = build_chronicle(root); write_chronicle(root)
        result["history"] = build_temporal_timeline(root); write_temporal_history(root)
        result["domain"] = build_domain_evolution(root); write_domain_evolution(root)
        result["versions"] = build_version_diff_report(root); write_version_diff_report(root)
        result["promotion"] = build_promotion_engine(root); write_promotion_report(root)
        result["audit"] = audit_repo(root)
        return result


    def run_federation(self) -> None:
        if self.repo:
            self._run_task("FEDERATION", lambda: self._federation_worker())


    def _federation_worker(self) -> dict[str, object]:
        value = build_federation_snapshot(self.repo)
        write_federation_snapshot(self.repo); write_candidate_snapshot(self.repo)
        return value


    def run_chronicle(self) -> None:
        if self.repo:
            self._run_task("CHRONICLE", lambda: self._chronicle_worker())
    def _chronicle_worker(self) -> dict[str, object]:
        value = build_chronicle(self.repo)
        write_chronicle(self.repo)
        return value


    def run_promotion(self) -> None:
        if self.repo:
            self._run_task("PROMOTION", self._promotion_worker)


    def _promotion_worker(self) -> dict[str, object]:
        value = build_promotion_engine(self.repo)
        write_promotion_report(self.repo)
        return value


    def run_ledger_verify(self) -> None:
        if self.repo:
            self._run_task("LEDGER VERIFY", lambda: {"errors": verify_chain(self.repo / "ledger" / "events.jsonl")})


    def _run_task(self, name: str, fn, switch_to_import: bool = False) -> None:
        if self.busy:
            self.status.set(f"{self.task_name} is already running in background.")
            return
        self.busy = True
        self.task_name = name
        self.task_started = datetime.now().timestamp()
        self.status.set(f"{name} · running in background · ATLAS remains usable")
        self.spinner.configure(text="◌", fg="#ffd166")
        self._log(f"[{self._clock()}] START  {name}")
        self._animate_progress()
        future = self.executor.submit(fn)
        def waiter():
            try:
                value = future.result()
                self.after(0, lambda: self._task_done(name, value))
            except Exception as exc:
                detail = traceback.format_exc()
                self.after(0, lambda: self._task_failed(name, exc, detail))
        threading.Thread(target=waiter, daemon=True, name=f"atlas-{name.lower()}-waiter").start()


    def _animate_progress(self) -> None:
        if not self.busy:
            self.progress.coords(self.progress_id, 0, 0, 0, 3)
            return
        width = max(300, self.progress.winfo_width())
        position = int((datetime.now().timestamp() * 140) % max(1, width + 260)) - 130
        self.progress.coords(self.progress_id, position, 0, position + 260, 3)
        self.after(40, self._animate_progress)


    def _task_done(self, name: str, value: object) -> None:
        self.busy = False
        self.spinner.configure(text="●", fg="#47dca7")
        elapsed = (datetime.now().timestamp() - self.task_started) if self.task_started else 0
        self.status.set(f"{name} · completed · {elapsed:.1f}s · no terminal window")
        self.job_history.append({"task": name, "status": "completed", "seconds": round(elapsed, 2),
                                 "at": datetime.now(timezone.utc).isoformat()})
        self._log(f"[{self._clock()}] DONE   {name} · {elapsed:.1f}s")
        self._write_result_to_page(name, value)
        self.refresh_views()


    def _task_failed(self, name: str, exc: Exception, detail: str) -> None:
        self.busy = False
        self.spinner.configure(text="●", fg="#ff7b8b")
        self.status.set(f"{name} · failed · details kept in ATLAS log")
        self.job_history.append({"task": name, "status": "failed", "error": str(exc),
                                 "at": datetime.now(timezone.utc).isoformat()})
        self._log(f"[{self._clock()}] FAIL   {name} · {exc}\n{detail}")
        self._write_result_to_page(name, {"error": str(exc), "traceback": detail})
    def _write_result_to_page(self, name: str, value: object) -> None:
        text = pretty(value)
        self.activity_log.insert("end", text + "\n\n")
        self.activity_log.see("end")
        self.last_result = value
        if name == "AUDIT TARGET":
            report = value.get("report", {}) if isinstance(value, dict) else {}
            self.last_audit = report
            self.finding_tree.delete(0, "end")
            for finding in report.get("findings", []):
                self.finding_tree.insert("end", f"[{finding.get('priority','?').upper():8}] {finding.get('file')}:{finding.get('line')} · {finding.get('signal')}")
            self.show_page("Audit Findings")
            self.finding_detail.delete("1.0", "end")
            self.finding_detail.insert("end", pretty(report))
        elif name == "IMPORT":
            report = value.get("report", {}) if isinstance(value, dict) else {}
            self.intake_detail.delete("1.0", "end")
            self.intake_detail.insert("end", pretty(report))
            self.show_page("Import / Intake")


    def _log(self, line: str) -> None:
        if hasattr(self, "activity_log"):
            self.activity_log.insert("end", line.rstrip() + "\n")
            self.activity_log.see("end")


    @staticmethod
    def _clock() -> str:
        return datetime.now().strftime("%H:%M:%S")


    def refresh_views(self) -> None:
        if not self.repo or self.busy:
            return
        def worker():
            try:
                data = self._read_views()
                self.after(0, lambda: self._apply_views(data))
            except Exception as exc:
                self.after(0, lambda: self.status.set(f"View refresh failed · {exc}"))
        threading.Thread(target=worker, daemon=True, name="atlas-view-loader").start()


    def _read_views(self) -> dict[str, object]:
        root = self.repo
        inventory = build_inventory(root)
        graph = ResearchGraph.from_repo(root)
        audit = read_report(root, "reports/longitudinal/research-intelligence.json", {})
        history = read_report(root, "reports/longitudinal/temporal-history.json", {})
        versions = read_report(root, "reports/longitudinal/protocol-version-diffs.json", {})
        promotion = read_report(root, "reports/longitudinal/promotion-decisions.json", {})
        cases = summarize_cases(query_cases(root, CaseQuery(text=self.case_query.get().strip() or None)))
        return {"inventory": inventory, "graph": graph, "cases": cases, "intakes": list_intakes(root),
                "intelligence": audit, "history": history, "versions": versions, "promotion": promotion}
    def _apply_views(self, data: dict[str, object]) -> None:
        inventory = data["inventory"]
        graph: ResearchGraph = data["graph"]
        cases = data["cases"]
        intakes = data["intakes"]
        if isinstance(inventory, dict):
            self.card_cases.configure(text=str(inventory.get("case_count", "—")))
            self.card_intakes.configure(text=str(len(intakes)))
            self.card_contracts.configure(text=str(sum(
                int(x.get("summary", {}).get("contract_count", 0)) for x in intakes
            )))
        self.card_nodes.configure(text=str(len(graph.nodes)))
        self.card_edges.configure(text=str(len(graph.edges)))
        candidate_count = read_report(self.repo, "reports/federation/snapshot.json", {}).get("candidate_record_count", "—")
        self.card_candidates.configure(text=str(candidate_count))
        self.card_evidence.configure(text=str((inventory or {}).get("knowledge_registry_counts", {}).get("evidence", "—")))
        self.card_invariants.configure(text=str((inventory or {}).get("knowledge_registry_counts", {}).get("invariants", "—")))
        self.system_checks["Knowledge Graph"].configure(fg="#48dca8")
        self.system_checks["Temporal Ledger"].configure(fg="#48dca8")
        self.system_checks["Federation Layer"].configure(fg="#48dca8")
        self.system_checks["Research Intelligence"].configure(fg="#48dca8")
        self.system_checks["Promotion Engine"].configure(fg="#48dca8")
        self.system_checks["Protocol Versions"].configure(fg="#48dca8")
        self.system_checks["Audit & Validation"].configure(fg="#48dca8")
        self.case_tree.delete(0, "end")
        for case in cases:
            self.case_tree.insert("end", f"{case.get('id')}  ·  {case.get('status')}  ·  {case.get('stage')}  ·  {case.get('title')}")
        self.intake_tree.delete(0, "end")
        for item in intakes:
            target = item.get("target", {})
            summary = item.get("summary", {})
            self.intake_tree.insert("end", f"{target.get('name')}  ·  {target.get('kind')}  ·  {summary.get('contract_count', 0)} contracts  ·  {item.get('id')}")
        self.graph_nodes.delete(0, "end")
        for key, node in graph.nodes.items():
            self.graph_nodes.insert("end", f"{key}  ·  {node.kind}")
        self.graph_edges.delete("1.0", "end")
        self.graph_edges.insert("end", pretty([
            {"from": edge.source.key, "to": edge.target.key, "relation": edge.relation}
            for edge in graph.edges
        ]))
        self._set_report_text("research_intelligence", data["intelligence"])
        self._set_report_text("temporal_ledger", data["history"])
        self._set_report_text("protocol_versions", data["versions"])
        self._set_report_text("promotion", data["promotion"])
    def _set_report_text(self, key: str, value: object) -> None:
        widget = getattr(self, f"text_{key}", None)
        if widget is not None:
            widget.delete("1.0", "end")
            widget.insert("end", pretty(value))


    def _close(self) -> None:
        try:
            self.executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self.executor.shutdown(wait=False)
        self.destroy()


def run_self_test() -> int:
    root = discover_repo()
    log_dir = settings_path().parent
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "self-test.log"
    if not root:
        log_file.write_text("SELF-TEST: repository not found\n", encoding="utf-8")
        return 2
    errors = validate_repo(root)
    if errors:
        log_file.write_text("SELF-TEST: validation failed\n" + "\n".join(errors), encoding="utf-8")
        return 1
    audit = audit_repo(root)
    if not audit.get("ok"):
        log_file.write_text("SELF-TEST: audit failed\n" + pretty(audit), encoding="utf-8")
        return 1
    ResearchGraph.from_repo(root)
    build_inventory(root)
    log_file.write_text(
        f"SELF-TEST: OK\ncases={audit['graph']['node_count']} nodes={audit['graph']['node_count']} edges={audit['graph']['edge_count']}\n",
        encoding="utf-8",
    )
    return 0


def main() -> int:
    import sys
    if "--self-test" in sys.argv:
        return run_self_test()
    target = next((Path(arg).expanduser() for arg in sys.argv[1:] if not arg.startswith("-") and Path(arg).exists()), None)
    try:
        app = AtlasApp(target)
        app.mainloop()
        return 0
    except Exception:
        detail = traceback.format_exc()
        path = crash_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(detail, encoding="utf-8")
        return 1
