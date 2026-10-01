from __future__ import annotations

import json
import os
import queue
import threading
import traceback
import sys
import shutil
import tempfile
from concurrent.futures import CancelledError, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

from PIL import Image, ImageOps, ImageTk

from .audit import audit_repo
from .evidence_fabric import build_evidence_fabric
from .finding_gate import attach_gate
from .chronicle import build_chronicle, write_chronicle
from .contract_audit import build_contract_audit, write_contract_audit
from .coverage import build_coverage
from .federation import build_federation_snapshot, write_candidate_snapshot, write_federation_snapshot
from .graph import ResearchGraph
from .history import build_domain_evolution, build_temporal_timeline, write_domain_evolution, write_temporal_history
from .intake import OperationCancelled, build_intake, list_intakes, write_intake_report
from .inventory import build_inventory
from .ledger import verify_chain
from .promotion import build_promotion_engine, write_promotion_report
from .query import CaseQuery, query_cases, summarize_cases
from .negative_knowledge import load_negative_results
from .research_intelligence import build_research_metrics, write_longitudinal_report
from .research_run import ResearchRun, resume_audit_run
from .validator import validate_repo
from .verification import human_outcome, run_verification, split_command, suggested_command, write_verification_result
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


def target_state_path() -> Path:
    return settings_path().parent / "target.json"


def save_target_state(target: Path, report_path: Path | None = None) -> None:
    path = target_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"target": str(target.resolve())}
    if report_path:
        try:
            payload["report_path"] = str(report_path.resolve())
        except OSError:
            payload["report_path"] = str(report_path)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def clear_target_state() -> None:
    try:
        target_state_path().unlink()
    except FileNotFoundError:
        pass


def discover_repo() -> Path | None:
    # ATLAS has one canonical local checkout. A packaged EXE must not attach to
    # an old build/verify copy just because that path launched the process.
    places: list[Path] = []
    canonical = Path.home() / "lucilfer12-web3-security-research"
    if canonical.is_dir():
        places.append(canonical)
    env = os.environ.get("ATLAS_REPO") or os.environ.get("W3SEC_REPO")
    if env:
        places.append(Path(env))
    try:
        saved = Path(json.loads(settings_path().read_text(encoding="utf-8")).get("repo", ""))
        if saved and saved != canonical:
            places.append(saved)
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

class GlassButton(tk.Button):
    """Native Tk button with a composited 70%-visible forest surface.

    A real Button is used for input semantics so mouse, keyboard and accessibility
    activation are handled by Tk rather than a canvas event shim.
    """
    def __init__(self, parent, text, command, app, *, font=("Segoe UI", 9, "bold"),
                 height=38, padx=12, radius=8):
        super().__init__(
            parent, text=text, command=command, font=font,
            bd=0, relief="flat", highlightthickness=0,
            activeforeground="#ffffff", foreground="#e3f4ff",
            compound="center", cursor="hand2", takefocus=1,
        )
        self._app=app; self._text=text; self._height=height; self._padx=padx
        self._photo=None; self._hover=False; self._active=False
        self._last_size=(0,0); self._redrawing=False
        self.configure(height=max(1,height), padx=padx, pady=0)
        self.bind("<Enter>", self._enter, add="+")
        self.bind("<Leave>", self._leave, add="+")
        self.bind("<ButtonPress-1>", self._press, add="+")
        self.bind("<ButtonRelease-1>", self._release, add="+")
        self.bind("<Configure>", lambda _e: self._redraw(), add="+")
        self.after_idle(self._redraw)

    def _enter(self, _event=None):
        self._hover=True; self._last_size=(0,0); self._redraw()

    def _leave(self, _event=None):
        self._hover=False; self._active=False; self._last_size=(0,0); self._redraw()

    def _press(self, _event=None):
        self._active=True; self._last_size=(0,0); self._redraw()

    def _release(self, _event=None):
        self._active=False; self._last_size=(0,0); self._redraw()

    def set_active(self, active: bool):
        self._active = bool(active)
        self._last_size=(0,0)
        self._redraw()

    def _background_crop(self):
        image=self._app._background_image
        if image is None: return None
        self._app._ensure_background_cache()
        fitted=self._app._background_fitted
        root_w, root_h = fitted.size
        x=max(0,self.winfo_rootx()-self._app.winfo_rootx()); y=max(0,self.winfo_rooty()-self._app.winfo_rooty())
        w=max(self.winfo_width(),2); h=max(self.winfo_height(),2)
        if x >= root_w or y >= root_h:
            return None
        right=max(x+1,min(x+w,root_w)); bottom=max(y+1,min(y+h,root_h))
        crop=fitted.crop((x,y,right,bottom))
        if crop.size!=(w,h):
            canvas=Image.new("RGB",(w,h)); canvas.paste(crop,(0,0)); crop=canvas
        return crop

    def _redraw(self):
        if not self.winfo_exists() or self._redrawing:
            return
        w,h=max(self.winfo_width(),2),max(self.winfo_height(),2)
        if (w,h)==self._last_size and self._photo is not None:
            return
        self._redrawing=True
        self._last_size=(w,h)
        base=self._background_crop()
        if base is None: base=Image.new("RGB",(w,h),"#0a1930")
        base=base.convert("RGBA")
        # Blend into the actual page background. Only hover/active states add
        # a light glass wash; idle buttons carry no visible rectangle.
        tint_alpha=34 if self._active else (16 if self._hover else 0)
        glass=Image.alpha_composite(base,Image.new("RGBA",base.size,(4,23,43,tint_alpha)))
        self._photo=ImageTk.PhotoImage(glass)
        try:
            self.configure(image=self._photo, text=self._text,
                           foreground="#ffffff" if (self._active or self._hover) else "#e3f4ff")
        finally:
            self._redrawing=False

def _validate_target_binding(requested: Path, report: dict[str, object]) -> None:
    """Reject any audit result that is not for the exact target the UI requested."""
    expected = requested.expanduser().resolve()
    target_info = report.get("target", {}) if isinstance(report, dict) else {}
    actual_raw = target_info.get("path") if isinstance(target_info, dict) else None
    if not actual_raw:
        raise RuntimeError("Target binding violation: audit report has no target path.")
    actual = Path(str(actual_raw)).expanduser().resolve()
    if actual != expected:
        raise RuntimeError(
            f"Target binding violation: requested={expected} reported={actual}"
        )


class AtlasApp(tk.Tk):
    def __init__(self, initial_target: Path | None = None) -> None:
        super().__init__()
        self.title("ATLAS — Web3 Security Research OS")
        screen_w = max(self.winfo_screenwidth(), 1180)
        screen_h = max(self.winfo_screenheight(), 740)
        window_w = min(1540, screen_w - 24)
        window_h = min(940, screen_h - 56)
        window_w = max(window_w, 1180)
        window_h = max(window_h, 740)
        self.geometry(f"{window_w}x{window_h}+0+0")
        self.minsize(1180, 740)
        self.configure(bg="#06121f")
        self.repo = discover_repo()
        self.initial_target = initial_target
        # Dashboard metrics stay at zero until a real user-triggered operation runs.
        # Repository history remains readable elsewhere without becoming fake live counters.
        self.session_active = bool(initial_target)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="atlas-worker")
        self.busy = False
        self.task_name = ""
        self.last_audit: dict[str, object] = {}
        self.visible_findings: list[dict[str, object]] = []
        self.finding_filter_var = None
        self.current_target: Path | None = None
        self.current_target_report: dict[str, object] = {}
        self.current_report_path: Path | None = None
        self.task_started: float | None = None
        self.job_history: list[dict[str, object]] = []
        self.progress_value = 0
        self.progress_target = 0
        self.progress_caption = "READY"
        self.progress_animation_id = None
        self.cancel_event = threading.Event()
        self.ui_event_queue: queue.Queue[tuple] = queue.Queue()
        self.current_future = None
        self._current_page_name = ""
        self._page_scroll = 0
        self._page_max_scroll = 0
        self._build_shell()
        self._build_pages()
        self._set_repo(self.repo)
        if self.initial_target:
            self._set_current_target(self.initial_target)
        # Never restore or execute a previously selected target on GUI startup.
        # Target restoration is an explicit user action via LOAD SAVED TARGET REPORT.
        self.show_page("Dashboard")
        self.status.set(
            "READY — target selected; no audit started automatically"
            if self.initial_target
            else "READY — no target audit starts automatically"
        )
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(250, self.refresh_views)
        self.after(2500, self._live_refresh_tick)



    def _background_asset(self) -> Path | None:
        candidates = [
            resource_path("backgrounds/atlas_forest.jpg"),
            resource_path("backgrounds/atlas_forest.png"),
            Path.home() / "Downloads" / "Sans titre.jpg",
        ]
        return next((path for path in candidates if path.is_file()), None)

    def _init_background(self) -> None:
        self._background_source = self._background_asset()
        self._background_image = None
        self._background_surfaces: list[tuple[tk.Widget, tk.Label]] = []
        self._background_cache_size = (0, 0)
        self._background_fitted = None
        self._background_redraw_after = None
        self._background_draw_queue = []
        self._background_draw_after = None
        if self._background_source is None:
            return
        try:
            self._background_image = Image.open(self._background_source).convert("RGB")
        except (OSError, ValueError):
            self._background_image = None

    def _apply_background(self, widget: tk.Widget) -> None:
        if self._background_image is None:
            return
        surface = tk.Label(widget, bd=0, highlightthickness=0)
        surface.place(x=0, y=0, relwidth=1, relheight=1)
        surface.lower()
        self._background_surfaces.append((widget, surface))
        self._schedule_background_redraw()

    def _ensure_background_cache(self) -> None:
        if self._background_image is None:
            return
        root_w = max(self.winfo_width(), 1)
        root_h = max(self.winfo_height(), 1)
        if self._background_cache_size == (root_w, root_h) and self._background_fitted is not None:
            return
        fitted = ImageOps.fit(
            self._background_image, (root_w, root_h),
            method=Image.Resampling.LANCZOS, centering=(0.5, 0.5)
        ).convert("RGBA")
        self._background_fitted = Image.alpha_composite(
            fitted, Image.new("RGBA", fitted.size, (4, 23, 43, 77))
        )
        self._background_cache_size = (root_w, root_h)

    def _schedule_background_redraw(self, _event=None) -> None:
        if self._background_image is None or not self.winfo_exists():
            return
        if self._background_redraw_after is not None:
            try:
                self.after_cancel(self._background_redraw_after)
            except tk.TclError:
                pass
        self._background_redraw_after = self.after(60, self._redraw_visible_backgrounds)

    def _redraw_visible_backgrounds(self) -> None:
        self._background_redraw_after = None
        if self._background_image is None:
            return
        self._ensure_background_cache()
        self._background_draw_queue = [
            pair for pair in self._background_surfaces
            if pair[0].winfo_exists() and pair[0].winfo_ismapped()
        ]
        self._redraw_next_background()

    def _redraw_next_background(self) -> None:
        if self._background_draw_queue:
            widget, surface = self._background_draw_queue.pop(0)
            self._render_surface(widget, surface)
            self._background_draw_after = self.after_idle(self._redraw_next_background)
            return
        self._background_draw_after = None

    def _render_surface(self, widget: tk.Widget, surface: tk.Label) -> None:
        if self._background_fitted is None:
            return
        fitted = self._background_fitted
        root_w, root_h = fitted.size
        x = max(0, widget.winfo_rootx() - self.winfo_rootx())
        y = max(0, widget.winfo_rooty() - self.winfo_rooty())
        width = max(widget.winfo_width(), 2)
        height = max(widget.winfo_height(), 2)
        if x >= root_w or y >= root_h:
            return
        right = max(x + 1, min(x + width, root_w))
        bottom = max(y + 1, min(y + height, root_h))
        crop = fitted.crop((x, y, right, bottom))
        if crop.size != (width, height):
            canvas = Image.new("RGBA", (width, height), (7, 18, 29, 255))
            canvas.paste(crop, (0, 0))
            crop = canvas
        photo = ImageTk.PhotoImage(crop)
        surface.configure(image=photo)
        surface._atlas_photo = photo

    def _build_shell(self) -> None:
        self.configure(bg="#050b15")
        self._init_background()
        self.bind("<Configure>", self._schedule_background_redraw, add="+")
        self.sidebar = tk.Frame(self, bg="#081D56")
        self.sidebar.place(x=16, y=16, width=222, relheight=1, height=-32)
        self._apply_background(self.sidebar)
        self.brand = tk.Label(self.sidebar, text="ATLAS", fg="#ffffff", bg="#081D56",
                              font=("Segoe UI", 25, "bold"), anchor="w")
        self.brand.pack(fill="x", padx=20, pady=(20, 0))
        tk.Label(self.sidebar, text=APP_TAGLINE.upper(), fg="#8bbfe3", bg="#081D56",
                 font=("Segoe UI", 8, "bold"), anchor="w").pack(fill="x", padx=21, pady=(0, 10))
        # Scrollable navigation without a visible scrollbar. The canvas itself
        # carries the continuous glass background; buttons are direct windows
        # on it so there is no opaque inner Frame hiding the forest.
        self.nav_view = tk.Canvas(self.sidebar, bg="#081D56", bd=0, highlightthickness=0)
        self.nav_view.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.nav_window_ids: list[int] = []
        self._nav_content_height = 0
        self.nav_view.bind("<Configure>", self._nav_configure, add="+")
        self.bind_all("<MouseWheel>", self._mousewheel, add="+")
        self.bind_all("<Button-4>", self._mousewheel, add="+")
        self.bind_all("<Button-5>", self._mousewheel, add="+")
        self.pages: dict[str, tk.Frame] = {}
        self.nav_buttons: dict[str, tk.Button] = {}
        nav = [
            ("Dashboard", "\u2302"), ("Import / Intake", "\u21e7"), ("Research Runs", "\u25b6"),
            ("Audit Findings", "\u26a0"), ("Evidence Fabric", "\u25ce"), ("Cases", "\u25a3"),
            ("Knowledge Graph", "\u2318"), ("Differential", "\u21c4"), ("Negative Knowledge", "\u2298"),
            ("Research Intelligence", "\u25c9"), ("Temporal Ledger", "\u25f7"), ("Promotion", "\u2197"),
            ("Protocol Versions", "\u25c7"), ("Reports", "\u2261"), ("Settings", "\u2699"),
        ]
        y = 4
        for name, icon in nav:
            btn = GlassButton(
                self.nav_view, f"{icon}  {name}", lambda n=name: self.show_page(n), self,
                font=("Segoe UI", 10), height=42, padx=14,
            )
            item_id = self.nav_view.create_window((0, y), window=btn, anchor="nw",
                                                  height=42, width=190)
            self.nav_window_ids.append(item_id)
            self.nav_buttons[name] = btn
            y += 46
        self._nav_content_height = y + 4
        self.nav_view.configure(scrollregion=(0, 0, 1, self._nav_content_height))
        tk.Label(self.sidebar, text="RESEARCH WORKSPACE", fg="#6fa9d0", bg="#081D56",
                 font=("Segoe UI", 8, "bold")).pack(side="bottom", padx=20, pady=(0, 18), anchor="w")
        self.main = tk.Frame(self, bg="#050b15")
        self.main.place(x=254, y=16, relwidth=1, width=-270, relheight=1, height=-32)
        self._apply_background(self.main)
        top = tk.Frame(self.main, bg="#081D56")
        top.pack(fill="x", pady=(0, 12), ipady=4)
        self.repo_var = tk.StringVar()
        tk.Label(top, text="REPOSITORY", fg="#7fb5db", bg="#081D56",
                 font=("Segoe UI", 8, "bold")).pack(side="left", padx=(15, 7), pady=10)
        # Reserve the action area first so the expanding repository field can never push controls off-screen.
        # Fixed compact action rail: only the four top buttons are constrained here.
        actions = tk.Frame(top, bg="#081D56", bd=0, highlightthickness=0, width=354, height=34)
        actions.pack(side="right", padx=(4, 4))
        actions.pack_propagate(False)
        self._top_button(actions, "CHOOSE TARGET", self.choose_target, 0, 2, 78)
        self._top_button(actions, "AUDIT", self.audit_selected, 82, 2, 50)
        self._top_button(actions, "FULL REFRESH", self.full_refresh, 140, 2, 92)
        self.stop_button = self._top_button(actions, "STOP", self.stop_current_task, 238, 2, 54)
        self._top_button(actions, "SETTINGS", lambda: self.show_page("Settings"), 300, 2, 54)
        repo_entry = tk.Entry(top, textvariable=self.repo_var, bg="#081D56", fg="#f3fbff",
                 insertbackground="#46F0D2", relief="flat", font=("Segoe UI", 9), highlightthickness=0)
        repo_entry.pack(side="left", fill="x", expand=True, ipady=7)
        status_row = tk.Frame(self.main, bg="#050b15")
        self._apply_background(status_row)
        status_row.pack(fill="x", pady=(0, 5))
        self.status = tk.StringVar(value="ATLAS ready")
        tk.Label(status_row, textvariable=self.status, fg="#a9c8de", bg="#050b15",
                 font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
        self.progress_caption_label = tk.Label(
            status_row, text="READY", fg="#6f92a5", bg="#050b15",
            font=("Segoe UI", 8), anchor="e"
        )
        self.progress_caption_label.pack(side="right", padx=(8, 10))
        self.spinner = tk.Label(status_row, text="\u25cf", fg="#46F0D2", bg="#050b15",
                                font=("Segoe UI", 9))
        self.spinner.pack(side="right", padx=(0, 2))
        self.progress_percent = tk.Label(status_row, text="0%", fg="#62AAE5", bg="#050b15",
                                         font=("Segoe UI", 9, "bold"))
        self.progress_percent.pack(side="right", padx=(0, 8))
        self.progress = tk.Canvas(self.main, height=3, bg="#101a28", highlightthickness=0)
        self.progress.pack(fill="x", pady=(0, 12))
        self.progress_base = self.progress.create_rectangle(0, 1, 0, 2, fill="#17304b", outline="")
        self.progress_id = self.progress.create_rectangle(0, 1, 0, 2, fill="#46F0D2", outline="")
        self.progress.bind("<Configure>", lambda _e: self._refresh_progress_line())
        self.content = tk.Frame(self.main, bg="#050b15")
        self.content.pack(fill="both", expand=True)
        self._apply_background(self.content)
        self.content.bind("<Configure>", lambda _e: self.after_idle(self._reflow_page), add="+")

    def _nav_configure(self, event=None) -> None:
        width = max(1, self.nav_view.winfo_width())
        for item_id in getattr(self, "nav_window_ids", []):
            self.nav_view.itemconfigure(item_id, width=width)
        self.nav_view.configure(
            scrollregion=(0, 0, width, max(self._nav_content_height, self.nav_view.winfo_height()))
        )
        self._redraw_nav_surface()

    def _redraw_nav_surface(self) -> None:
        if self._background_image is None or not self.nav_view.winfo_exists():
            return
        self._ensure_background_cache()
        fitted = self._background_fitted
        root_w, root_h = fitted.size
        x = max(0, self.nav_view.winfo_rootx() - self.winfo_rootx())
        y = max(0, self.nav_view.winfo_rooty() - self.winfo_rooty())
        w = max(self.nav_view.winfo_width(), 2)
        h = max(self.nav_view.winfo_height(), 2)
        if x >= root_w or y >= root_h:
            return
        right = max(x + 1, min(x + w, root_w))
        bottom = max(y + 1, min(y + h, root_h))
        crop = fitted.crop((x, y, right, bottom))
        if crop.size != (w, h):
            canvas = Image.new("RGBA", (w, h), (7, 18, 29, 255))
            canvas.paste(crop, (0, 0)); crop = canvas
        glass = Image.alpha_composite(crop, Image.new("RGBA", crop.size, (4, 23, 43, 77)))
        self._nav_photo = ImageTk.PhotoImage(glass)
        self.nav_view.delete("nav-bg")
        self.nav_view.create_image(0, 0, anchor="nw", image=self._nav_photo, tags=("nav-bg",))
        items = self.nav_view.find_all()
        if len(items) > 1:
            self.nav_view.tag_lower("nav-bg", items[1])

    def _mousewheel(self, event) -> None:
        """Route the physical wheel to navigation or the current page."""
        widget = getattr(event, "widget", None)
        if widget is None:
            try:
                widget = self.winfo_containing(event.x_root, event.y_root)
            except tk.TclError:
                widget = None
        if widget is None:
            return

        # Navigation has its own scroll region.
        if self._is_descendant(widget, self.nav_view):
            if hasattr(event, "delta") and event.delta:
                steps = -int(event.delta / 120) or (-1 if event.delta < 0 else 1)
            else:
                steps = 1 if getattr(event, "num", None) == 5 else -1
            self.nav_view.yview_scroll(steps, "units")
            return "break"

        # Native text/list controls keep their own wheel behavior.
        if isinstance(widget, (tk.Text, tk.Listbox)):
            return

        # Everything else inside the working area scrolls the current page.
        if self._is_descendant(widget, self.content):
            if hasattr(event, "delta") and event.delta:
                steps = -int(event.delta / 120) or (-1 if event.delta < 0 else 1)
            else:
                steps = 1 if getattr(event, "num", None) == 5 else -1
            self._scroll_page(steps)
            return "break"
    def _top_button(self, parent: tk.Frame, text: str, command, x: int, y: int, width: int) -> GlassButton:
        # Top-bar buttons are deliberately ~65% of the previous visual height.
        btn=GlassButton(parent, text, command, self, font=("Segoe UI", 7, "bold"), height=20, padx=3)
        btn.place(x=x, y=y, width=width, height=28)
        return btn

    def _build_pages(self) -> None:
        names = ["Dashboard", "Import / Intake", "Research Runs", "Audit Findings", "Evidence Fabric",
                 "Cases", "Knowledge Graph", "Differential", "Negative Knowledge",
                 "Research Intelligence", "Temporal Ledger", "Promotion", "Protocol Versions",
                 "Reports", "Settings"]
        for name in names:
            frame = tk.Frame(self.content, bg="#06121f")
            self.pages[name] = frame
            self._apply_background(frame)
        self._dashboard_page()
        self._intake_page()
        self._research_runs_page()
        self._audit_findings_page()
        self._evidence_fabric_page()
        self._cases_page()
        self._differential_page()
        self._negative_knowledge_page()
        self._reports_pages()
        self._settings_page()
    def show_page(self, name: str) -> None:
        for frame in self.pages.values():
            frame.place_forget()
        self._current_page_name = name
        self._page_scroll = 0
        self._page_max_scroll = 0
        page = self.pages[name]
        page.place(relx=0, rely=0, relwidth=1, height=max(self.content.winfo_height(), 1), y=0)
        for key, btn in self.nav_buttons.items():
            btn.set_active(key == name)
        self.status.set(f"ATLAS - {name}")
        self.after_idle(self._reflow_page)

    def _reflow_page(self) -> None:
        name = self._current_page_name
        if not name or name not in self.pages or not self.content.winfo_exists():
            return
        page = self.pages[name]
        page.update_idletasks()
        viewport_h = max(self.content.winfo_height(), 1)
        requested_h = max(page.winfo_reqheight(), viewport_h)
        self._page_max_scroll = max(0, requested_h - viewport_h)
        self._page_scroll = min(self._page_scroll, self._page_max_scroll)
        page.place(relx=0, rely=0, relwidth=1, height=requested_h, y=-self._page_scroll)

    def _scroll_page(self, steps: int) -> None:
        if self._page_max_scroll <= 0:
            self._reflow_page()
            if self._page_max_scroll <= 0:
                return
        self._page_scroll = max(0, min(self._page_max_scroll, self._page_scroll + steps * 42))
        page = self.pages.get(self._current_page_name)
        if page is not None:
            page.place_configure(y=-self._page_scroll)
        self._schedule_background_redraw()

    def _is_descendant(self, widget: tk.Widget | None, ancestor: tk.Widget) -> bool:
        """Return True when widget is ancestor or nested below it."""
        current = widget
        while current is not None:
            if current is ancestor:
                return True
            try:
                parent_path = current.winfo_parent()
                if not parent_path:
                    break
                current = self.nametowidget(parent_path)
            except (tk.TclError, KeyError, AttributeError):
                break
        return False

    def _panel(self, parent: tk.Frame, title: str, subtitle: str | None = None, **layout) -> tk.Frame:
        # Open-surface layout: panels are typographic groups, not boxes.
        panel = tk.Frame(parent, bg="#06121f", highlightthickness=0, bd=0)
        self._apply_background(panel)
        if "row" in layout or "column" in layout or "sticky" in layout:
            panel.grid(**layout)
        else:
            panel.pack(**layout)
        head = tk.Frame(panel, bg="#06121f", highlightthickness=0, bd=0)
        self._apply_background(head)
        head.pack(fill="x", padx=2, pady=(8, 10))
        tk.Label(head, text=title.upper(), fg="#dceeff", bg="#06121f",
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        if subtitle:
            tk.Label(head, text=subtitle, fg="#62AAE5", bg="#06121f",
                     font=("Segoe UI", 7, "bold")).pack(side="right")
        tk.Frame(panel, bg="#17304b", height=1).pack(fill="x", padx=2, pady=(0, 8))
        return panel

    def _card(self, parent: tk.Frame, title: str, key: str, column: int, row: int = 0) -> None:
        # Metric clusters intentionally have no enclosing card/frame.
        cluster = tk.Frame(parent, bg="#050b15", bd=0, highlightthickness=0)
        self._apply_background(cluster)
        cluster.grid(row=row, column=column, sticky="nsew", padx=(0, 22), pady=(3, 12))
        tk.Label(cluster, text=title.upper(), fg="#6fa9d0", bg="#050b15",
                 font=("Segoe UI", 7, "bold")).pack(anchor="w")
        value = tk.Label(cluster, text="0", fg="#f4fbff", bg="#050b15",
                         font=("Segoe UI", 27, "bold"))
        value.pack(anchor="w", pady=(2, 1))
        meta = tk.Frame(cluster, bg="#050b15", height=1)
        meta.pack(fill="x", pady=(2, 0))
        tk.Frame(meta, bg="#46F0D2", height=1, width=28).pack(side="left", anchor="w")
        tk.Frame(meta, bg="#17304b", height=1).pack(side="left", fill="x", expand=True, padx=(6, 0))
        setattr(self, f"card_{key}", value)

    def _dashboard_page(self) -> None:
        page = self.pages["Dashboard"]
        header = tk.Frame(page, bg="#050b15")
        header.pack(fill="x")
        tk.Label(header, text="Command Center", fg="#f4fbff", bg="#050b15",
                 font=("Segoe UI", 22, "bold")).pack(side="left")
        tk.Label(header, text="Evidence  ->  Analysis  ->  Research  ->  Knowledge", fg="#6fa9d0",
                 bg="#050b15", font=("Segoe UI", 9)).pack(side="left", padx=16, pady=(8, 0))
        cards = tk.Frame(page, bg="#050b15")
        cards.pack(fill="x", pady=(18, 18))
        for i in range(4):
            cards.columnconfigure(i, weight=1, uniform="metric")
        metrics = [
            ("Target Source Files", "target_files"), ("Target Contracts", "target_contracts"), ("Target Functions", "target_functions"), ("Target Findings", "target_findings"),
            ("Engine Findings", "engine_findings"), ("Research Cases", "research_cases"), ("Research Candidates", "research_candidates"), ("Research Nodes", "research_nodes"),
        ]
        for i, item in enumerate(metrics):
            self._card(cards, item[0], item[1], i % 4, i // 4)
        body = tk.Frame(page, bg="#050b15")
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=3)
        body.rowconfigure(1, weight=1)
        self.current_target_panel = self._panel(body, "Current Target", "TARGET-DERIVED", row=1, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        self.current_target_text = tk.Label(self.current_target_panel, text="NO TARGET SELECTED", fg="#b9d8e4", bg="#06121f", justify="left", anchor="nw", font=("Consolas", 9))
        self.current_target_text.pack(fill="both", expand=True, padx=14, pady=12)
        self._dashboard_system(body)
        self._dashboard_activity(body)

    def _dashboard_system(self, parent: tk.Frame) -> None:
        panel = self._panel(parent, "System Overview", "LIVE STATE", row=0, column=0, sticky="nsew", padx=(0, 5))
        self.system_lines = tk.Frame(panel, bg="#06121f")
        self.system_lines.pack(fill="both", expand=True, padx=12, pady=8)
        self.system_checks: dict[str, tuple[tk.Label, tk.Label]] = {}
        labels = ["Knowledge Graph", "Temporal Ledger", "Federation Layer", "Research Intelligence",
                  "Promotion Engine", "Protocol Versions", "Audit & Validation"]
        for label in labels:
            row = tk.Frame(self.system_lines, bg="#06121f")
            row.pack(fill="x", pady=6)
            check = tk.Label(row, text="●", fg="#7b91a1", bg="#06121f", font=("Segoe UI", 10))
            check.pack(side="left", padx=(2, 8))
            text_label = tk.Label(row, text=label, fg="#d8ecf5", bg="#06121f",
                                  font=("Segoe UI", 9, "bold"), anchor="w")
            text_label.pack(side="left")
            state = tk.Label(row, text="EMPTY", fg="#7b91a1", bg="#06121f",
                             font=("Segoe UI", 8, "bold"), anchor="e")
            state.pack(side="right")
            self.system_checks[label] = (check, state)
        tk.Label(panel, text="System state is derived from the ATLAS repository. Historical metrics are labeled as historical; current-target figures come only from the selected target audit.",
                 fg="#66899d", bg="#06121f", justify="left", wraplength=430,
                 font=("Segoe UI", 8)).pack(fill="x", padx=14, pady=(8, 14))


    def _dashboard_activity(self, parent: tk.Frame) -> None:
        pane = tk.Frame(parent, bg="#06121f")
        self._apply_background(pane)
        pane.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        pane.rowconfigure(0, weight=1)
        pane.rowconfigure(1, weight=1)
        pane.columnconfigure(0, weight=1)
        quick = self._panel(pane, "Quick Actions", "READY", row=0, column=0, sticky="nsew")
        grid = tk.Frame(quick, bg="#06121f")
        self._apply_background(grid)
        grid.pack(fill="both", expand=True, padx=10, pady=8)
        actions = [
            ("IMPORT CONTRACT / REPOSITORY", self.open_import),
            ("AUDIT", self.audit_selected),
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
        self.activity_log = ScrolledText(activity, bg="#07121d", fg="#b8d4df",
                                         insertbackground="#ffffff", relief="flat",
                                         font=("Consolas", 9), height=8)
        self.activity_log.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(activity, self.activity_log)
    def _intake_page(self) -> None:
        page = self.pages["Import / Intake"]
        tk.Label(page, text="Contract Intake", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(page, text="Load source files, ZIP/TAR archives, or a complete contract repository.",
                 fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 10))
        toolbar = tk.Frame(page, bg="#06121f", highlightthickness=0)
        self._apply_background(toolbar)
        toolbar.pack(fill="x", pady=(0, 8), ipady=6)
        self.target_var = tk.StringVar()
        self.active_target_label = tk.Label(page, text="ACTIVE TARGET  ·  NONE",
                                             fg="#46F0D2", bg="#06121f", font=("Segoe UI", 8, "bold"),
                                             anchor="w")
        self.active_target_label.pack(fill="x", pady=(0, 6))
        tk.Entry(toolbar, textvariable=self.target_var, bg="#091a29", fg="#e8f7ff",
                 insertbackground="#ffffff", relief="flat", highlightthickness=0).pack(side="left", fill="x", expand=True, padx=10, ipady=7)
        self._toolbar_button(toolbar, "FILES", self.choose_files)
        self._toolbar_button(toolbar, "ZIP / ARCHIVE", self.choose_archive)
        self._toolbar_button(toolbar, "DIRECTORY", self.choose_directory)
        self._toolbar_button(toolbar, "AUDIT TARGET", self.audit_target)
        self._toolbar_button(toolbar, "REGISTER", self.register_target)
        tk.Label(page, text="Accepted: all file types are importable. Known smart-contract ecosystems are classified; "
                 "unknown/binary files are safely inventoried by hash rather than guessed.",
                 fg="#6f92a5", bg="#06121f", font=("Segoe UI", 8), justify="left").pack(anchor="w", pady=(0, 8))

        body = tk.Frame(page, bg="#06121f")
        self._apply_background(body)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)
        left = self._panel(body, "Historical Intakes", "HASHED", row=0, column=0, sticky="nsew", padx=(0, 5))
        right = self._panel(body, "Intake Snapshot", "STRUCTURAL", row=0, column=1, sticky="nsew", padx=(5, 0))
        self.intake_tree = tk.Listbox(left, bg="#07121d", fg="#b9d8e4", relief="flat",
                                      selectbackground="#12496a", selectforeground="#ffffff",
                                      font=("Consolas", 9))
        self.intake_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.intake_tree.bind("<<ListboxSelect>>", self._intake_selected)
        self.intake_detail = ScrolledText(right, bg="#07121d", fg="#b9d8e4",
                                          insertbackground="#ffffff", relief="flat",
                                          font=("Consolas", 9))
        self.intake_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(right, self.intake_detail)
    def _action_button(self, parent: tk.Frame, text: str, command) -> GlassButton:
        return GlassButton(
            parent, text, command, self,
            font=("Segoe UI", 9, "bold"), height=42, padx=12,
        )

    def _toolbar_button(self, parent: tk.Frame, text: str, command) -> GlassButton:
        return GlassButton(
            parent, text, command, self,
            font=("Segoe UI", 8, "bold"), height=34, padx=10,
        )

    def _copy_widget(self, widget: tk.Text) -> None:
        try:
            text = widget.get("1.0", "end-1c")
        except tk.TclError:
            text = ""
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        self.status.set(f"Copied {len(text)} characters to clipboard.")

    def _copy_button(self, parent: tk.Widget, widget: tk.Text) -> tk.Button:
        button = tk.Button(
            parent, text="COPY", command=lambda: self._copy_widget(widget),
            bg="#0b2940", fg="#bfeeff", activebackground="#12496a",
            activeforeground="#ffffff", relief="flat", bd=0,
            font=("Segoe UI", 8, "bold"), cursor="hand2",
        )
        button.pack(anchor="e", padx=10, pady=(0, 7))
        return button

    def _intake_selected(self, _event=None) -> None:
        if not self.intake_tree.curselection():
            return
        index = self.intake_tree.curselection()[0]
        items = list_intakes(self.repo) if self.repo else []
        if 0 <= index < len(items):
            self.intake_detail.delete("1.0", "end")
            self.intake_detail.insert("end", pretty(items[index]))


    def _set_current_target(self, target: Path) -> Path:
        target = target.expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        self.current_target = target
        save_target_state(target)
        self.title(f"{APP_NAME} — {APP_TAGLINE} — {target.name}")
        if hasattr(self, "target_var"):
            self.target_var.set(str(target))
        if hasattr(self, "active_target_label"):
            self.active_target_label.configure(text=f"ACTIVE TARGET  ·  {target.name}")
        if hasattr(self, "finding_target_label"):
            self.finding_target_label.configure(text=f"TARGET  ·  {target}")
        self._refresh_cases_target_banner()
        return target

    def _refresh_cases_target_banner(self) -> None:
        # Use __dict__ so lightweight test doubles without a Tk root do not invoke
        # tkinter's recursive __getattr__ while checking optional widgets.
        label = self.__dict__.get("cases_target_label")
        detail = self.__dict__.get("cases_target_detail")
        if label is None or detail is None:
            return
        target = self.current_target
        report = self.current_target_report if isinstance(self.current_target_report, dict) else {}
        summary = report.get("summary", {}) if isinstance(report.get("summary", {}), dict) else {}
        if target is None:
            label.configure(text="CURRENT TARGET  ·  NONE")
            detail.configure(text="No target selected.")
            return
        if not report:
            label.configure(text=f"CURRENT TARGET  ·  {target.name}  ·  AUDIT NOT RUN")
            detail.configure(
                text=f"{target}  ·  select AUDIT TARGET to execute a fresh target-bound analysis."
            )
            return
        supporting = summary.get("supporting_finding_count", 0)
        label.configure(text=f"CURRENT TARGET  ·  {target.name}  ·  AUDIT READY")
        detail.configure(text=(
            f"{target}  ·  SOURCE FILES {summary.get('source_file_count', 0)}  ·  "
            f"CONTRACTS {summary.get('contract_count', 0)}  ·  FUNCTIONS {summary.get('function_count', 0)}  ·  "
            f"PRIMARY FINDINGS {summary.get('finding_count', 0)}  ·  SUPPORTING EVIDENCE {supporting}  ·  "
            f"ENGINE FINDINGS {summary.get('engine_finding_count', 0)}"
        ))

    def _copy_current_target_report(self) -> None:
        report = self.current_target_report if isinstance(self.current_target_report, dict) else self.last_audit
        self.clipboard_clear()
        self.clipboard_append(pretty(report) if report else "NO TARGET AUDIT RESULT")
        self.update_idletasks()
        self.status.set("Copied current target audit report to clipboard.")

    def _clear_target_result(self) -> None:
        self.last_audit = {}
        self.visible_findings = []
        self.current_target_report = {}
        self.current_report_path = None
        if self.current_target:
            save_target_state(self.current_target)
        if hasattr(self, "finding_tree"):
            self.finding_tree.delete(0, "end")
        if hasattr(self, "supporting_tree"):
            self.supporting_tree.delete(0, "end")
        if hasattr(self, "finding_detail"):
            self.finding_detail.delete("1.0", "end")

    def choose_target(self) -> None:
        """Open the real target picker; archives must remain visible/selectable."""
        path = filedialog.askopenfilename(
            title="Choose ATLAS target",
            filetypes=[
                ("All supported inputs", "*.zip *.tar *.tgz *.tar.gz *.tar.bz2 *.tar.xz *.7z *.rar *.sol *.vy *.rs *.move *.cairo *.go *.ts *.js *.json *.yaml *.yml *.*"),
                ("Archives", "*.zip *.tar *.tgz *.tar.gz *.tar.bz2 *.tar.xz *.7z *.rar"),
                ("All files", "*.*"),
            ],
        )
        if path:
            target = self._set_current_target(Path(path))
            self._clear_target_result()
            self.show_page("Import / Intake")
            self.status.set(
                f"Target selected - {target.name}. No audit was executed. "
                "Press AUDIT TARGET when you are ready."
            )


    def choose_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Load contract files / artifacts",
            filetypes=[
                ("All supported inputs", "*.zip *.tar *.tgz *.tar.gz *.tar.bz2 *.tar.xz *.7z *.rar *.sol *.vy *.rs *.move *.cairo *.go *.ts *.js *.json *.yaml *.yml *.*"),
                ("Archives", "*.zip *.tar *.tgz *.tar.gz *.tar.bz2 *.tar.xz *.7z *.rar"),
                ("All files", "*.*"),
            ],
        )
        if not paths:
            return
        self._stage_files([Path(x) for x in paths])


    def choose_archive(self) -> None:
        path = filedialog.askopenfilename(
            title="Load archive",
            filetypes=[("Archives", "*.zip *.tar *.tgz *.tar.gz *.tar.bz2 *.tar.xz *.7z *.rar"), ("All files", "*.*")]
        )
        if path:
            target = self._set_current_target(Path(path))
            self._clear_target_result()
            self.show_page("Import / Intake")
            self.status.set(
                f"Archive selected - {target.name}. No audit was executed. "
                "Press AUDIT TARGET when you are ready."
            )


    def choose_directory(self) -> None:
        path = filedialog.askdirectory(title="Load contract repository")
        if path:
            target = self._set_current_target(Path(path))
            self._clear_target_result()
            self.show_page("Import / Intake")
            self.status.set(
                f"Repository selected as target - {target.name}. No audit was executed. "
                "Press AUDIT TARGET when you are ready."
            )

    def _research_runs_page(self) -> None:
        page = self.pages["Research Runs"]
        tk.Label(page, text="Research Runs", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(page, text="Durable run IDs, checkpoints, cancellation state, and resumable research history.",
                 fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))
        toolbar = tk.Frame(page, bg="#06121f")
        toolbar.pack(fill="x", pady=(0, 8))
        self._toolbar_button(toolbar, "REFRESH RUNS", self.refresh_views)
        self._toolbar_button(toolbar, "RESUME SELECTED", self.resume_selected_run)
        body = tk.Frame(page, bg="#06121f")
        self._apply_background(body)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)
        left = self._panel(body, "Runs", "PERSISTENT", row=0, column=0, sticky="nsew", padx=(0, 5))
        right = self._panel(body, "Checkpoint Detail", "REPLAYABLE", row=0, column=1, sticky="nsew", padx=(5, 0))
        self.run_tree = tk.Listbox(left, bg="#07121d", fg="#b9d8e4", relief="flat",
                                   selectbackground="#12496a", selectforeground="#ffffff", font=("Consolas", 9))
        self.run_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.run_tree.bind("<<ListboxSelect>>", self._run_selected)
        self.run_detail = ScrolledText(right, bg="#07121d", fg="#b9d8e4", insertbackground="#ffffff",
                                       relief="flat", font=("Consolas", 9))
        self.run_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(right, self.run_detail)

    def _run_selected(self, _event=None) -> None:
        if not self.run_tree.curselection():
            return
        index = self.run_tree.curselection()[0]
        runs = self._list_all_run_states()
        if 0 <= index < len(runs):
            self.run_detail.delete("1.0", "end")
            self.run_detail.insert("end", pretty(runs[index]))

    def _list_all_run_states(self) -> list[dict[str, object]]:
        if not self.repo:
            return []
        base = self.repo / "runs"
        values = []
        for path in sorted(base.glob("*/state.json")) if base.exists() else []:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                values.append(value)
        return sorted(values, key=lambda item: str(item.get("updated_at", "")), reverse=True)

    def resume_selected_run(self) -> None:
        if self.busy or not self.repo or not self.run_tree.curselection():
            return
        index = self.run_tree.curselection()[0]
        runs = self._list_all_run_states()
        if not (0 <= index < len(runs)):
            return
        run_id = str(runs[index].get("run_id", "")).strip()
        if not run_id:
            return
        self._run_task(
            "RESUME RUN",
            lambda: resume_audit_run(self.repo, run_id, self._progress_callback, self.cancel_event.is_set),
        )

    def _evidence_fabric_page(self) -> None:
        page = self.pages["Evidence Fabric"]
        tk.Label(page, text="Evidence Fabric", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(page, text="No evidence stage can silently promote the next stage.",
                 fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))
        self.evidence_summary = tk.Label(page, text="NO AUDIT EVIDENCE",
                                         fg="#62AAE5", bg="#06121f", font=("Segoe UI", 9, "bold"))
        self.evidence_summary.pack(anchor="w", pady=(0, 8))
        body = self._panel(page, "Finding Chains", "STAGE-GATED", fill="both", expand=True)
        self.evidence_detail = ScrolledText(body, bg="#07121d", fg="#b9d8e4",
                                            insertbackground="#ffffff", relief="flat", font=("Consolas", 9))
        self.evidence_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(body, self.evidence_detail)

    def _differential_page(self) -> None:
        page = self.pages["Differential"]
        tk.Label(page, text="Differential Security", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(page, text="Revision A ↔ Revision B: source, structure, findings, and execution-domain changes.",
                 fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))
        body = tk.Frame(page, bg="#06121f")
        self._apply_background(body)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)
        left = self._panel(body, "Revision Diffs", "RECORDED", row=0, column=0, sticky="nsew", padx=(0, 5))
        right = self._panel(body, "Diff Detail", "EXPLICIT", row=0, column=1, sticky="nsew", padx=(5, 0))
        self.diff_tree = tk.Listbox(left, bg="#07121d", fg="#b9d8e4", relief="flat",
                                    selectbackground="#12496a", selectforeground="#ffffff", font=("Consolas", 8))
        self.diff_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.diff_tree.bind("<<ListboxSelect>>", self._diff_selected)
        self.diff_detail = ScrolledText(right, bg="#07121d", fg="#b9d8e4", relief="flat", font=("Consolas", 8))
        self.diff_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(right, self.diff_detail)

    def _diff_selected(self, _event=None) -> None:
        if not self.diff_tree.curselection() or not self.repo:
            return
        paths = sorted((self.repo / "reports" / "differential").glob("*.json"))
        index = self.diff_tree.curselection()[0]
        if 0 <= index < len(paths):
            self.diff_detail.delete("1.0", "end")
            self.diff_detail.insert("end", pretty(read_report(self.repo, str(paths[index].relative_to(self.repo)), {})))

    def _negative_knowledge_page(self) -> None:
        page = self.pages["Negative Knowledge"]
        tk.Label(page, text="Negative Knowledge", fg="#f2fbff", bg="#06121f",
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(page, text="Failed proof attempts stay queryable with environment, input space, and explored-state context.",
                 fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 8))
        body = tk.Frame(page, bg="#06121f")
        self._apply_background(body)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)
        left = self._panel(body, "Negative Results", "MEMORY", row=0, column=0, sticky="nsew", padx=(0, 5))
        right = self._panel(body, "Attempt Detail", "WHY NOT PROVED", row=0, column=1, sticky="nsew", padx=(5, 0))
        self.negative_tree = tk.Listbox(left, bg="#07121d", fg="#b9d8e4", relief="flat",
                                        selectbackground="#12496a", selectforeground="#ffffff", font=("Consolas", 8))
        self.negative_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.negative_tree.bind("<<ListboxSelect>>", self._negative_selected)
        self.negative_detail = ScrolledText(right, bg="#07121d", fg="#b9d8e4", relief="flat", font=("Consolas", 8))
        self.negative_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(right, self.negative_detail)

    def _negative_selected(self, _event=None) -> None:
        if not self.negative_tree.curselection() or not self.repo:
            return
        values = load_negative_results(self.repo)
        index = self.negative_tree.curselection()[0]
        if 0 <= index < len(values):
            self.negative_detail.delete("1.0", "end")
            self.negative_detail.insert("end", pretty(values[index]))


    def _audit_findings_page(self) -> None:
        page = self.pages["Audit Findings"]
        tk.Label(page, text="Audit Findings", fg="#f2fbff", bg="#06121f", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        self.finding_target_label = tk.Label(page, text="TARGET  ·  NONE", fg="#46F0D2", bg="#06121f", font=("Segoe UI", 8, "bold"), anchor="w")
        self.finding_target_label.pack(fill="x", pady=(0, 3))
        tk.Label(page, text="Deterministic review leads · not automatic proof of exploitability", fg="#7193a7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 6))
        audit_actions = tk.Frame(page, bg="#06121f"); audit_actions.pack(fill="x", pady=(0, 4))
        self._toolbar_button(audit_actions, "VERIFY SELECTED FINDING", self.verify_selected_finding)
        self._toolbar_button(audit_actions, "LOAD SAVED TARGET REPORT", self.load_saved_target_report)
        self._toolbar_button(audit_actions, "COPY CURRENT TARGET REPORT", self._copy_current_target_report)
        filter_bar = tk.Frame(page, bg="#06121f")
        filter_bar.pack(fill="x", pady=(0, 8))
        tk.Label(
            filter_bar,
            text="VIEW",
            fg="#8fb5c8",
            bg="#06121f",
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(0, 6))
        self.finding_filter_var = tk.StringVar(value="VERIFY_FIRST")
        menu = tk.OptionMenu(
            filter_bar,
            self.finding_filter_var,
            "VERIFY_FIRST",
            "DEEP_REVIEW",
            "CONTEXT",
            "VERIFIED",
            "ALL",
            command=lambda _value: self._render_findings(),
        )
        menu.configure(
            bg="#0b2940",
            fg="#bfeeff",
            activebackground="#12496a",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=("Segoe UI", 8, "bold"),
        )
        menu["menu"].configure(
            bg="#07121d",
            fg="#b9d8e4",
            activebackground="#12496a",
            activeforeground="#ffffff",
        )
        menu.pack(side="left")
        self.finding_lane_summary = tk.Label(
            filter_bar,
            text="NO TARGET FINDINGS",
            fg="#7193a7",
            bg="#06121f",
            font=("Consolas", 8),
            anchor="w",
        )
        self.finding_lane_summary.pack(side="left", padx=10)
        body = tk.Frame(page, bg="#06121f"); self._apply_background(body); body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1); body.columnconfigure(1, weight=2); body.rowconfigure(0, weight=1)
        left = self._panel(
            body,
            "Findings + Supporting Evidence",
            "PRODUCTION / SUPPORTING",
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 5),
        )
        right = self._panel(body, "Finding Detail", "EVIDENCE", row=0, column=1, sticky="nsew", padx=(5, 0))
        tk.Label(
            left,
            text="PRIMARY FINDINGS - production attack surface",
            fg="#d6efff",
            bg="#07121d",
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        ).pack(fill="x", padx=10, pady=(8, 3))
        self.finding_tree = tk.Listbox(
            left,
            bg="#07121d",
            fg="#c3dce7",
            selectbackground="#6b2b38",
            selectforeground="#ffffff",
            relief="flat",
            font=("Consolas", 9),
            height=12,
        )
        self.finding_tree.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.finding_tree.bind("<<ListboxSelect>>", self._finding_selected)
        tk.Label(
            left,
            text="SUPPORTING EVIDENCE - Rust/tests/fuzz/bench/tooling retained for context",
            fg="#8fb5c8",
            bg="#07121d",
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        ).pack(fill="x", padx=10, pady=(4, 3))
        self.supporting_tree = tk.Listbox(
            left,
            bg="#07121d",
            fg="#94b5c4",
            selectbackground="#12496a",
            selectforeground="#ffffff",
            relief="flat",
            font=("Consolas", 8),
            height=10,
        )
        self.supporting_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.supporting_tree.bind("<<ListboxSelect>>", self._supporting_selected)
        self.finding_detail = ScrolledText(right, bg="#07121d", fg="#b9d8e4", insertbackground="#ffffff", relief="flat", font=("Consolas", 9))
        self.finding_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(right, self.finding_detail)


    def load_cases(self) -> None:
        if not self.repo:
            return
        try:
            cases = summarize_cases(query_cases(self.repo, CaseQuery(text=self.case_query.get().strip() or None)))
            self.case_tree.delete(0, "end")
            for case in cases:
                self.case_tree.insert("end", f"{case.get('id')}  ·  {case.get('status')}  ·  {case.get('stage')}  ·  {case.get('title')}")
            self.status.set(f"Reference cases loaded · {len(cases)} records")
        except Exception as exc:
            self.status.set(f"Case search failed · {exc}")

    def _cases_page(self) -> None:
        page = self.pages["Cases"]
        tk.Label(page, text="Research Cases", fg="#f2fbff", bg="#06121f", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        target = tk.Frame(page, bg="#07121d", highlightthickness=1, highlightbackground="#163b55")
        target.pack(fill="x", pady=(8, 8))
        self.cases_target_label = tk.Label(target, text="CURRENT TARGET  ·  NONE", fg="#46F0D2", bg="#07121d", font=("Segoe UI", 9, "bold"), anchor="w")
        self.cases_target_label.pack(fill="x", padx=12, pady=(9, 2))
        self.cases_target_detail = tk.Label(target, text="No target selected.", fg="#b9d8e4", bg="#07121d", font=("Consolas", 9), justify="left", anchor="w")
        self.cases_target_detail.pack(fill="x", padx=12, pady=(0, 8))
        actions = tk.Frame(target, bg="#07121d"); actions.pack(fill="x", padx=8, pady=(0, 7))
        self._toolbar_button(actions, "VIEW AUDIT FINDINGS", lambda: self.show_page("Audit Findings"))
        self._toolbar_button(actions, "COPY TARGET REPORT", self._copy_current_target_report)
        top = tk.Frame(page, bg="#06121f"); top.pack(fill="x", pady=(0, 8)); self.case_query = tk.StringVar()
        tk.Entry(top, textvariable=self.case_query, bg="#091a29", fg="#e8f7ff", insertbackground="#ffffff", relief="flat").pack(side="left", fill="x", expand=True, padx=10, ipady=8)
        self._toolbar_button(top, "SEARCH REFERENCE CASES", self.load_cases)
        body = self._panel(page, "REFERENCE CASE CORPUS", "REPOSITORY RECORDS · NOT CURRENT TARGET FINDINGS", fill="both", expand=True)
        self.case_tree = tk.Listbox(body, bg="#07121d", fg="#c0dbe6", relief="flat", selectbackground="#12496a", selectforeground="#ffffff", font=("Consolas", 9))
        self.case_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._refresh_cases_target_banner()

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
            widget = ScrolledText(text, bg="#07121d", fg="#b9d8e4", insertbackground="#ffffff",
                                  relief="flat", font=("Consolas", 9))
            widget.pack(fill="both", expand=True, padx=10, pady=10)
            self._copy_button(text, widget)
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
        self.graph_nodes = tk.Listbox(nodes, bg="#07121d", fg="#b9d8e4", relief="flat",
                                      font=("Consolas", 8))
        self.graph_nodes.pack(fill="both", expand=True, padx=10, pady=10)
        self.graph_edges = ScrolledText(edges, bg="#07121d", fg="#b9d8e4", relief="flat",
                                        font=("Consolas", 8))
        self.graph_edges.pack(fill="both", expand=True, padx=10, pady=10)
        self._copy_button(edges, self.graph_edges)

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
                 fg="#88a7b7", bg="#06121f", font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=14)
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
        # The dashboard reflects the real selected repository immediately.
        # An explicit target audit remains distinct from the repository audit.
        self.session_active = bool(self.repo)
        self.repo_var.set(str(self.repo) if self.repo else "No repository selected")
        if not self.repo:
            self._reset_dashboard_metrics()
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
        self._set_current_target(stage)
        self._clear_target_result()
        self.show_page("Import / Intake")
        self.status.set(
            f"{len(paths)} file(s) staged as the current target. "
            "No audit was executed. Press AUDIT TARGET when you are ready."
        )


    def _start_initial_target_audit(self, target: Path) -> None:
        if not target.exists():
            self.status.set("Initial target does not exist.")
            return
        target = self._set_current_target(target)
        self._clear_target_result()
        self.show_page("Import / Intake")
        self._run_task("AUDIT TARGET", lambda: self._audit_target_worker(target), switch_to_import=True)


    def start_target_import(self, target: Path) -> None:
        if not target.exists():
            self.status.set("Import target does not exist.")
            return
        target = self._set_current_target(target)
        self._clear_target_result()
        self.show_page("Import / Intake")
        self.status.set(f"Import queued · {target.name}")
        self._run_task("IMPORT", lambda: self._import_target(target))


    def _import_target(self, target: Path) -> dict[str, object]:
        if not self.repo:
            raise RuntimeError("Choose the ATLAS research repository first.")
        report = build_intake(target, self._progress_callback, self.cancel_event.is_set)
        path = write_intake_report(self.repo, report)
        return {"report": report, "report_path": str(path)}


    def register_target(self) -> None:
        raw = self.target_var.get().strip()
        if raw:
            self.start_target_import(Path(raw).expanduser())


    def audit_selected(self) -> None:
        """Top-level AUDIT follows the selected target; otherwise audit the repository."""
        raw = self.target_var.get().strip()
        if raw:
            target = Path(raw).expanduser()
            if target.exists():
                self.audit_target()
                return
            self.status.set("Selected target does not exist.")
            return
        self.audit_repo()


    def audit_target(self) -> None:
        raw = self.target_var.get().strip()
        if not raw:
            self.status.set("Select a contract file, archive, or repository first.")
            return
        target = self._set_current_target(Path(raw).expanduser())
        self._clear_target_result()
        self.show_page("Import / Intake")
        self._run_task("AUDIT TARGET", lambda: self._audit_target_worker(target), switch_to_import=True)


    def _restore_saved_target(self) -> None:
        if not self.repo:
            return
        try:
            state = json.loads(target_state_path().read_text(encoding="utf-8"))
            target = Path(str(state.get("target", ""))).expanduser()
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return
        if not target.exists():
            clear_target_state()
            return
        # Startup may remember which target the user last selected, but it must never
        # re-run or re-activate a previous audit implicitly. Reports are loaded only by
        # an explicit user action.
        self._set_current_target(target)
        self.current_target_report = {}
        self.last_audit = {}
        self.current_report_path = None
        self.status.set(
            f"Target restored without executing an audit - {target.name}. "
            "Run AUDIT TARGET explicitly when you want a new result."
        )

    def load_saved_target_report(self) -> None:
        if not self.repo:
            self.status.set("Choose the ATLAS research repository first.")
            return
        try:
            state = json.loads(target_state_path().read_text(encoding="utf-8"))
            raw_target = state.get("target")
            raw_report = state.get("report_path")
            saved_target = Path(str(raw_target)).expanduser() if raw_target else None
            report_path = Path(str(raw_report)).expanduser() if raw_report else None
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            saved_target = None
            report_path = None
        if self.current_target is None and saved_target is not None and saved_target.exists():
            self._set_current_target(saved_target)
        if self.current_target is None:
            self.status.set("No saved target is available.")
            return
        if not report_path or not report_path.exists() or not self._report_matches_target(report_path, self.current_target):
            self.status.set("No saved audit report matches the current target.")
            return
        report = (
            read_report(self.repo, str(report_path.relative_to(self.repo)), {})
            if report_path.is_relative_to(self.repo) else {}
        )
        if not isinstance(report, dict) or not report.get("target"):
            self.status.set("Saved target report could not be loaded.")
            return
        self.current_target_report = report
        self.last_audit = report
        self.current_report_path = report_path
        self._apply_target_report(report)
        self._write_result_to_page("AUDIT TARGET", {"report": report, "report_path": str(report_path)})
        self.status.set(f"Loaded saved audit report - {report_path.name}")

    @staticmethod
    def _report_matches_target(report_path: Path, target: Path) -> bool:
        try:
            value = json.loads(report_path.read_text(encoding="utf-8"))
            actual = Path(str(value.get("target", {}).get("path", ""))).expanduser().resolve()
            return actual == target.expanduser().resolve()
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return False


    def _audit_target_worker(self, target: Path) -> dict[str, object]:
        if not self.repo:
            raise RuntimeError("Choose the ATLAS research repository first.")
        report = build_contract_audit(target, self.repo, self._progress_callback, self.cancel_event.is_set)
        _validate_target_binding(target, report)
        path = write_contract_audit(self.repo, report)
        return {"report": report, "report_path": str(path)}


    def _finding_is_verified(self, finding: dict[str, object]) -> bool:
        verification = finding.get("verification", {})
        if not isinstance(verification, dict):
            return False
        gates = verification.get("gates", {})
        return isinstance(gates, dict) and bool(gates.get("reproduction"))

    def _render_findings(self) -> None:
        if not hasattr(self, "finding_tree") or not isinstance(self.last_audit, dict):
            return
        findings = self.last_audit.get("findings", [])
        findings = [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []
        selected = str(self.finding_filter_var.get()) if self.finding_filter_var is not None else "ALL"
        if selected == "VERIFIED":
            visible = [x for x in findings if self._finding_is_verified(x)]
        elif selected == "ALL":
            visible = findings
        else:
            visible = [x for x in findings if str(x.get("triage_lane") or "CONTEXT") == selected]
        self.visible_findings = visible
        self.finding_tree.delete(0, "end")
        for finding in visible:
            score = int(finding.get("triage_score") or 0)
            status = str(finding.get("status", "candidate")).upper()
            lane = str(finding.get("triage_lane") or "CONTEXT").upper()
            grade = str((finding.get("verification") or {}).get("evidence_grade", "E")).upper()
            self.finding_tree.insert(
                "end",
                f"[{status[:10]:10}] [{lane[:10]:10}] G{grade} S{score:02} "
                f"{finding.get('file')}:{finding.get('line')} · {finding.get('signal')}"
            )
        from collections import Counter
        counts = Counter(str(x.get("triage_lane") or "CONTEXT") for x in findings)
        verified = sum(1 for x in findings if self._finding_is_verified(x))
        summary = (
            f"VERIFY_FIRST={counts.get('VERIFY_FIRST', 0)}  "
            f"DEEP_REVIEW={counts.get('DEEP_REVIEW', 0)}  "
            f"CONTEXT={counts.get('CONTEXT', 0)}  "
            f"VERIFIED={verified}  SHOWING={len(visible)}/{len(findings)}"
        )
        if hasattr(self, "finding_lane_summary"):
            self.finding_lane_summary.configure(text=summary)

    def _selected_finding(self) -> dict[str, object] | None:
        if not self.finding_tree.curselection() or not self.visible_findings:
            return None
        index = self.finding_tree.curselection()[0]
        return self.visible_findings[index] if 0 <= index < len(self.visible_findings) else None

    def _finding_selected(self, _event=None) -> None:
        finding = self._selected_finding()
        if finding is None:
            return
        if hasattr(self, "supporting_tree"):
            self.supporting_tree.selection_clear(0, "end")
        self.finding_detail.delete("1.0", "end")
        self.finding_detail.insert("end", pretty(finding))

    def _supporting_selected(self, _event=None) -> None:
        if not self.supporting_tree.curselection() or not isinstance(self.last_audit, dict):
            return
        items = self.last_audit.get("supporting_evidence", [])
        index = self.supporting_tree.curselection()[0]
        if not isinstance(items, list) or not (0 <= index < len(items)):
            return
        if hasattr(self, "finding_tree"):
            self.finding_tree.selection_clear(0, "end")
        self.finding_detail.delete("1.0", "end")
        self.finding_detail.insert("end", pretty(items[index]))

    def verify_selected_finding(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            messagebox.showinfo("ATLAS verification", "Select a finding first.")
            return
        if not self.current_target or not self.current_report_path:
            messagebox.showinfo(
                "ATLAS verification",
                "Run an explicit target audit first so ATLAS has a pinned report and target.",
            )
            return
        reproducer_path = None
        suggested = suggested_command(self.current_target)
        target_suffix = self.current_target.suffix.lower()
        if suggested is None and target_suffix in {".sol", ".rs"}:
            is_solidity = target_suffix == ".sol"
            target_label = "Solidity" if is_solidity else "Rust"
            reproducer_glob = "*.sol" if is_solidity else "*.rs"
            harness = (
                "Foundry harness around an exact copy of the contract"
                if is_solidity else
                "Cargo harness around an exact copy of the Rust source"
            )
            use_reproducer = messagebox.askyesno(
                "ATLAS verification",
                f"The selected {target_label} file is standalone (no native project was detected).\n\n"
                f"Attach a local reproducer so ATLAS can build an isolated {harness}?",
                parent=self,
            )
            if use_reproducer:
                chosen = filedialog.askopenfilename(
                    title=f"Choose {target_label} reproducer",
                    filetypes=[(f"{target_label} files", reproducer_glob), ("All files", "*.*")],
                )
                if chosen:
                    reproducer_path = Path(chosen).resolve()
                    suggested = suggested_command(self.current_target, reproducer_path)
        initial_command = " ".join(suggested) if suggested else (
            "forge test --offline -vv"
            if str(finding.get("language", "")).lower() == "solidity"
            else "cargo test --workspace --offline"
            if str(finding.get("language", "")).lower() == "rust"
            else ""
        )
        command_text = simpledialog.askstring(
            "ATLAS · Verify finding",
            "Local verification command (test/build only):",
            initialvalue=initial_command,
            parent=self,
        )
        if not command_text:
            return
        expected_exit = simpledialog.askinteger(
            "ATLAS · Expected result",
            "Expected process exit code:",
            initialvalue=0,
            minvalue=0,
            maxvalue=255,
            parent=self,
        )
        if expected_exit is None:
            return
        mode = simpledialog.askstring(
            "ATLAS · Verification mode",
            "Mode: baseline or reproduction",
            initialvalue="reproduction",
            parent=self,
        )
        mode = (mode or "reproduction").strip().lower()
        if mode not in {"baseline", "reproduction"}:
            messagebox.showerror("ATLAS verification", "Mode must be baseline or reproduction.")
            return
        baseline_expected_exit = 0
        if mode == "reproduction":
            baseline_expected_exit = simpledialog.askinteger(
                "ATLAS �� Baseline health",
                "Expected exit code for the clean target BEFORE adding the reproducer:",
                initialvalue=0,
                minvalue=0,
                maxvalue=255,
                parent=self,
            )
            if baseline_expected_exit is None:
                return
        property_text = simpledialog.askstring(
            "ATLAS · Security property",
            "State the security property this test is intended to prove/disprove:",
            initialvalue=str(finding.get("title") or finding.get("signal") or "").strip(),
            parent=self,
        )
        if not property_text:
            return
        try:
            command = split_command(command_text)
        except ValueError as exc:
            messagebox.showerror("ATLAS verification", str(exc))
            return
        trust_target = messagebox.askyesno(
            "ATLAS · Verification execution trust",
            "The test runner may execute target-controlled code such as tests, build scripts, "
            "or proc-macros. On this Windows machine ATLAS does not provide OS-level sandboxing.\n\n"
            "Choose YES only when you trust the selected target and its test/build toolchain. "
            "Choose NO to cancel this execution.\n\n"
            "The original target is still copied to a disposable workspace; this switch explicitly "
            "authorizes running that copy with your user privileges.",
            parent=self,
        )
        if not trust_target:
            return
        confirm = messagebox.askyesno(
            "ATLAS · Execute verification",
            "ATLAS will make an isolated copy of the selected target and execute only "
            "the approved local test/build command there. The original target is not modified.\n\n"
            f"Command: {' '.join(command)}\n"
            f"Mode: {mode}\n"
            f"Expected exit: {expected_exit}\n"
            f"Baseline expected exit: {baseline_expected_exit}\n\n"
            "For reproduction, ATLAS first runs the clean target. A non-clean baseline makes "
            "the result INCONCLUSIVE; only then is the reproducer executed on a fresh copy.\n\n"
            "A reproduced result is evidence for the security-property gate; an ordinary "
            "passing test is not, by itself, proof that the finding is false.",
            parent=self,
        )
        if not confirm:
            return
        payload = {
            "target": self.current_target,
            "finding": finding,
            "command": command,
            "expected_exit": expected_exit,
            "mode": mode,
            "baseline_expected_exit": baseline_expected_exit,
            "security_property": property_text,
            "reproducer": str(reproducer_path) if reproducer_path else None,
            "trusted_target_code": trust_target,
        }
        self._run_task(
            "VERIFY FINDING",
            lambda: self._verify_finding_worker(payload),
        )

    def _verify_finding_worker(self, payload: dict[str, object]) -> dict[str, object]:
        if not self.repo:
            raise RuntimeError("Choose the ATLAS research repository first.")
        target = Path(str(payload["target"])).expanduser().resolve()
        finding = payload["finding"]
        result = run_verification(
            target,
            finding if isinstance(finding, dict) else {},
            payload["command"],
            expected_exit=int(payload["expected_exit"]),
            mode=str(payload["mode"]),
            baseline_expected_exit=int(payload.get("baseline_expected_exit", 0)),
            security_property=str(payload["security_property"]),
            timeout_seconds=300,
            reproducer=(
                Path(str(payload["reproducer"])).expanduser().resolve()
                if payload.get("reproducer") else None
            ),
            trusted_target_code=bool(payload.get("trusted_target_code")),
        )
        result_path = write_verification_result(
            self.repo,
            result,
            report_path=self.current_report_path,
        )
        return {"verification": result.as_dict(), "result_path": str(result_path)}

    def open_report(self, relative: str) -> None:
        if not self.repo:
            return
        path = self.repo / relative
        if path.exists():
            os.startfile(path)
        else:
            self.status.set(f"Report not found · {relative}")
    def audit_repo(self) -> None:
        """Run the repository audit bound to the canonical ATLAS repository.

        Target/contract auditing remains available through the Import / Intake
        flow; the top-level AUDIT action must always have one unambiguous job.
        """
        if not self.repo:
            self.status.set("Choose a repository first.")
            return
        self.show_page("Audit Findings")
        self._run_task(
            "AUDIT REPOSITORY",
            lambda: audit_repo(self.repo, self._progress_callback, self.cancel_event.is_set),
        )


    def full_refresh(self) -> None:
        if not self.repo:
            self.status.set("Choose a repository first.")
            return
        self._run_task("FULL REFRESH", self._full_refresh_worker)


    def _raise_if_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise OperationCancelled("ATLAS operation cancelled")

    def _full_refresh_worker(self) -> dict[str, object]:
        root = self.repo
        result: dict[str, object] = {}
        self._raise_if_cancelled()
        self._progress_callback(5, "Starting full refresh")

        federation = build_federation_snapshot(root)
        write_federation_snapshot(root); write_candidate_snapshot(root)
        result["federation"] = federation
        self._raise_if_cancelled()
        self._progress_callback(14, "Federation snapshot complete")

        result["research"] = build_research_metrics(root)
        write_longitudinal_report(root)
        self._raise_if_cancelled()
        self._progress_callback(24, "Research intelligence complete")

        result["chronicle"] = build_chronicle(root)
        write_chronicle(root)
        self._raise_if_cancelled()
        self._progress_callback(34, "Temporal chronicle complete")

        result["history"] = build_temporal_timeline(root)
        write_temporal_history(root)
        self._raise_if_cancelled()
        self._progress_callback(44, "Temporal history complete")

        result["domain"] = build_domain_evolution(root)
        write_domain_evolution(root)
        self._raise_if_cancelled()
        self._progress_callback(54, "Domain evolution complete")

        result["versions"] = build_version_diff_report(root)
        write_version_diff_report(root)
        self._raise_if_cancelled()
        self._progress_callback(64, "Protocol versions complete")

        result["promotion"] = build_promotion_engine(root)
        write_promotion_report(root)
        self._raise_if_cancelled()
        self._progress_callback(74, "Promotion gates complete")

        result["audit"] = audit_repo(
            root,
            lambda percent, caption="": self._progress_callback(
                74 + int(max(0, min(100, int(percent))) * 0.26),
                caption or "Repository audit",
            ),
            self.cancel_event.is_set,
        )
        self._progress_callback(100, "Full refresh complete")
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
        self.cancel_event.clear()
        self.current_future = None
        self.stop_button.configure(state="normal")
        self.task_started = datetime.now().timestamp()
        self.progress_target = 1
        if self.progress_animation_id is not None:
            try:
                self.after_cancel(self.progress_animation_id)
            except Exception:
                pass
            self.progress_animation_id = None
        self._set_progress(1, "Starting")
        self.progress_target = max(self.progress_target, 1)
        self._animate_progress()
        self.status.set(f"{name} - running in background - ATLAS remains usable")
        self.spinner.configure(text="●", fg="#62AAE5")
        self._log(f"[{self._clock()}] START  {name}")
        def guarded_task():
            value = fn()
            self._raise_if_cancelled()
            return value

        future = self.executor.submit(guarded_task)
        self.current_future = future

        def waiter():
            try:
                value = future.result()
                self.ui_event_queue.put(("done", name, value))
            except (OperationCancelled, CancelledError) as exc:
                self.ui_event_queue.put(("cancelled", name, str(exc) or "ATLAS operation cancelled"))
            except Exception as exc:
                detail = traceback.format_exc()
                self.ui_event_queue.put(("failed", name, exc, detail))

        threading.Thread(target=waiter, daemon=True, name=f"atlas-{name.lower()}-waiter").start()
        self.after(50, self._drain_ui_events)

    def _set_progress(self, percent: int, caption: str = "") -> None:
        self.progress_value = max(0, min(100, int(percent)))
        if caption:
            self.progress_caption = caption
        if hasattr(self, "progress_caption_label"):
            self.progress_caption_label.configure(text=self.progress_caption.upper())
        if hasattr(self, "progress_percent"):
            self.progress_percent.configure(text=f"{self.progress_value}%")
        if hasattr(self, "progress") and self.progress.winfo_exists():
            self._refresh_progress_line()

    def _progress_callback(self, percent: int, caption: str = "") -> None:
        """Queue real worker progress for consumption by the Tk main thread."""
        target = max(1, min(99, int(percent)))
        self.ui_event_queue.put(("progress", target, caption))

    def _drain_ui_events(self) -> None:
        """Apply worker events on the Tk thread; never call Tk from worker threads."""
        terminal = False
        while True:
            try:
                event = self.ui_event_queue.get_nowait()
            except queue.Empty:
                break
            kind = event[0]
            if kind == "progress":
                _, target, caption = event
                self.progress_target = max(self.progress_target, target)
                if caption:
                    self.progress_caption = caption
                if self.busy and self.progress_animation_id is None:
                    self._animate_progress()
            elif kind == "done":
                _, name, value = event
                self._task_done(name, value)
                terminal = True
            elif kind == "cancelled":
                _, name, detail = event
                self._task_cancelled(name, detail)
                terminal = True
            elif kind == "failed":
                _, name, exc, detail = event
                self._task_failed(name, exc, detail)
                terminal = True
        if self.busy and not terminal:
            self.after(50, self._drain_ui_events)


    def _animate_progress(self) -> None:
        target = self.progress_target
        if not self.busy:
            self.progress_animation_id = None
            return
        # Move exactly one percentage point at a time toward the latest real worker checkpoint.
        # 100% is written only by the completion handler, so the UI never lies about completion.
        if self.progress_value < target:
            self._set_progress(min(target, self.progress_value + 1))
        if self.progress_value < target:
            self.progress_animation_id = self.after(100, self._animate_progress)
        else:
            self.progress_animation_id = None

    def _refresh_progress_line(self) -> None:
        if not hasattr(self, "progress"):
            return
        width = max(1, self.progress.winfo_width())
        self.progress.coords(self.progress_base, 0, 1, width, 2)
        fill = int(width * (self.progress_value / 100.0))
        self.progress.coords(self.progress_id, 0, 1, max(0, fill), 2)

    def stop_current_task(self) -> None:
        if not self.busy:
            self.status.set("No ATLAS operation is running.")
            return
        self.cancel_event.set()
        self.progress_caption = "Stopping"
        self.status.set(f"{self.task_name} - STOP requested - waiting for safe cancellation point")
        self.progress_caption_label.configure(text="STOPPING")
        self.stop_button.configure(state="disabled")
        future = self.current_future
        if future is not None:
            future.cancel()

    def _task_cancelled(self, name: str, detail: str = "") -> None:
        self.busy = False
        self.current_future = None
        self.spinner.configure(text="●", fg="#e7a64b")
        self.stop_button.configure(state="normal")
        self.progress_target = self.progress_value
        self._set_progress(self.progress_value, "Cancelled")
        self.status.set(f"{name} - CANCELLED")
        self.job_history.append({
            "task": name, "status": "cancelled",
            "at": datetime.now(timezone.utc).isoformat(),
            "detail": detail,
        })
        self._log(f"[{self._clock()}] CANCEL {name} - {detail}")
        self.cancel_event.clear()

    def _task_done(self, name: str, value: object) -> None:
        self._set_progress(100, "Complete")
        self.busy = False
        self.current_future = None
        self.cancel_event.clear()
        self.stop_button.configure(state="normal")
        self.spinner.configure(text="●", fg="#46F0D2")
        elapsed = (datetime.now().timestamp() - self.task_started) if self.task_started else 0
        self.status.set(f"{name} - completed - {elapsed:.1f}s")
        self.job_history.append({"task": name, "status": "completed", "seconds": round(elapsed, 2),
                                 "at": datetime.now(timezone.utc).isoformat()})
        self._log(f"[{self._clock()}] DONE   {name} - {elapsed:.1f}s")
        self._write_result_to_page(name, value)
        self.refresh_views()

    def _task_failed(self, name: str, exc: Exception, detail: str) -> None:
        self.busy = False
        self.current_future = None
        self.cancel_event.clear()
        self.stop_button.configure(state="normal")
        self.spinner.configure(text="●", fg="#62AAE5")
        self._set_progress(0, "Failed")
        self.status.set(f"{name} - failed - details kept in ATLAS log")
        self.job_history.append({"task": name, "status": "failed", "error": str(exc),
                                 "at": datetime.now(timezone.utc).isoformat()})
        self._log(f"[{self._clock()}] FAIL   {name} - {exc}\n{detail}")
        self._write_result_to_page(name, {"error": str(exc), "traceback": detail})

    def _write_result_to_page(self, name: str, value: object) -> None:
        text = pretty(value)
        self.activity_log.insert("end", text + "\n\n")
        self.activity_log.see("end")
        self.last_result = value
        if name == "AUDIT TARGET":
            report = value.get("report", {}) if isinstance(value, dict) else {}
            self.session_active = True
            self.current_target_report = report
            self.last_audit = report
            self.current_report_path = Path(str(value.get("report_path"))) if value.get("report_path") else None
            target_info = report.get("target", {}) if isinstance(report, dict) else {}
            target_path = target_info.get("path") if isinstance(target_info, dict) else None
            if target_path:
                self._set_current_target(Path(str(target_path)))
            if self.current_target:
                save_target_state(self.current_target, self.current_report_path)
            self._apply_target_report(report)
            if hasattr(self, "supporting_tree"):
                self.supporting_tree.delete(0, "end")
                supporting = report.get("supporting_evidence", []) if isinstance(report, dict) else []
                for item in supporting:
                    if not isinstance(item, dict):
                        continue
                    scope_file = str(item.get("file") or "?")
                    line = item.get("line", "?")
                    signal = str(item.get("signal") or "evidence")
                    confidence = str(item.get("confidence") or "-")
                    self.supporting_tree.insert(
                        "end",
                        f"[{confidence[:4]:4}] {scope_file}:{line} · {signal}"
                    )
            self._render_findings()
            self.show_page("Audit Findings")
            self.finding_detail.delete("1.0", "end")
            self.finding_detail.insert("end", pretty(report))
        elif name == "IMPORT":
            report = value.get("report", {}) if isinstance(value, dict) else {}
            self.session_active = True
            self.current_target_report = report
            target_info = report.get("target", {}) if isinstance(report, dict) else {}
            target_path = target_info.get("path") if isinstance(target_info, dict) else None
            if target_path:
                self._set_current_target(Path(str(target_path)))
            self._apply_target_report(report)
            self.intake_detail.delete("1.0", "end")
            self.intake_detail.insert("end", pretty(report))
            self.show_page("Import / Intake")
        elif name == "AUDIT REPOSITORY":
            report = value if isinstance(value, dict) else {"result": value}
            self.last_audit = report
            self.finding_tree.delete(0, "end")
            if "error" in report:
                self.finding_tree.insert(0, "REPOSITORY AUDIT · FAILED")
            else:
                self.session_active = True
                status = "PASS" if report.get("ok") else "ATTENTION"
                self.finding_tree.insert(0, f"REPOSITORY AUDIT · {status}")
            self.finding_detail.delete("1.0", "end")
            self.finding_detail.insert("end", pretty(report))
            self.show_page("Audit Findings")
        elif name == "VERIFY FINDING":
            verification = value.get("verification", {}) if isinstance(value, dict) else {}
            updated_finding = None
            if isinstance(self.last_audit, dict) and isinstance(verification, dict):
                finding_id = str(verification.get("finding_id", ""))
                for index, finding in enumerate(self.last_audit.get("findings", [])):
                    if isinstance(finding, dict) and str(finding.get("id")) == finding_id:
                        finding.setdefault("verifications", []).append(verification)
                        updated_finding = attach_gate(finding)
                        self.last_audit["findings"][index] = updated_finding
                        break
                self.current_target_report = self.last_audit
                self._apply_target_report(self.last_audit)
            outcome = human_outcome(
                type("_VerificationView", (), {"outcome": str(verification.get("outcome", "unknown"))})()
            )
            grade = (
                str((updated_finding or {}).get("verification", {}).get("evidence_grade", "E")).upper()
                if updated_finding else "E"
            )
            self.status.set(f"VERIFY FINDING · {outcome} · GRADE {grade}")
            self.finding_detail.delete("1.0", "end")
            self.finding_detail.insert("end", pretty(value))
            self.show_page("Audit Findings")

        elif name == "FULL REFRESH":
            # An explicit repository operation starts the live research session.
            self.session_active = True
            self.status.set(f"{name} complete · live repository state loaded")


    def _log(self, line: str) -> None:
        if hasattr(self, "activity_log"):
            self.activity_log.insert("end", line.rstrip() + "\n")
            self.activity_log.see("end")


    @staticmethod
    def _clock() -> str:
        return datetime.now().strftime("%H:%M:%S")


    def _live_refresh_tick(self) -> None:
        if not self.winfo_exists():
            return
        self.refresh_views()
        self.after(2500, self._live_refresh_tick)


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
        federation = read_report(root, "reports/federation/snapshot.json", {})
        validation_errors = validate_repo(root)
        ledger_errors = verify_chain(root / "ledger" / "events.jsonl")
        cases = summarize_cases(query_cases(root, CaseQuery(text=self.case_query.get().strip() or None)))
        runs = self._list_all_run_states()
        negatives = load_negative_results(root)
        finding_records = []
        audit_dir = root / "reports" / "contract-audits"
        if audit_dir.exists():
            for path in sorted(audit_dir.glob("*.json")):
                value = read_report(root, str(path.relative_to(root)), {})
                if isinstance(value, dict):
                    finding_records.extend(
                        item for item in value.get("findings", []) if isinstance(item, dict)
                    )
        evidence_fabric = build_evidence_fabric(finding_records)
        diff_paths = sorted((root / "reports" / "differential").glob("*.json"))
        return {"inventory": inventory, "graph": graph, "cases": cases, "intakes": list_intakes(root),
                "intelligence": audit, "history": history, "versions": versions, "promotion": promotion,
                "federation": federation, "validation_errors": validation_errors, "ledger_errors": ledger_errors,
                "runs": runs, "negative_results": negatives, "evidence_fabric": evidence_fabric,
                "differential_paths": diff_paths}
    def _reset_dashboard_metrics(self) -> None:
        for key in ("target_files", "target_contracts", "target_functions", "target_findings", "engine_findings",
                    "research_cases", "research_candidates", "research_nodes"):
            widget = getattr(self, f"card_{key}", None)
            if widget is not None:
                widget.configure(text="0")

    def _apply_target_report(self, report: object) -> None:
        target = report if isinstance(report, dict) else {}
        target_info = target.get("target", {}) if isinstance(target.get("target", {}), dict) else {}
        target_summary = target.get("summary", {}) if isinstance(target.get("summary", {}), dict) else {}
        for key, value in (
            ("target_files", target_summary.get("source_file_count", 0)),
            ("target_contracts", target_summary.get("contract_count", 0)),
            ("target_functions", target_summary.get("function_count", 0)),
            ("target_findings", target_summary.get("finding_count", 0)),
            ("engine_findings", target_summary.get("engine_finding_count", 0)),
        ):
            widget = getattr(self, f"card_{key}", None)
            if widget is not None:
                widget.configure(text=str(value))
        target_path = target_info.get("path") or (str(self.current_target) if self.current_target else None)
        if hasattr(self, "current_target_text"):
            if target_path and not target:
                self.current_target_text.configure(
                    text=f"TARGET  {target_path}\\nAUDIT NOT RUN - press AUDIT TARGET to execute analysis."
                )
            elif target_path:
                self.current_target_text.configure(text=(
                    f"TARGET  {target_path}\\n"
                    f"SOURCE FILES  {target_summary.get('source_file_count', 0)}    "
                    f"CONTRACTS  {target_summary.get('contract_count', 0)}    "
                    f"FUNCTIONS  {target_summary.get('function_count', 0)}\\n"
                    f"PRIMARY FINDINGS  {target_summary.get('finding_count', 0)}    "
                    f"SUPPORTING EVIDENCE  {target_summary.get('supporting_finding_count', 0)}    "
                    f"ENGINE FINDINGS  {target_summary.get('engine_finding_count', 0)}"
                ))
            else:
                self.current_target_text.configure(
                    text="NO TARGET SELECTED\\nChoose a file, archive, or directory to start a target-bound audit."
                )

        self._refresh_cases_target_banner()

    def _apply_dashboard_metrics(self, inventory: object, graph: ResearchGraph, intakes: object, federation: object) -> None:
        if not isinstance(inventory, dict):
            self._reset_dashboard_metrics()
            return
        federation = federation if isinstance(federation, dict) else {}
        target = self.current_target_report if isinstance(self.current_target_report, dict) else {}
        self._apply_target_report(target)
        self.card_research_cases.configure(text=str(inventory.get("case_count", 0)))
        self.card_research_candidates.configure(text=str(federation.get("candidate_record_count", 0)))
        self.card_research_nodes.configure(text=str(len(graph.nodes)))

    def _apply_views(self, data: dict[str, object]) -> None:
        inventory = data["inventory"]
        graph: ResearchGraph = data["graph"]
        cases = data["cases"]
        intakes = data["intakes"]
        self._apply_dashboard_metrics(inventory, graph, intakes, data.get("federation"))
        validation_ok = not data.get("validation_errors")
        ledger_ok = not data.get("ledger_errors")
        federation = data.get("federation") or {}
        ledger_path = self.repo / "ledger" / "events.jsonl"
        states = {
            "Knowledge Graph": ("READY" if graph.nodes else "EMPTY", bool(graph.nodes)),
            "Temporal Ledger": ("OK" if ledger_path.exists() and ledger_ok else ("EMPTY" if not ledger_path.exists() else "FAILED"), bool(ledger_path.exists() and ledger_ok)),
            "Federation Layer": ("OK" if federation.get("federation_health") == "ok" else ("BLOCKED" if federation else "EMPTY"), federation.get("federation_health") == "ok"),
            "Research Intelligence": ("READY" if data.get("intelligence") else "EMPTY", bool(data.get("intelligence"))),
            "Promotion Engine": ("READY" if data.get("promotion") else "EMPTY", bool(data.get("promotion"))),
            "Protocol Versions": ("READY" if data.get("versions") else "EMPTY", bool(data.get("versions"))),
            "Audit & Validation": ("OK" if validation_ok and ledger_ok else "FAILED", validation_ok and ledger_ok),
        }
        for label, (state, ok) in states.items():
            dot, state_label = self.system_checks[label]
            if state == "EMPTY":
                tone = "#7b91a1"
            elif ok:
                tone = "#48dca8"
            else:
                tone = "#e7a64b"
            dot.configure(fg=tone)
            state_label.configure(text=state, fg=tone)
        # Cases page is target-facing. Reference cases are loaded only by SEARCH REFERENCE CASES,
        # so a repository refresh cannot overwrite the current target context with historical records.
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

        runs = data.get("runs", [])
        self.run_tree.delete(0, "end")
        for item in runs if isinstance(runs, list) else []:
            self.run_tree.insert(
                "end",
                f'{item.get("run_id")}  ·  {item.get("status")}  ·  last={item.get("last_completed_stage")}'
            )

        fabric = data.get("evidence_fabric") or {}
        self.evidence_summary.configure(
            text=(
                f'FINDINGS {fabric.get("finding_count", 0)}  ·  '
                f'VALIDATED {fabric.get("validated_count", 0)}  ·  '
                f'RESEARCH DEBT {fabric.get("research_debt_count", 0)}'
            )
        )
        self.evidence_detail.delete("1.0", "end")
        self.evidence_detail.insert("end", pretty(fabric))

        diff_paths = data.get("differential_paths", [])
        self.diff_tree.delete(0, "end")
        for path in diff_paths if isinstance(diff_paths, list) else []:
            self.diff_tree.insert("end", path.name)

        negatives = data.get("negative_results", [])
        self.negative_tree.delete(0, "end")
        for item in negatives if isinstance(negatives, list) else []:
            self.negative_tree.insert(
                "end",
                f'{item.get("id")}  ·  {item.get("tool")}  ·  states={item.get("explored_states", 0)}'
            )

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
        self.cancel_event.set()
        try:
            self.executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self.executor.shutdown(wait=False)
        self.destroy()


def _run_local_self_test_fixture(research_root: Path) -> dict[str, object]:
    """Exercise the audit pipeline on a disposable fixture, never on the user's repository."""
    with tempfile.TemporaryDirectory(prefix="atlas-self-test-") as td:
        fixture_root = Path(td)
        target = fixture_root / "Smoke.sol"
        target.write_text(
            "pragma solidity ^0.8.20; "
            "contract AtlasSelfTest { "
            "uint256 public x; "
            "function ping(uint256 v) external { x = v; } "
            "}",
            encoding="utf-8",
        )
        report = build_contract_audit(target, fixture_root)
        summary = report.get("summary", {}) if isinstance(report, dict) else {}
        return {
            "finding_count": int(summary.get("finding_count", 0)),
            "contract_count": int(summary.get("contract_count", 0)),
            "function_count": int(summary.get("function_count", 0)),
            "source_file_count": int(summary.get("source_file_count", 0)),
            "target_path": str(target),
        }


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
    try:
        fixture = _run_local_self_test_fixture(root)
        ResearchGraph.from_repo(root)
        build_inventory(root)
    except Exception as exc:
        log_file.write_text("SELF-TEST: fixture failed\n" + pretty({"error": repr(exc)}), encoding="utf-8")
        return 1
    log_file.write_text(
        "SELF-TEST: OK\n"
        f"fixture_contracts={fixture['contract_count']} "
        f"fixture_functions={fixture['function_count']} "
        f"fixture_findings={fixture['finding_count']}\n"
        "startup_target_audit=DISABLED\n",
        encoding="utf-8",
    )
    return 0


def startup_target(argv: list[str]) -> Path | None:
    if "--target" not in argv:
        return None
    index = argv.index("--target")
    if index + 1 >= len(argv):
        raise SystemExit("--target requires a path")
    target = Path(argv[index + 1]).expanduser()
    if not target.exists():
        raise SystemExit(f"--target does not exist: {target}")
    return target


def main() -> int:
    import sys
    if "--self-test" in sys.argv:
        return run_self_test()
    target = startup_target(sys.argv)
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
