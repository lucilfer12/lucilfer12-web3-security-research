"""Compatibility entry point for the ATLAS desktop application.

The runtime wrapper keeps the canonical UI implementation in atlas_ui while
ensuring a persisted target is actually audited on startup.
"""

import sys
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText

from .atlas_ui import (
    APP_NAME,
    APP_TAGLINE,
    AtlasApp as _AtlasApp,
    discover_repo,
    resource_path,
    run_self_test,
    save_repo,
    settings_path,
    crash_path,
)


class AtlasApp(_AtlasApp):
    def _restore_saved_target(self) -> None:
        super()._restore_saved_target()
        if self.current_target and not self.current_target_report:
            target = self.current_target
            self.after(500, lambda t=target: self._start_initial_target_audit(t))

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
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        activity = self._panel(
            pane, "Background Activity", "NO TERMINAL",
            row=1, column=0, sticky="nsew", pady=(8, 0),
        )
        self.activity_log = ScrolledText(
            activity, bg="#07121d", fg="#b8d4df",
            insertbackground="#ffffff", relief="flat",
            font=("Consolas", 9), height=8,
        )
        self.activity_log.pack(fill="both", expand=True, padx=10, pady=10)

        controls = tk.Frame(activity, bg="#06121f")
        controls.pack(anchor="e", padx=10, pady=(0, 7))
        tk.Button(
            controls, text="COPY",
            command=lambda: self._copy_widget(self.activity_log),
            bg="#0b2940", fg="#bfeeff", activebackground="#12496a",
            activeforeground="#ffffff", relief="flat", bd=0,
            font=("Segoe UI", 8, "bold"), cursor="hand2",
        ).pack(side="left", padx=4)
        self._download_button(controls, self.activity_log, "atlas-background-activity.txt")

    def _download_widget_txt(
        self, widget: tk.Text, default_name: str = "atlas-results.txt"
    ) -> Path | None:
        try:
            content = widget.get("1.0", "end-1c")
        except tk.TclError:
            content = ""
        if not content:
            self.status.set("Nothing to download.")
            return None
        path = filedialog.asksaveasfilename(
            title="Download results as TXT",
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return None
        destination = Path(path)
        try:
            destination.write_text(content, encoding="utf-8")
        except OSError as exc:
            self.status.set(f"TXT download failed: {exc}")
            return None
        self.status.set(f"Saved {len(content)} characters to {destination}")
        return destination

    def _download_button(
        self, parent: tk.Widget, widget: tk.Text, default_name: str
    ) -> tk.Button:
        button = tk.Button(
            parent, text="DOWNLOAD TXT",
            command=lambda: self._download_widget_txt(widget, default_name),
            bg="#0b2940", fg="#bfeeff", activebackground="#12496a",
            activeforeground="#ffffff", relief="flat", bd=0,
            font=("Segoe UI", 8, "bold"), cursor="hand2",
        )
        button.pack(side="left", padx=4)
        return button


def _show_target_scan_state(self, inventory, graph, intakes, federation) -> None:
    _AtlasApp._apply_dashboard_metrics(self, inventory, graph, intakes, federation)
    if self.current_target and not self.current_target_report and self.busy:
        for key in ("target_files", "target_contracts", "target_functions",
                    "target_findings", "engine_findings"):
            card = getattr(self, f"card_{key}", None)
            if card is not None:
                card.configure(text="SCAN")


AtlasApp._apply_dashboard_metrics = _show_target_scan_state


W3SecApp = AtlasApp
APP_VERSION = "development"


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()
    target = next(
        (Path(arg).expanduser() for arg in sys.argv[1:]
         if not arg.startswith("-") and Path(arg).exists()),
        None,
    )
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
