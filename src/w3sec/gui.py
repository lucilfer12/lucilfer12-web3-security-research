"""Compatibility entry point for the ATLAS desktop application.

The runtime wrapper keeps the canonical UI implementation in atlas_ui while
ensuring a persisted target is actually audited on startup.
"""

import sys
import traceback
from pathlib import Path

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


def _show_target_scan_state(self, inventory, graph, intakes, federation) -> None:
    _AtlasApp._apply_dashboard_metrics(self, inventory, graph, intakes, federation)
    if self.current_target and not self.current_target_report and self.busy:
        for key in ("target_files", "target_contracts", "target_functions",
                    "target_findings", "engine_findings"):
            card = getattr(self, f"card_{key}", None)
            if card is not None:
                card.configure(text="SCAN")


AtlasApp._apply_dashboard_metrics = _show_target_scan_state
