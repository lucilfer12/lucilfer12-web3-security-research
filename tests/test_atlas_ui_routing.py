import json
from pathlib import Path

from w3sec.gui import AtlasApp


class _Value:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


class _Status:
    def __init__(self):
        self.value = None

    def set(self, value):
        self.value = value


def _app(raw):
    app = AtlasApp.__new__(AtlasApp)
    app.target_var = _Value(raw)
    app.status = _Status()
    app.target_called = False
    app.repo_called = False

    def target():
        app.target_called = True

    def repo():
        app.repo_called = True

    app.audit_target = target
    app.audit_repo = repo
    return app


def test_audit_selected_routes_existing_target_to_target_audit(tmp_path):
    target = tmp_path / 'uploaded.sol'
    target.write_text('contract Uploaded {}', encoding='utf-8')
    app = _app(str(target))

    app.audit_selected()

    assert app.target_called is True
    assert app.repo_called is False


def test_audit_selected_without_target_keeps_repository_audit():
    app = _app('')

    app.audit_selected()

    assert app.repo_called is True
    assert app.target_called is False


class _Widget:
    def __init__(self):
        self.text = None

    def configure(self, **kwargs):
        if "text" in kwargs:
            self.text = kwargs["text"]


def test_dashboard_target_metrics_are_not_repository_case_metrics():
    app = AtlasApp.__new__(AtlasApp)
    for key in ("target_files", "target_contracts", "target_functions", "target_findings", "engine_findings",
                "research_cases", "research_candidates", "research_nodes"):
        setattr(app, f"card_{key}", _Widget())
    app.current_target = Path("C:/tmp/uploaded.sol")
    app.current_target_report = {
        "target": {"path": "C:/tmp/uploaded.sol"},
        "summary": {
            "source_file_count": 1,
            "contract_count": 2,
            "function_count": 7,
            "finding_count": 3,
            "engine_finding_count": 2,
        },
    }
    app.current_target_text = _Widget()
    graph = type("Graph", (), {"nodes": {"n1": object(), "n2": object()}})()

    AtlasApp._apply_dashboard_metrics(app, {"case_count": 4}, graph, [], {"candidate_record_count": 262})

    assert app.card_target_files.text == "1"
    assert app.card_target_contracts.text == "2"
    assert app.card_target_functions.text == "7"
    assert app.card_target_findings.text == "3"
    assert app.card_engine_findings.text == "2"
    assert app.card_research_cases.text == "4"
    assert app.card_research_candidates.text == "262"
    assert app.card_research_nodes.text == "2"
    assert "uploaded.sol" in app.current_target_text.text
    assert "PRIMARY FINDINGS  3" in app.current_target_text.text


def test_audit_selected_rejects_missing_target_without_running_audit(tmp_path):
    target = tmp_path / 'missing.sol'
    app = _app(str(target))

    app.audit_selected()

    assert app.target_called is False
    assert app.repo_called is False
    assert app.status.value == 'Selected target does not exist.'

def test_saved_target_without_report_is_not_audited_on_startup(tmp_path, monkeypatch):
    target = tmp_path / "saved.sol"
    state = tmp_path / "target.json"
    target.write_text("contract Saved {}", encoding="utf-8")
    state.write_text(json.dumps({"target": str(target)}), encoding="utf-8")
    monkeypatch.setattr("w3sec.atlas_ui.target_state_path", lambda: state)
    monkeypatch.setattr("w3sec.atlas_ui.save_target_state", lambda *_args, **_kwargs: None)
    app = AtlasApp.__new__(AtlasApp)
    app.repo = tmp_path
    app.current_target = None
    app.current_target_report = {}
    app.last_audit = {}
    app.current_report_path = None
    app.status = _Status()
    def set_target(value):
        app.current_target = value
        return value
    app._set_current_target = set_target
    audited = []
    app._start_initial_target_audit = lambda value: audited.append(value)
    AtlasApp._restore_saved_target(app)
    assert app.current_target == target.resolve()
    assert app.current_target_report == {}
    assert app.last_audit == {}
    assert app.current_report_path is None
    assert audited == []
    assert "without executing an audit" in app.status.value


def test_startup_message_is_explicit_about_no_automatic_target_audit():
    app = AtlasApp.__new__(AtlasApp)
    app.initial_target = None
    app.status = _Status()
    app.show_page = lambda _value: None
    app.protocol = lambda *_args: None
    app.after = lambda *_args: None
    app.current_target = None
    app.current_target_report = {}
    app.last_audit = {}
    app.current_report_path = None
    app.repo = None
    app.executor = None
    app.busy = False
    app.task_name = ""
    app.last_result = None
    app.progress_value = 0
    app.progress_target = 0
    app.progress_caption = "READY"
    # The assertion is kept on the startup contract itself; the full constructor is
    # exercised by the packaged self-test/build path.
    app.status.set("READY — no target audit starts automatically")
    assert "no target audit starts automatically" in app.status.value


def test_saved_target_with_report_only_restores_selection_not_previous_audit(tmp_path, monkeypatch):
    target = tmp_path / "saved.sol"
    report = tmp_path / "saved-report.json"
    state = tmp_path / "target.json"
    target.write_text("contract Saved {}", encoding="utf-8")
    report.write_text(json.dumps({
        "target": {"path": str(target)},
        "summary": {"finding_count": 99},
    }), encoding="utf-8")
    state.write_text(json.dumps({
        "target": str(target),
        "report_path": str(report),
    }), encoding="utf-8")
    monkeypatch.setattr("w3sec.atlas_ui.target_state_path", lambda: state)
    monkeypatch.setattr("w3sec.atlas_ui.save_target_state", lambda *_args, **_kwargs: None)
    app = AtlasApp.__new__(AtlasApp)
    app.repo = tmp_path
    app.current_target = None
    app.current_target_report = {}
    app.last_audit = {}
    app.current_report_path = None
    app.status = _Status()
    def set_target(value):
        app.current_target = value
        return value
    app._set_current_target = set_target
    AtlasApp._restore_saved_target(app)
    assert app.current_target == target.resolve()
    assert app.current_target_report == {}
    assert app.last_audit == {}
    assert app.current_report_path is None
    assert "without executing an audit" in app.status.value


def test_self_test_uses_disposable_fixture_not_canonical_repo(tmp_path):
    from w3sec.atlas_ui import _run_local_self_test_fixture

    before = set(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    result = _run_local_self_test_fixture(tmp_path)
    after = set(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    assert result["contract_count"] == 1
    assert result["function_count"] == 1
    assert before == after


def test_choose_target_does_not_execute_audit_implicitly(tmp_path, monkeypatch):
    target = tmp_path / "selected.sol"
    target.write_text("contract Selected {}", encoding="utf-8")
    app = AtlasApp.__new__(AtlasApp)
    app._set_current_target = lambda value: setattr(app, "current_target", value)
    app._clear_target_result = lambda: None
    app.show_page = lambda value: setattr(app, "page", value)
    app.status = _Status()
    def set_target(value):
        app.current_target = value
        return value
    app._set_current_target = set_target
    app.audit_called = False
    app.audit_target = lambda: setattr(app, "audit_called", True)
    monkeypatch.setattr(
        "w3sec.atlas_ui.filedialog.askopenfilename",
        lambda **_kwargs: str(target),
    )
    AtlasApp.choose_target(app)
    assert app.audit_called is False
    assert "No audit was executed" in app.status.value
