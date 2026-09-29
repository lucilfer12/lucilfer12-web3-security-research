from pathlib import Path

from w3sec.atlas_ui import AtlasApp


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
    assert "FINDINGS  3" in app.current_target_text.text


def test_audit_selected_rejects_missing_target_without_running_audit(tmp_path):
    target = tmp_path / 'missing.sol'
    app = _app(str(target))

    app.audit_selected()

    assert app.target_called is False
    assert app.repo_called is False
    assert app.status.value == 'Selected target does not exist.'