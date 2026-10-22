from pipelineguard.rules.workflow_rules import scan_path


def ids(findings):
    return {f.rule_id for f in findings}


def test_vulnerable_workflow_trips_every_rule():
    findings = scan_path("samples/workflows/vulnerable.yml")
    assert {"PG-GHA-001", "PG-GHA-002", "PG-GHA-003", "PG-GHA-004", "PG-GHA-005", "PG-GHA-006"} <= ids(findings)


def test_prt_checkout_is_critical_with_line_number():
    f = next(x for x in scan_path("samples/workflows/vulnerable.yml") if x.rule_id == "PG-GHA-001")
    assert f.severity.name == "CRITICAL" and f.line == 14


def test_third_party_tag_is_high_first_party_is_medium():
    f = [x for x in scan_path("samples/workflows/vulnerable.yml") if x.rule_id == "PG-GHA-002"]
    by_title = {x.title: x.severity.name for x in f}
    assert by_title["Action not pinned to a commit SHA: aquasecurity/trivy-action@v0.28.0"] == "HIGH"
    assert by_title["Action not pinned to a commit SHA: actions/checkout@v4"] == "MEDIUM"


def test_safe_workflow_is_clean():
    assert scan_path("samples/workflows/safe.yml") == []


def test_script_injection_detected(tmp_path):
    wf = tmp_path / "w.yml"
    wf.write_text("on: issues\npermissions: {contents: read}\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                  "    steps:\n      - run: echo ${{ github.event.issue.title }}\n")
    assert "PG-GHA-005" in ids(scan_path(str(wf)))


def test_env_indirection_is_not_flagged(tmp_path):
    wf = tmp_path / "w.yml"
    wf.write_text("on: issues\npermissions: {contents: read}\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                  "    steps:\n      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo \"$T\"\n")
    assert "PG-GHA-005" not in ids(scan_path(str(wf)))


def test_bad_yaml_reports_parse_finding(tmp_path):
    wf = tmp_path / "w.yml"
    wf.write_text("on: [unclosed\n")
    assert ids(scan_path(str(wf))) == {"PG-GHA-000"}
