import re
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"


def test_every_ci_job_uses_the_cpu_runner_contract_and_timeout() -> None:
    source = WORKFLOW.read_text().split("\njobs:\n", 1)[1]
    jobs = re.findall(r"(?ms)^  ([a-z][a-z-]*):\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", source)

    assert [name for name, _ in jobs] == ["checks", "conformance", "container"]
    for name, body in jobs:
        assert "    runs-on: ${{ fromJSON(vars.CI_RUNNERS).linux }}\n" in body, name
        assert "    timeout-minutes: 10\n" in body, name
