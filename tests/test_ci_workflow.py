import re
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"


def test_every_ci_job_uses_the_cpu_runner_contract_and_timeout() -> None:
    source = WORKFLOW.read_text()
    jobs_source = source.split("\njobs:\n", 1)[1]
    jobs = re.findall(r"(?ms)^  ([a-z][a-z-]*):\n(.*?)(?=^  [a-z][a-z-]*:\n|\Z)", jobs_source)

    assert [name for name, _ in jobs] == ["checks", "conformance", "container", "deploy"]
    for name, body in jobs[:3]:
        assert "    runs-on: ${{ fromJSON(vars.CI_RUNNERS).linux }}\n" in body, name
        assert "    timeout-minutes: 10\n" in body, name
    deploy = jobs[3][1]
    assert "    needs: [checks, conformance, container]\n" in deploy
    assert "    uses: ./.github/workflows/deploy.yml\n" in deploy
    assert "github.event_name == 'push' && github.ref == 'refs/heads/main'" in deploy
    assert "vars.FLY_DEPLOY_ENABLED == 'true'" in deploy
    deployment = WORKFLOW.with_name("deploy.yml").read_text()
    assert "    runs-on: ${{ fromJSON(vars.CI_RUNNERS).linux }}\n" in deployment
    assert "ref: ${{ github.sha }}" in deployment
    assert '--image "$FLY_IMAGE"' in deployment
    assert "--network host" in deployment
    assert "DINKSTER_REPO_TOKEN" not in deployment
    assert "continue-on-error" not in source
    assert "gpu" not in source.lower()
    assert "python scripts/check-release-packs.py'" in source


def test_postgres_uses_dynamic_loopback_ports_without_bridge_networks() -> None:
    source = WORKFLOW.read_text()
    postgres = (WORKFLOW.parents[2] / "scripts" / "with-test-postgres.sh").read_text()

    assert "\n    services:" not in source
    assert source.count("bash scripts/with-test-postgres.sh ") == 4
    assert "--network host" in postgres
    assert 's.bind(("127.0.0.1", 0))' in postgres
    assert "-c listen_addresses=127.0.0.1" in postgres
    assert '-c port="$port"' in postgres
    assert "5432:5432" not in source
    assert "docker network create" not in source
    assert "--network dinkster-registry-test" not in source
    assert source.count('export DINKSTER_PUBLIC_BASE_URL="http://127.0.0.1:$http_port"') == 3
    assert source.count('s.bind(("127.0.0.1", 0))') == 3
    assert "--port 8000" not in source
    assert "http://127.0.0.1:8000" not in source
