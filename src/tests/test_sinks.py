import subprocess
import os
import yaml
import sqlite3
from pathlib import Path
from string import Template

import pytest

from sentinel.policy import load_policy
from sentinel.sinks import apply_patches, PolicyViolation

policy_path = Path(__file__).parent / "fixtures" / "policy.yaml"
policy = load_policy(str(policy_path))
apply_patches(policy)


def test_subprocess_run_safe():
    """Test that safe subprocess.run commands are allowed."""
    result = subprocess.run(["echo", "Hello"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Hello" in result.stdout


def test_subprocess_run_unsafe():
    """Test that unsafe subprocess.run commands are blocked."""
    with pytest.raises(PolicyViolation):
        subprocess.run("echo HACK; rm -rf /", shell=True)


def test_os_system_safe():
    """Test that safe os.system commands are allowed."""
    # Note: This will actually execute, so use a safe command
    os.system("echo 'Safe command'")


def test_os_system_unsafe():
    """Test that unsafe os.system commands are blocked."""
    with pytest.raises(PolicyViolation):
        os.system("echo HACK; rm -rf /")


def test_builtins_open_safe(tmp_path):
    """Test that safe file writes are allowed."""
    uploads = tmp_path / "data" / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)

    # Create temporary policy with updated path
    policy_text = policy_path.read_text(encoding="utf-8")
    patched_text = policy_text.replace("data/uploads", str(uploads))
    temp_policy = tmp_path / "policy.yaml"
    temp_policy.write_text(patched_text, encoding="utf-8")
    temp_policy_obj = load_policy(str(temp_policy))
    apply_patches(temp_policy_obj)

    safe_file = uploads / "safe.txt"
    with open(safe_file, "w") as f:
        f.write("test")
    assert safe_file.exists()


def test_builtins_open_unsafe(tmp_path):
    """Test that unsafe file writes are blocked."""
    uploads = tmp_path / "data" / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)

    # Create temporary policy with updated path
    policy_text = policy_path.read_text(encoding="utf-8")
    patched_text = policy_text.replace("data/uploads", str(uploads))
    temp_policy = tmp_path / "policy.yaml"
    temp_policy.write_text(patched_text, encoding="utf-8")
    temp_policy_obj = load_policy(str(temp_policy))
    apply_patches(temp_policy_obj)

    # Try to write with path traversal
    unsafe_file = uploads / "../outside.txt"
    with pytest.raises(PolicyViolation):
        with open(unsafe_file, "w") as f:
            f.write("hack")

    # Try to write with unsafe filename
    unsafe_filename = uploads / "../../etc/passwd"
    with pytest.raises(PolicyViolation):
        with open(unsafe_filename, "w") as f:
            f.write("hack")


def test_yaml_load_blocked():
    """Test that yaml.load is blocked."""
    with pytest.raises(PolicyViolation):
        yaml.load("test: value")


def test_yaml_safe_load_allowed():
    """Test that yaml.safe_load is allowed."""
    data = yaml.safe_load("test: value")
    assert data == {"test": "value"}


def test_sqlite_execute_safe(tmp_path):
    """Test that safe SQL queries are allowed."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'alice')")
    conn.commit()

    cursor.execute("SELECT * FROM users WHERE name = 'alice'")
    results = cursor.fetchall()
    assert len(results) == 1

    conn.close()


def test_sqlite_execute_unsafe(tmp_path):
    """Test that unsafe SQL queries are blocked."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")

    with pytest.raises(PolicyViolation):
        cursor.execute("SELECT * FROM users; DROP TABLE users; --")

    conn.close()


def test_string_template_safe():
    """Test that safe template substitutions are allowed."""
    template = Template("Hello, $name!")
    result = template.substitute(name="Alice")
    assert result == "Hello, Alice!"


def test_string_template_unsafe():
    """Test that unsafe template substitutions are blocked."""
    template = Template("Hello, {{7*7}}!")
    with pytest.raises(PolicyViolation):
        template.substitute(name="Alice")


@pytest.mark.skipif(
    not pytest.importorskip("jinja2", reason="jinja2 not installed"),
    reason="jinja2 not available",
)
def test_jinja_render_safe():
    """Test that safe Jinja2 templates are allowed."""
    import jinja2

    template = jinja2.Template("Hello, {{ name }}!")
    result = template.render(name="Alice")
    assert result == "Hello, Alice!"


@pytest.mark.skipif(
    not pytest.importorskip("jinja2", reason="jinja2 not installed"),
    reason="jinja2 not available",
)
def test_jinja_render_unsafe():
    """Test that unsafe Jinja2 templates are blocked."""
    import jinja2

    template = jinja2.Template("Hello, {{ 7*7 }}!")
    with pytest.raises(PolicyViolation):
        template.render(name="Alice")


@pytest.mark.skipif(
    not pytest.importorskip("requests", reason="requests not installed"),
    reason="requests not available",
)
def test_requests_get_safe():
    """Test that safe HTTP requests are allowed."""
    import requests

    response = requests.get("https://httpbin.org/get", timeout=5)
    assert response.status_code == 200


@pytest.mark.skipif(
    not pytest.importorskip("requests", reason="requests not installed"),
    reason="requests not available",
)
def test_requests_get_unsafe():
    """Test that unsafe HTTP requests are blocked."""
    import requests

    with pytest.raises(PolicyViolation):
        requests.get("http://localhost:22", timeout=1)


def test_urllib_urlopen_safe():
    """Test that safe urllib requests are allowed."""
    import urllib.request

    with urllib.request.urlopen("https://httpbin.org/get", timeout=5) as response:
        assert response.status == 200


def test_urllib_urlopen_unsafe():
    """Test that unsafe urllib requests are blocked."""
    import urllib.request

    with pytest.raises(PolicyViolation):
        urllib.request.urlopen("http://127.0.0.1:22", timeout=1)
