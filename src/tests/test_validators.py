from pathlib import Path
from sentinel.policy import load_policy
from sentinel.validators import validate_value

policy_path = Path(__file__).parent / "fixtures" / "policy.yaml"
policy = load_policy(str(policy_path))


def test_string_validator_basic():
    print("\nTesting string validator basic functionality...")

    print("Testing valid filename 'hello.txt'...")
    ok, msg = validate_value(policy, "safe_filename", "hello.txt")
    assert ok, msg
    print(f"Valid filename test passed: {msg}")

    print("\nTesting path traversal attack '../passwd'...")
    ok, msg = validate_value(policy, "safe_filename", "../passwd")
    assert not ok and "forbidden" in msg.lower()
    print(f"Path traversal test passed: {msg}")

    print("\nTesting filename length limit...")
    long_name = "a" * 129
    ok, msg = validate_value(policy, "safe_filename", long_name)
    assert not ok and "length" in msg.lower()
    print(f"Length limit test passed: {msg}")


def test_path_validator_under_root(tmp_path):
    print("\nTesting path validator under root directory...")
    # Create a fake uploads dir under temp
    uploads = tmp_path / "data" / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    print(f"Created test uploads directory at: {uploads}")

    policy_text = policy_path.read_text(encoding="utf-8")
    # Rewrite policy to point to temp uploads root
    patched_text = policy_text.replace("data/uploads", str(uploads))
    temp_policy = tmp_path / "policy.yaml"
    temp_policy.write_text(patched_text, encoding="utf-8")
    print("Created temporary policy file with patched uploads path")

    policy = load_policy(str(temp_policy))

    # Path inside uploads
    print("\nTesting file path inside uploads directory...")
    inside = uploads / "file.txt"
    print(f"Testing path: {inside}")
    ok, msg = validate_value(policy, "path_in_uploads", str(inside))
    assert ok, msg
    print(f"Inside uploads test passed: {msg}")

    # Path outside uploads
    print("\nTesting file path outside uploads directory...")
    outside = tmp_path / "outside.txt"
    print(f"Testing path: {outside}")
    ok, msg = validate_value(policy, "path_in_uploads", str(outside))
    assert not ok and "allowed roots" in msg.lower()
    print(f"Outside uploads test passed: {msg}")


def test_subdirectory_constraint(tmp_path):
    print("\nTesting subdirectory constraints...")
    uploads = tmp_path / "data" / "uploads"
    (uploads / "nested").mkdir(parents=True, exist_ok=True)
    print(f"Created test directory structure at: {uploads}")
    print(f"With nested directory at: {uploads / 'nested'}")

    policy_text = policy_path.read_text(encoding="utf-8").replace(
        "data/uploads", str(uploads)
    )
    temp_policy = tmp_path / "policy.yaml"
    temp_policy.write_text(policy_text, encoding="utf-8")
    policy = load_policy(str(temp_policy))
    print("Created temporary policy file with patched uploads path")

    # Safe file path OK
    print("\nTesting safe file path (should be allowed)...")
    safe_path = str(uploads / "ok.txt")
    print(f"Testing path: {safe_path}")
    ok, msg = validate_value(policy, "path_in_uploads", safe_path)
    assert ok, msg
    print(f"Safe file path test passed: {msg}")

    # Subdirectory blocked
    print("\nTesting file in subdirectory (should be blocked)...")
    nested_path = str(uploads / "nested" / "nope.txt")
    print(f"Testing path: {nested_path}")
    ok, msg = validate_value(policy, "path_in_uploads", nested_path)
    assert not ok and "subdirectories disallowed" in msg.lower()
    print(f"Subdirectory test passed: {msg}")


def test_json_schema():
    """Test JSON schema validation."""
    ok, msg = validate_value(
        policy, "order_schema", {"filename": "a.txt", "content": "QQ=="}
    )
    assert ok, msg

    ok, msg = validate_value(policy, "order_schema", {"filename": "a.txt"})
    assert not ok  # missing required field 'content'

    ok, msg = validate_value(
        policy, "order_schema", {"filename": "", "content": "QQ=="}
    )
    assert not ok  # filename too short


def test_shell_safe():
    """Test shell injection detection."""
    ok, msg = validate_value(policy, "shell_safe", "image.jpg")
    assert ok, msg

    ok, msg = validate_value(policy, "shell_safe", "image.jpg && rm -rf /")
    assert not ok

    ok, msg = validate_value(policy, "shell_safe", "echo hello; cat file")
    assert not ok


def test_sql_safe():
    """Test SQL injection detection."""
    ok, msg = validate_value(policy, "sql_safe", "SELECT * FROM users")
    assert ok, msg

    ok, msg = validate_value(policy, "sql_safe", "alice'; DROP TABLE users; --")
    assert not ok

    ok, msg = validate_value(
        policy, "sql_safe", "SELECT * FROM users UNION SELECT * FROM admins"
    )
    assert not ok


def test_template_safe():
    """Test template injection detection."""
    ok, msg = validate_value(policy, "template_safe", "Hello, Alice!")
    assert ok, msg

    ok, msg = validate_value(policy, "template_safe", "Hello, {{7*7}}!")
    assert not ok

    ok, msg = validate_value(policy, "template_safe", "Hello, ${name}!")
    assert not ok


def test_url_safe():
    """Test SSRF protection."""
    ok, msg = validate_value(policy, "url_safe", "https://example.com")
    assert ok, msg

    ok, msg = validate_value(policy, "url_safe", "http://localhost:22")
    assert not ok

    ok, msg = validate_value(policy, "url_safe", "file:///etc/passwd")
    assert not ok

    ok, msg = validate_value(policy, "url_safe", "http://127.0.0.1:8080")
    assert not ok
