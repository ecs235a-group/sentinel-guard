from pathlib import Path
from sentinel.policy import load_policy
from sentinel.validators import validate_value

policy_path = Path(__file__).parents[1] / 'config' / 'policies' / 'base.yaml'
policy = load_policy(str(policy_path))

def test_string_validator_basic():
    print("\nTesting string validator basic functionality...")
    
    print("Testing valid filename 'hello.txt'...")
    ok, msg = validate_value(policy, 'safe_filename', 'hello.txt')
    assert ok, msg
    print(f"Valid filename test passed: {msg}")

    print("\nTesting path traversal attack '../passwd'...")
    ok, msg = validate_value(policy, 'safe_filename', '../passwd')
    assert not ok and 'forbidden' in msg.lower()
    print(f"Path traversal test passed: {msg}")

    print("\nTesting filename length limit...")
    long_name = 'a' * 129
    ok, msg = validate_value(policy, 'safe_filename', long_name)
    assert not ok and 'length' in msg.lower()
    print(f"Length limit test passed: {msg}")

def test_path_validator_under_root(tmp_path):
    print("\nTesting path validator under root directory...")
    # Create a fake uploads dir under temp
    uploads = tmp_path / 'data' / 'uploads'
    uploads.mkdir(parents=True, exist_ok=True)
    print(f"Created test uploads directory at: {uploads}")

    policy_text = policy_path.read_text(encoding='utf-8')
    # Rewrite policy to point to temp uploads root
    patched_text = policy_text.replace('data/uploads', str(uploads))
    temp_policy = tmp_path / 'policy.yaml'
    temp_policy.write_text(patched_text, encoding='utf-8')
    print("Created temporary policy file with patched uploads path")

    policy = load_policy(str(temp_policy))

    # Path inside uploads
    print("\nTesting file path inside uploads directory...")
    inside = uploads / 'file.txt'
    print(f"Testing path: {inside}")
    ok, msg = validate_value(policy, 'path_in_uploads', str(inside))
    assert ok, msg
    print(f"Inside uploads test passed: {msg}")

    # Path outside uploads
    print("\nTesting file path outside uploads directory...")
    outside = tmp_path / 'outside.txt'
    print(f"Testing path: {outside}")
    ok, msg = validate_value(policy, 'path_in_uploads', str(outside))
    assert not ok and 'allowed roots' in msg.lower()
    print(f"Outside uploads test passed: {msg}")

def test_subdirectory_constraint(tmp_path):
    print("\nTesting subdirectory constraints...")
    uploads = tmp_path / 'data' / 'uploads'
    (uploads / 'nested').mkdir(parents=True, exist_ok=True)
    print(f"Created test directory structure at: {uploads}")
    print(f"With nested directory at: {uploads/'nested'}")

    policy_text = policy_path.read_text(encoding='utf-8').replace('data/uploads', str(uploads))
    temp_policy = tmp_path / 'policy.yaml'
    temp_policy.write_text(policy_text, encoding='utf-8')
    policy = load_policy(str(temp_policy))
    print("Created temporary policy file with patched uploads path")

    # Safe file path OK
    print("\nTesting safe file path (should be allowed)...")
    safe_path = str(uploads / 'ok.txt')
    print(f"Testing path: {safe_path}")
    ok, msg = validate_value(policy, 'path_in_uploads', safe_path)
    assert ok, msg
    print(f"Safe file path test passed: {msg}")

    # Subdirectory blocked
    print("\nTesting file in subdirectory (should be blocked)...")
    nested_path = str(uploads / 'nested' / 'nope.txt')
    print(f"Testing path: {nested_path}")
    ok, msg = validate_value(policy, 'path_in_uploads', nested_path)
    assert not ok and 'subdirectories disallowed' in msg.lower()
    print(f"Subdirectory test passed: {msg}")
