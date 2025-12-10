# Sentinel-Guard: A Policy-Driven Input Wrapper (Python)

Sentinel-Guard is a small library that **labels untrusted data**, **validates it** with a **policy file**, and **blocks dangerous actions** (e.g., shell exec, path traversal, unsafe YAML) **before** they execute.

It includes:

- A **policy language** (YAML) to define what "non-secure input" means.
- **Wrappers/patches (sinks)** for `subprocess.run`, `os.system`, `builtins.open`, `yaml.load`, `sqlite3`, template engines, and HTTP libraries.
- Simple **taint tracking** to mark data from untrusted sources.
- **FastAPI middleware** for automatic taint tracking in web applications.

## Quick start

### Requirements

- Python 3.10+
- macOS/Linux or WSL (Windows may need slight path tweaks)

### Installation

```bash
# Clone the repository
git clone https://github.com/ecs235a-group/sentinel-guard.git
cd sentinel-guard

# Create a virtual environment
pip3 install --user virtualenv
~/.local/bin/virtualenv .venv
source .venv/bin/activate

# Install the sentinel package
pip install -e .
export PYTHONPATH="$PWD/src:$PYTHONPATH"
```

### Basic Usage in Code

```python
from sentinel.policy import load_policy
from sentinel.sinks import apply_patches

# Load policy and apply security patches
policy = load_policy("path/to/your/policy.yaml")
apply_patches(policy)

# Now dangerous operations are protected
import subprocess
subprocess.run(["echo", "safe"])  # OK
subprocess.run("rm -rf /", shell=True)  # Blocked by policy
```

### FastAPI Integration

```python
from fastapi import FastAPI
from sentinel.policy import load_policy
from sentinel.sinks import apply_patches
from sentinel.middleware import SentinelMiddleware

policy = load_policy("path/to/your/policy.yaml")
apply_patches(policy)

app = FastAPI()
app.add_middleware(SentinelMiddleware)

# Your endpoints are now protected
```

For a complete working example, see [`fastapi_app_example/README.md`](fastapi_app_example/README.md).

### Running Tests (optional)

```bash
# Install pytest
pip install pytest
```

```bash
# From repo root
pytest -s -v

# Run specific test file
pytest src/tests/test_sinks.py -v
```

## How it works

1. **Policy** defines validators (regex/length/path/json-schema) and which **sinks** require them.
2. **Patch**: Load policy, call `sentinel.sinks.apply_patches(policy)`, which monkey-patches dangerous functions to check inputs first.
3. **Taint**: Use `sentinel.taint.taint_recursive()` to mark incoming strings as untrusted; validators run regardless, but taint helps you track data flow.

## Features

### Protected Operations

- **Shell execution**: `subprocess.run`, `os.system`
- **File operations**: `builtins.open` (validates paths/filenames for write modes)
- **YAML loading**: `yaml.load` (blocks unsafe loaders)
- **SQL queries**: `sqlite3.Cursor.execute`, `sqlite3.Cursor.executemany`
- **Template rendering**: `string.Template.substitute`, `jinja2.Template.render`
- **HTTP requests**: `requests.get/post`, `urllib.request.urlopen` (SSRF protection)

### Validators

- **String validators**: regex patterns, length limits, character set restrictions, deny patterns
- **Path validators**: enforce paths under allowed directories, prevent subdirectories
- **JSON schema validators**: validate structured data against JSON schemas

### Taint Tracking

- Mark untrusted data with tags
- Track data flow through your application
- Automatic taint propagation through string operations
- FastAPI middleware for automatic HTTP request tainting

## Policy Configuration

Policies are defined in YAML files. See `src/tests/fixtures/policy.yaml` for an example policy file.

### Example Policy

```yaml
version: 1

defaults:
  mode: block

validators:
  - id: safe_filename
    type: string
    max_len: 128
    regex: "^[A-Za-z0-9._-]+$"
    deny_substrings: ["..", "/", '\\']

sinks:
  - id: file_write
    function: builtins.open
    require: [safe_filename, path_in_uploads]
```

## Notes / Limitations

- Patches are Python-level; native extensions could bypass them.
- `builtins.open` patch validates **path & filename** for write-modes only.
- For production use, combine with OS sandboxing (containers/AppArmor/seccomp).
- Some features require optional dependencies (`requests`, `jinja2`).

## License

See LICENSE file for details.
