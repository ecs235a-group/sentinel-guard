# Sentinel-Guard: A Policy-Driven Input Wrapper (Python)

## Quick start (For CSIF machines)

### 1) Requirements
- Python 3.13+
- macOS/Linux or WSL (Windows may need slight path tweaks)

### 2) Install project
```bash
git clone https://github.com/ecs235a-group/sentinel-guard.git
cd sentinel-guard
```

### 3) Create a virtual environment and install dependencies
```bash
pip3 install --user virtualenv
~/.local/bin/virtualenv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD/src:$PYTHONPATH"
```

### 4) Run Examples with pytest

```bash
# From repo root
pytest -s -v
```
