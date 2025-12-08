# Sentinel-Guard FastAPI Example

Simple FastAPI application to sentinel-guard.

## Setup

1. Make sure you're in the `sentinel-guard` directory root
2. Install the sentinel package (this also installs the dependencies):
   ```bash
   pip install -e .
   ```
3. Set the PYTHONPATH:
   ```bash
   export PYTHONPATH="$PWD/src:$PYTHONPATH"
   ```

## Running the App

```bash
cd fastapi_app
python app.py
```

The API will be available at `http://localhost:8000`

## API Endpoints

### GET /

Root endpoint with API information.

### POST /upload

Upload a file (tests path traversal protection).

**Example:**

```bash
curl -X POST http://localhost:8000/upload \
  -H "Content-Type: application/json" \
  -d '{"filename": "test.txt", "content": "SGVsbG8gV29ybGQ="}'
```

**Try an attack:**

```bash
curl -X POST http://localhost:8000/upload \
  -H "Content-Type: application/json" \
  -d '{"filename": "../../etc/passwd", "content": "SGVsbG8gV29ybGQ="}'
```

### POST /exec

Execute a shell command (tests shell injection protection).

**Example:**

```bash
curl -X POST http://localhost:8000/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "echo hello"}'
```

**Try an attack:**

```bash
curl -X POST http://localhost:8000/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "echo hello; rm -rf /"}'
```

### POST /query

Execute a SQL query (tests SQL injection protection).

**Example:**

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users WHERE id = 1"}'
```

**Try an attack:**

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users; DROP TABLE users;"}'
```

### POST /fetch

Fetch a URL (tests SSRF protection).

**Example:**

```bash
curl -X POST http://localhost:8000/fetch \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Try an attack:**

```bash
curl -X POST http://localhost:8000/fetch \
  -H "Content-Type: application/json" \
  -d '{"url": "http://localhost:22"}'
```

### POST /template

Render a template (tests template injection protection).

**Example:**

```bash
curl -X POST http://localhost:8000/template \
  -H "Content-Type: application/json" \
  -d '{"template": "Hello {{ name }}", "context": {"name": "World"}}'
```

**Try an attack:**

```bash
curl -X POST http://localhost:8000/template \
  -H "Content-Type: application/json" \
  -d '{"template": "{{ config.items() }}", "context": {}}'
```

## Features Demonstrated

- **Path Traversal Protection**: File operations are validated to prevent directory traversal attacks
- **Shell Injection Protection**: Shell commands are validated to prevent command injection
- **SQL Injection Protection**: SQL queries are validated to prevent SQL injection attacks
- **SSRF Protection**: HTTP requests are validated to prevent Server-Side Request Forgery
- **Template Injection Protection**: Template rendering is validated to prevent template injection

All protections are enforced by the sentinel-guard policy defined in `config/policies/base.yaml`.
