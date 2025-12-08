import base64
import subprocess
import sqlite3
from pathlib import Path

import jinja2
import requests
from fastapi import FastAPI, HTTPException, Request

from sentinel.policy import load_policy
from sentinel.sinks import apply_patches, PolicyViolation
from sentinel.middleware import SentinelMiddleware, taint_flow
from sentinel.validators import validate_value

# Load policy and apply security patches
POLICY_PATH = Path(__file__).parent / "config" / "policies" / "base.yaml"
policy = load_policy(str(POLICY_PATH))
apply_patches(policy)

# Create FastAPI app with middleware
app = FastAPI(
    title="Sentinel-Guard Demo API",
    description="Demonstrates security protections for various operations",
)

app.add_middleware(SentinelMiddleware)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Sentinel-Guard FastAPI Demo",
        "endpoints": [
            "/upload - File upload (tests path traversal protection)",
            "/exec - Shell command execution (tests shell injection protection)",
            "/query - SQL query (tests SQL injection protection)",
            "/fetch - HTTP request (tests SSRF protection)",
            "/template - Template rendering (tests template injection protection)",
        ],
    }


@app.post("/upload")
async def upload_file(request: Request):
    """
    Upload a file - demonstrates path traversal protection.

    Expected JSON:
    {
        "filename": "safe_filename.txt",
        "content": "base64_encoded_content"
    }
    """
    try:
        flow = taint_flow.get()
        flow.append("fastapi_app.upload_file")
        taint_flow.set(flow)
    except Exception:
        pass

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Validate against JSON schema
    ok, msg = validate_value(policy, "order_schema", data)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Validation failed: {msg}")

    # Create uploads directory
    uploads_dir = Path("data/uploads")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    file_path = uploads_dir / data["filename"]

    try:
        # This will be blocked if filename contains path traversal (../, etc.)
        content = base64.b64decode(data["content"])
        with open(file_path, "wb") as f:
            f.write(content)
        return {
            "status": "success",
            "message": "File uploaded successfully",
            "path": str(file_path),
        }
    except PolicyViolation as e:
        raise HTTPException(status_code=403, detail=f"Security policy violation: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/exec")
async def execute_command(request: Request):
    """
    Execute a shell command - demonstrates shell injection protection.

    Expected JSON:
    {
        "command": "echo hello"
    }
    """
    try:
        flow = taint_flow.get()
        flow.append("fastapi_app.execute_command")
        taint_flow.set(flow)
    except Exception:
        pass

    try:
        data = await request.json()
        command = data.get("command", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not command:
        raise HTTPException(status_code=400, detail="Missing 'command' field")

    try:
        # This will be blocked if command contains shell metacharacters
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=5
        )
        return {
            "status": "success",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except PolicyViolation as e:
        raise HTTPException(status_code=403, detail=f"Security policy violation: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/query")
async def sql_query(request: Request):
    """
    Execute a SQL query - demonstrates SQL injection protection.

    Expected JSON:
    {
        "query": "SELECT * FROM users WHERE id = 1"
    }
    """
    try:
        flow = taint_flow.get()
        flow.append("fastapi_app.sql_query")
        taint_flow.set(flow)
    except Exception:
        pass

    try:
        data = await request.json()
        query = data.get("query", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not query:
        raise HTTPException(status_code=400, detail="Missing 'query' field")

    # Create a demo database
    db_path = Path("data/demo.db")
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Create demo table if it doesn't exist
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'Alice'), (2, 'Bob')")
    conn.commit()

    try:
        # This will be blocked if query contains SQL injection patterns
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()

        return {"status": "success", "results": results, "rowcount": len(results)}
    except PolicyViolation as e:
        conn.close()
        raise HTTPException(status_code=403, detail=f"Security policy violation: {e}")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/fetch")
async def fetch_url(request: Request):
    """
    Fetch a URL - demonstrates SSRF protection.

    Expected JSON:
    {
        "url": "https://example.com"
    }
    """
    try:
        flow = taint_flow.get()
        flow.append("fastapi_app.fetch_url")
        taint_flow.set(flow)
    except Exception:
        pass

    try:
        data = await request.json()
        url = data.get("url", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' field")

    try:
        # This will be blocked if URL points to localhost or private IPs
        response = requests.get(url, timeout=5)
        return {
            "status": "success",
            "url": url,
            "status_code": response.status_code,
            "content_length": len(response.content),
        }
    except PolicyViolation as e:
        raise HTTPException(status_code=403, detail=f"Security policy violation: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/template")
async def render_template(request: Request):
    """
    Render a template - demonstrates template injection protection.

    Expected JSON:
    {
        "template": "Hello {{ name }}",
        "name": "World"
    }
    """
    try:
        flow = taint_flow.get()
        flow.append("fastapi_app.render_template")
        taint_flow.set(flow)
    except Exception:
        pass

    try:
        data = await request.json()
        template_str = data.get("template", "")
        context = data.get("context", {})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not template_str:
        raise HTTPException(status_code=400, detail="Missing 'template' field")

    try:
        # This will be blocked if template contains dangerous expressions
        template = jinja2.Template(template_str)
        rendered = template.render(**context)
        return {"status": "success", "rendered": rendered}
    except PolicyViolation as e:
        raise HTTPException(status_code=403, detail=f"Security policy violation: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
