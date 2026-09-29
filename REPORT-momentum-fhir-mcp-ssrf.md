# Server-Side Request Forgery in Momentum FHIR MCP Server (`add_document_to_pinecone`)

## Metadata

| | |
|---|---|
| Product | Momentum FHIR MCP Server (`the-momentum/fhir-mcp-server`, themomentum.ai) |
| Version | commit `df048bc8d4e8a784f2dd3e690d43e535355ea7ef` (current `main`) |
| Component | `app/services/rag/document_service.py`, `app/services/rag/document_processor.py`, `app/mcp/v1/tools/document_reference.py` |
| Vulnerability class | Server-Side Request Forgery (CWE-918) |
| Severity | High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:L` (8.3) |

## Summary

The `add_document_to_pinecone` MCP tool accepts a `url` argument that is fetched by the
server with no validation whatsoever — no scheme or host allowlist, no block on
internal/link-local addresses, and no timeout. An attacker who can influence the tool
argument (via indirect prompt injection in content the agent reads, or by having the agent
index a supplied URL) causes the server to issue an HTTP GET to an arbitrary destination.
On cloud infrastructure this reaches the instance metadata service
(`http://169.254.169.254/…`) to steal IAM credentials, and reaches any internal-only
service on the server's network.

The `search_pinecone` tool's documented rules **auto-trigger** `add_document_to_pinecone`
when a document is not yet indexed, so the vulnerable path is reachable during a normal
search flow.

## Affected code

`Document.url` is an unconstrained string (`app/schemas/document_schemas.py`):

```python
class Document(BaseModel):
    url: str
    fhir_document_id: str
    format: DocumentFormat | None = None
```

The tool passes it to the processor (`app/mcp/v1/tools/document_reference.py`):

```python
@document_reference_router.tool
async def add_document_to_pinecone(document: Document) -> str | PineconeError:
    ...
    document_processor.process_document(document=document)
```

which fetches it with no controls (`app/services/rag/document_processor.py` →
`app/services/rag/document_service.py:26`):

```python
pdf_bytes = download_bytes(url=document.url)      # document_processor.py
# ...
def download_bytes(url: str) -> bytes:            # document_service.py
    response = requests.get(url)                  # no allowlist, no internal-IP block, no timeout
    response.raise_for_status()
    return response.content
```

## Proof of concept

`poc_ssrf_download.py` extracts and runs the project's exact `download_bytes` source
(verbatim, via AST — so the heavy RAG stack need not be installed) against a simulated
internal endpoint:

```
python3 poc_ssrf_download.py
```

Output:

```
=== running this exact function from document_service.py ===
def download_bytes(url: str) -> bytes:
    response = requests.get(url)
    response.raise_for_status()
    return response.content

internal endpoint was reached: '/latest/meta-data/iam/security-credentials/role'
server fetched attacker URL and returned its body to the app: {"AccessKeyId":"ASIA-STOLEN",...}
>>> SSRF CONFIRMED: arbitrary-URL fetch, no allowlist/timeout.
```

In a live deployment the attacker sets
`url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>"` (AWS) or
the GCP/Azure equivalent; the fetched credential body is returned into the document pipeline
and can be surfaced back through the agent.

## Impact

- **Cloud credential theft / account compromise** where the server runs on a cloud instance
  with a reachable metadata endpoint (the common deployment).
- **Internal network access:** authenticated or unauthenticated GETs to services reachable
  from the server but not from the internet (admin panels, databases, other internal APIs).
- **Denial of service:** `requests.get` has no timeout, so a slow/hanging endpoint ties up
  the worker.
- **Trigger:** the `url` originates from an LLM tool argument, reachable via indirect prompt
  injection in agent-visible content; `search_pinecone` auto-invokes the vulnerable tool.

Impact ceiling depends on the deployment environment (cloud + reachable metadata / internal
services), but the unrestricted-fetch primitive is unconditional.

## Remediation

1. Validate `Document.url`: require `https`, resolve the host and reject private, loopback,
   and link-local ranges (including `169.254.169.254` and IPv6 equivalents), and reject
   redirects to such ranges.
2. Apply an egress allowlist of permitted document hosts, and set an explicit
   `requests.get(url, timeout=..., allow_redirects=False)`.
3. Consider fetching documents only from URLs that appear in the referenced FHIR
   `DocumentReference.content.attachment.url`, validated against the same allowlist, rather
   than an arbitrary tool-supplied URL.

## Disclosure

Reported privately to hello@themomentum.ai per the repository SECURITY.md, before any public
disclosure. Reporter: Clinton Obi, clinton.obi@vnsis.com.
