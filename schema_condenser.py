"""
AHVF — Module 2: Schema Condenser (FR-04)
==========================================
Implements FR-04.1 through FR-04.5:
  FR-04.1  Strip HTTP headers to method, path, content-type, param structure
  FR-04.2  Replace concrete values with typed placeholders (INT, STRING, etc.)
  FR-04.3  Separate file upload endpoints — capture MIME type + filename only
  FR-04.4  Group by structural fingerprint — deduplicate identical schemas
  FR-04.5  Attach contextual metadata (path-inferred function hints)

Input:  SQLite endpoints table (populated by M1 Crawler)
        OR crawl_results.json fallback
Output: List of CondensedSchema objects, written to SQLite + JSON

NOTE: Zero PII must pass through this module.  All concrete parameter
      values are replaced with typed placeholders before any data
      reaches the LLM in M3.

USAGE:
    from schema_condenser import SchemaCondenser
    from database import AHVFDatabase

    db = AHVFDatabase()
    db.initialize()
    condenser = SchemaCondenser(db)
    schemas = condenser.condense()
"""

import hashlib
import json
import re
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
#  DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class CondensedSchema:
    """
    A sanitised, deduplicated representation of an endpoint group.

    This is what gets sent to the LLM in M3.  It must NEVER contain
    concrete PII, session tokens, or response body content.
    """
    schema_hash:        str                         # Dedup fingerprint
    method:             str                         # HTTP method
    path:               str                         # URL path (no host/scheme)
    content_type:       Optional[str] = None        # Content-Type header
    params:             dict = field(default_factory=dict)  # param_name -> typed placeholder
    endpoint_count:     int = 1                     # How many endpoints share this schema
    roles:              list[str] = field(default_factory=list)  # Which roles have access
    context_hints:      list[str] = field(default_factory=list)  # FR-04.5 inferred function
    is_file_upload:     bool = False                # FR-04.3 flag
    upload_mime_types:  list[str] = field(default_factory=list)  # FR-04.3
    has_graphql:        bool = False                # GraphQL endpoint flag
    form_fields:        dict = field(default_factory=dict)  # form field name -> type


# ─────────────────────────────────────────────
#  TYPE DETECTION (FR-04.2)
# ─────────────────────────────────────────────

# Regex patterns for value type inference
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
JWT_PATTERN = re.compile(r'^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
INT_PATTERN = re.compile(r'^-?\d+$')
FLOAT_PATTERN = re.compile(r'^-?\d+\.\d+$')
BOOL_PATTERN = re.compile(r'^(true|false)$', re.IGNORECASE)
EMAIL_PATTERN = re.compile(r'^[^@]+@[^@]+\.[^@]+$')


def _infer_type(value: str) -> str:
    """
    Infer the typed placeholder for a concrete parameter value (FR-04.2).

    Returns one of: INT, FLOAT, STRING, UUID, BOOL, JWT, EMAIL, ARRAY, OBJECT
    """
    if value is None:
        return "STRING"

    value_str = str(value).strip()

    if not value_str:
        return "STRING"

    # Check specific patterns first (most specific → least specific)
    if JWT_PATTERN.match(value_str):
        return "JWT"
    if UUID_PATTERN.match(value_str):
        return "UUID"
    if BOOL_PATTERN.match(value_str):
        return "BOOL"
    if INT_PATTERN.match(value_str):
        return "INT"
    if FLOAT_PATTERN.match(value_str):
        return "FLOAT"
    if EMAIL_PATTERN.match(value_str):
        return "EMAIL"

    # Check if it's a JSON array or object
    try:
        parsed = json.loads(value_str)
        if isinstance(parsed, list):
            return "ARRAY"
        if isinstance(parsed, dict):
            return "OBJECT"
    except (json.JSONDecodeError, TypeError):
        pass

    return "STRING"


def _infer_type_from_name(param_name: str) -> str:
    """
    Fallback type inference based on parameter name patterns.
    Used when no concrete value is available.
    """
    name_lower = param_name.lower()

    if any(kw in name_lower for kw in ("id", "count", "num", "page", "limit", "offset", "size")):
        return "INT"
    if any(kw in name_lower for kw in ("email", "mail")):
        return "EMAIL"
    if any(kw in name_lower for kw in ("uuid", "guid")):
        return "UUID"
    if any(kw in name_lower for kw in ("token", "jwt", "bearer", "auth")):
        return "JWT"
    if any(kw in name_lower for kw in ("active", "enabled", "disabled", "is_", "has_", "flag")):
        return "BOOL"
    if any(kw in name_lower for kw in ("price", "amount", "rate", "score", "lat", "lng", "longitude", "latitude")):
        return "FLOAT"
    if any(kw in name_lower for kw in ("tags", "items", "list", "ids", "roles")):
        return "ARRAY"

    return "STRING"


# ─────────────────────────────────────────────
#  CONTEXT HINTS (FR-04.5)
# ─────────────────────────────────────────────

# Path segment → inferred function mapping
CONTEXT_HINT_PATTERNS = {
    "export":       "FILE_GENERATION — likely CSV/XLSX export; test injection via file extension param",
    "import":       "FILE_IMPORT — test for path traversal and SSRF via uploaded file content",
    "upload":       "FILE_UPLOAD — test SSTI via filename, MIME type bypass",
    "download":     "FILE_DOWNLOAD — test path traversal, IDOR via file ID",
    "search":       "SEARCH — possible SQL context + HTML reflection (polyglot candidate)",
    "login":        "AUTHENTICATION — test credential stuffing, brute force, bypass",
    "auth":         "AUTHENTICATION — test token manipulation, session fixation",
    "admin":        "ADMIN_PANEL — high-value BAC target",
    "user":         "USER_DATA — test IDOR, BAC, data exposure",
    "profile":      "USER_PROFILE — test stored XSS, IDOR",
    "settings":     "SETTINGS — test privilege escalation, BAC",
    "delete":       "DESTRUCTIVE_ACTION — test CSRF, BAC on deletion",
    "reset":        "PASSWORD_RESET — test token prediction, account takeover",
    "password":     "PASSWORD — test credential exposure, reset flow bypass",
    "api":          "API_ENDPOINT — test authentication, rate limiting",
    "graphql":      "GRAPHQL — test introspection, injection, DoS via nested queries",
    "webhook":      "WEBHOOK — test SSRF, injection via callback URL",
    "callback":     "CALLBACK — test SSRF, open redirect",
    "redirect":     "REDIRECT — test open redirect, SSRF",
    "report":       "REPORT_GENERATION — test injection via report parameters",
    "payment":      "PAYMENT — test price manipulation, IDOR",
    "checkout":     "CHECKOUT — test price manipulation, race conditions",
    "comment":      "USER_CONTENT — test stored XSS, injection",
    "message":      "USER_CONTENT — test stored XSS, injection",
    "file":         "FILE_HANDLING — test path traversal, upload bypass",
    "image":        "MEDIA — test upload bypass, SSRF via image URL",
    "config":       "CONFIGURATION — test information disclosure, BAC",
    "debug":        "DEBUG — test information disclosure, should not be exposed",
    "log":          "LOGGING — test information disclosure, log injection",
    "internal":     "INTERNAL — should not be publicly accessible, BAC candidate",
}


def _get_context_hints(path: str) -> list[str]:
    """
    Infer functional context from URL path segments (FR-04.5).

    Returns a list of context hint strings that inform AI payload selection.
    """
    hints = []
    segments = path.lower().split("/")

    for segment in segments:
        for keyword, hint in CONTEXT_HINT_PATTERNS.items():
            if keyword in segment:
                hints.append(hint)
                break  # One hint per segment

    return hints


# ─────────────────────────────────────────────
#  FILE UPLOAD DETECTION (FR-04.3)
# ─────────────────────────────────────────────

def _detect_file_upload(endpoint: dict) -> tuple[bool, list[str]]:
    """
    Detect if an endpoint handles file uploads.

    Checks:
      - Content-Type: multipart/form-data
      - Form fields with type="file"
      - Path segments containing upload/file/attach keywords

    Returns (is_file_upload, list_of_mime_types).
    """
    is_upload = False
    mime_types = []

    # Check content-type header
    headers = endpoint.get("headers", {})
    content_type = ""
    if isinstance(headers, dict):
        content_type = headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        is_upload = True

    # Check form structure for file inputs
    form_structure = endpoint.get("form_structure")
    if form_structure and isinstance(form_structure, dict):
        fields = form_structure.get("fields", {})
        for field_name, field_type in fields.items():
            if field_type == "file":
                is_upload = True
                # Infer MIME from field name
                name_lower = field_name.lower()
                if any(kw in name_lower for kw in ("image", "photo", "avatar", "picture")):
                    mime_types.append("image/*")
                elif any(kw in name_lower for kw in ("document", "doc", "pdf")):
                    mime_types.append("application/pdf")
                elif any(kw in name_lower for kw in ("csv", "excel", "spreadsheet")):
                    mime_types.append("text/csv")
                else:
                    mime_types.append("application/octet-stream")

    # Check URL path for upload indicators
    url = endpoint.get("url", "")
    path = urllib.parse.urlparse(url).path.lower()
    if any(kw in path for kw in ("upload", "attach", "import")):
        is_upload = True

    return is_upload, mime_types


# ─────────────────────────────────────────────
#  PARAMETER EXTRACTION & SANITISATION
# ─────────────────────────────────────────────

def _extract_params(endpoint: dict) -> dict[str, str]:
    """
    Extract parameters from an endpoint and replace values with
    typed placeholders (FR-04.2).

    Sources of parameters:
      1. Query string parameters from the URL
      2. POST body (JSON or form-encoded)
      3. Form structure fields

    Returns dict of param_name -> type_placeholder.
    """
    params = {}

    # 1. Query string parameters
    url = endpoint.get("url", "")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    for name, values in query_params.items():
        # Use first value for type inference, then replace
        val = values[0] if values else ""
        params[name] = _infer_type(val)

    # 2. POST body
    body = endpoint.get("body")
    if body:
        # Try JSON body
        try:
            body_json = json.loads(body)
            if isinstance(body_json, dict):
                for key, value in body_json.items():
                    if isinstance(value, list):
                        params[key] = "ARRAY"
                    elif isinstance(value, dict):
                        params[key] = "OBJECT"
                    elif isinstance(value, bool):
                        params[key] = "BOOL"
                    elif isinstance(value, int):
                        params[key] = "INT"
                    elif isinstance(value, float):
                        params[key] = "FLOAT"
                    else:
                        params[key] = _infer_type(str(value))
        except (json.JSONDecodeError, TypeError):
            # Try form-encoded body
            try:
                form_params = urllib.parse.parse_qs(body)
                for name, values in form_params.items():
                    val = values[0] if values else ""
                    params[name] = _infer_type(val)
            except Exception:
                pass

    # 3. Form structure fields (from Crawler's form discovery)
    form_structure = endpoint.get("form_structure")
    if form_structure and isinstance(form_structure, dict):
        fields = form_structure.get("fields", {})
        for field_name, field_type in fields.items():
            if field_name not in params:
                # Infer from HTML input type
                type_map = {
                    "text": "STRING",
                    "email": "EMAIL",
                    "number": "INT",
                    "password": "STRING",
                    "url": "STRING",
                    "search": "STRING",
                    "tel": "STRING",
                    "hidden": "STRING",
                    "checkbox": "BOOL",
                    "radio": "STRING",
                    "file": "FILE",
                    "date": "STRING",
                    "datetime-local": "STRING",
                }
                params[field_name] = type_map.get(field_type, "STRING")

    # 4. Fallback: if no params extracted, try inferring from param name patterns
    # for any params that are still "STRING"
    for name in list(params.keys()):
        if params[name] == "STRING":
            inferred = _infer_type_from_name(name)
            if inferred != "STRING":
                params[name] = inferred

    return params


# ─────────────────────────────────────────────
#  SCHEMA CONDENSER CLASS
# ─────────────────────────────────────────────

class SchemaCondenser:
    """
    Module 2: Schema Condenser.

    Reads raw endpoint data from the SQLite database (or JSON fallback),
    sanitises it by stripping PII and replacing values with typed
    placeholders, deduplicates by structural fingerprint, and attaches
    contextual metadata for the AI Payload Orchestrator (M3).
    """

    def __init__(self, db=None):
        """
        Args:
            db: AHVFDatabase instance. If None, will use JSON file fallback.
        """
        self.db = db

    def condense(self, json_fallback_path: Optional[str] = None) -> list[CondensedSchema]:
        """
        Main entry point: condense all endpoints into deduplicated schemas.

        Reads from SQLite if db is available, otherwise falls back to
        reading crawl_results.json.

        Returns list of CondensedSchema objects.
        """
        # Step 1: Load raw endpoints
        endpoints = self._load_endpoints(json_fallback_path)
        if not endpoints:
            print("[M2] No endpoints found to condense")
            return []

        print(f"[M2] Loaded {len(endpoints)} raw endpoint(s)")

        # Step 2: Group by schema_hash (FR-04.4 deduplication)
        groups = self._group_by_schema(endpoints)
        print(f"[M2] Grouped into {len(groups)} unique schema(s) (dedup ratio: "
              f"{len(endpoints)}/{len(groups)} = {len(endpoints)/max(len(groups),1):.1f}x)")

        # Step 3: Condense each group into a CondensedSchema
        schemas = []
        for schema_hash, group_endpoints in groups.items():
            schema = self._condense_group(schema_hash, group_endpoints)
            schemas.append(schema)

        # Step 4: Sort by endpoint count (most common schemas first)
        schemas.sort(key=lambda s: s.endpoint_count, reverse=True)

        print(f"[M2] Condensation complete: {len(schemas)} schema(s)")
        self._print_summary(schemas)

        return schemas

    def condense_and_store(self, json_fallback_path: Optional[str] = None) -> list[CondensedSchema]:
        """
        Condense schemas and write the result to a JSON file.

        This is the file that M3 (Payload Orchestrator) will read.
        """
        schemas = self.condense(json_fallback_path)

        # Write condensed schemas to JSON for M3 consumption
        output_path = Path("results") / "condensed_schemas.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        serialised = [asdict(s) for s in schemas]
        output_path.write_text(
            json.dumps(serialised, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[M2] Condensed schemas written to {output_path}")

        return schemas

    # ── Internal Methods ─────────────────────────────────────────

    def _load_endpoints(self, json_fallback_path: Optional[str] = None) -> list[dict]:
        """Load endpoints from SQLite or JSON fallback."""
        # Try SQLite first
        if self.db:
            try:
                endpoints = self.db.get_all_endpoints()
                if endpoints:
                    return endpoints
                print("[M2] SQLite endpoints table is empty, trying JSON fallback...")
            except Exception as e:
                print(f"[M2] SQLite read failed: {e}, trying JSON fallback...")

        # JSON fallback
        fallback = Path(json_fallback_path) if json_fallback_path else Path("results") / "crawl_results.json"
        if fallback.exists():
            print(f"[M2] Loading from JSON fallback: {fallback}")
            raw = json.loads(fallback.read_text(encoding="utf-8"))

            # crawl_results.json has a nested structure:
            # { "results": [ { "role": "...", "endpoints": [...] }, ... ] }
            endpoints = []
            for role_result in raw.get("results", []):
                role = role_result.get("role", "unknown")
                for ep in role_result.get("endpoints", []):
                    ep["role"] = role  # Ensure role is set
                    endpoints.append(ep)

            # If loading from JSON, also populate the SQLite DB
            if self.db and endpoints:
                print(f"[M2] Populating SQLite from JSON ({len(endpoints)} endpoints)...")
                self.db.insert_endpoints(endpoints)

            return endpoints

        print(f"[M2] No data source found (no SQLite data, no JSON at {fallback})")
        return []

    def _group_by_schema(self, endpoints: list[dict]) -> dict[str, list[dict]]:
        """Group endpoints by schema_hash for deduplication (FR-04.4)."""
        groups = defaultdict(list)
        for ep in endpoints:
            schema_hash = ep.get("schema_hash", "")
            if schema_hash:
                groups[schema_hash].append(ep)
            else:
                # Generate hash if missing
                url = ep.get("url", "")
                method = ep.get("method", "GET")
                parsed = urllib.parse.urlparse(url)
                params = sorted(urllib.parse.parse_qs(parsed.query).keys())
                canonical = f"{method.upper()}:{parsed.scheme}://{parsed.netloc}{parsed.path}?{','.join(params)}"
                h = hashlib.sha256(canonical.encode()).hexdigest()[:16]
                groups[h].append(ep)
        return dict(groups)

    def _condense_group(self, schema_hash: str, endpoints: list[dict]) -> CondensedSchema:
        """
        Condense a group of structurally identical endpoints
        into a single CondensedSchema.
        """
        # Use the first endpoint as the representative
        rep = endpoints[0]

        # Extract path (strip host/scheme — FR-04.1)
        url = rep.get("url", "")
        parsed = urllib.parse.urlparse(url)
        path = parsed.path

        # Determine content type (FR-04.1)
        headers = rep.get("headers", {})
        content_type = None
        if isinstance(headers, dict):
            content_type = headers.get("content-type", headers.get("Content-Type"))

        # Extract and sanitise parameters (FR-04.2)
        params = _extract_params(rep)

        # Collect roles from all endpoints in the group
        roles = list(set(ep.get("role", "unknown") for ep in endpoints))

        # Detect file upload (FR-04.3)
        is_upload, mime_types = _detect_file_upload(rep)

        # Get context hints (FR-04.5)
        context_hints = _get_context_hints(path)

        # Check for GraphQL
        has_graphql = "graphql" in path.lower() or rep.get("source", "") == "graphql"

        # Extract form fields if present
        form_fields = {}
        form_structure = rep.get("form_structure")
        if form_structure and isinstance(form_structure, dict):
            raw_fields = form_structure.get("fields", {})
            for fname, ftype in raw_fields.items():
                form_fields[fname] = ftype

        return CondensedSchema(
            schema_hash=schema_hash,
            method=rep.get("method", "GET"),
            path=path,
            content_type=content_type,
            params=params,
            endpoint_count=len(endpoints),
            roles=roles,
            context_hints=context_hints,
            is_file_upload=is_upload,
            upload_mime_types=mime_types,
            has_graphql=has_graphql,
            form_fields=form_fields,
        )

    def _print_summary(self, schemas: list[CondensedSchema]):
        """Print a brief summary of the condensed schemas."""
        print(f"\n{'─'*50}")
        print(f"  M2 Condensation Summary")
        print(f"{'─'*50}")
        print(f"  Total unique schemas : {len(schemas)}")
        print(f"  File upload schemas  : {sum(1 for s in schemas if s.is_file_upload)}")
        print(f"  GraphQL schemas      : {sum(1 for s in schemas if s.has_graphql)}")
        print(f"  With context hints   : {sum(1 for s in schemas if s.context_hints)}")
        print(f"  Methods distribution :")

        method_counts = defaultdict(int)
        for s in schemas:
            method_counts[s.method] += 1
        for method, count in sorted(method_counts.items()):
            print(f"    {method:8s} : {count}")

        print(f"{'─'*50}\n")

    # ── Formatting for LLM (used by M3) ─────────────────────────

    @staticmethod
    def format_for_llm(schemas: list[CondensedSchema], batch_size: int = 50) -> list[str]:
        """
        Format condensed schemas into prompt-ready batches for M3.

        Each batch is a JSON-encoded list of schema summaries,
        sized according to FR-05.1 (default 50 schemas per batch).

        Returns a list of JSON strings, each suitable for injection
        into the LLM user prompt.
        """
        batches = []

        for i in range(0, len(schemas), batch_size):
            batch = schemas[i:i + batch_size]
            formatted = []

            for schema in batch:
                entry = {
                    "schema_hash": schema.schema_hash,
                    "method": schema.method,
                    "path": schema.path,
                    "content_type": schema.content_type,
                    "params": schema.params,
                    "roles": schema.roles,
                    "context_hints": schema.context_hints,
                }

                if schema.is_file_upload:
                    entry["is_file_upload"] = True
                    entry["upload_mime_types"] = schema.upload_mime_types

                if schema.has_graphql:
                    entry["has_graphql"] = True

                if schema.form_fields:
                    entry["form_fields"] = schema.form_fields

                formatted.append(entry)

            batches.append(json.dumps(formatted, indent=2, ensure_ascii=False))

        return batches


# ─────────────────────────────────────────────
#  STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== Schema Condenser Test ===\n")

    # Try with JSON fallback (no DB required for standalone test)
    condenser = SchemaCondenser(db=None)
    schemas = condenser.condense_and_store()

    if schemas:
        print(f"\nFirst 3 schemas:")
        for s in schemas[:3]:
            print(f"  {s.method:6s} {s.path}")
            print(f"         Params: {s.params}")
            print(f"         Roles:  {s.roles}")
            print(f"         Hints:  {s.context_hints}")
            print()

        # Show LLM-ready batches
        batches = SchemaCondenser.format_for_llm(schemas)
        print(f"LLM batches: {len(batches)} batch(es)")
    else:
        print("No schemas to condense. Run the Crawler first.")
