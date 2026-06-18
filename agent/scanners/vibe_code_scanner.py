import re
from .base import BaseScanner, ScannerResult, Severity


class VibeCodeScanner(BaseScanner):
    name = "vibe_code_security"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)

    def _scan_sql_injection(self, code: str) -> list:
        findings = []
        patterns = [
            (r"(?:execute|exec|query|run|raw)\s*\(?\s*['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE).*?['\"]\s*[+%].*?['\"]", "string_concatenated_sql_query"),
            (r"(?:\"|').*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE).*?(?:\"|')\s*\+", "sql_in_string_concat"),
            (r"\.format\(.*?\{.*?\}.*?\).*?(?:SELECT|INSERT|UPDATE|DELETE)", "sql_format_injection"),
            (r"f['\"].*?\{.*?\}.*?(?:SELECT|INSERT|UPDATE|DELETE)", "f_string_sql_injection"),
            (r"%(?:s|d|r|f)\s*(?:\)|,).*(?:SELECT|INSERT|UPDATE|DELETE)", "sql_percent_formatting"),
            (r"exec(?:ute)?\s*\(?\s*['\"]{3}.*?\{", "triple_quote_sql_injection"),
            (r"request\.(?:GET|POST|REQUEST|FORM)\[.*?\].*?(?:SELECT|INSERT|UPDATE|DELETE)", "user_input_direct_sql"),
            (r"(?<!_)id\s*=\s*request\.(?:GET|POST|REQUEST|FORM)\[", "unsafe_id_from_request"),
            (r"(?:WHERE|where)\s+\w+\s*=\s*['\"].*?\{.*?\}.*?['\"]", "where_clause_injection"),
            (r"execute_query\s*\(.*?request\.", "unsafe_query_execution"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "critical", "category": "sql_injection"})
        return findings

    def _scan_xss(self, code: str) -> list:
        findings = []
        patterns = [
            (r"innerHTML\s*[+=]?\s*['\"].*?[+%].*?['\"]|\.innerHTML\s*[+=]?\s*\w+", "unsafe_inner_html"),
            (r"document\.write\s*\([^)]*?(?:request|params|data|input|user|name|query|search)", "unsafe_document_write"),
            (r"dangerouslySetInnerHTML", "react_dangerous_html"),
            (r"v-html\s*=", "vue_dangerous_html"),
            (r"(?:<%=|<%-|<%\s*=)\s*(?:request|params|data|input|user|name|query)", "erb_unsafe_output"),
            (r"(?:{{|{!).*?(?:request|params|data|input|user|name|query).*?(?:}}|!})", "template_unsafe_var"),
            (r"\$_?(?:GET|POST|REQUEST|SERVER)\[.*?\].*?(?:echo|print|printf|write)", "php_direct_output"),
            (r"(?:append|prepend|after|before|html|replaceWith)\s*\([^)]*?(?:request|params|data|input|user)", "jquery_unsafe_insertion"),
            (r"(?:\"|').*?(?:<script|<img|<iframe|<svg|<body|<input).*?(?:\"|')\s*[+%]", "html_injection_concat"),
            (r"(?:eval|setTimeout|setInterval)\s*\([^)]*?(?:request|params|data|input|user|name)", "eval_user_input"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "critical", "category": "xss"})
        return findings

    def _scan_csrf(self, code: str) -> list:
        findings = []
        patterns = [
            (r"fetch\s*\([^)]*?\{[^}]*?method\s*:\s*['\"]?(?:POST|PUT|DELETE|PATCH)", "fetch_mutation_no_csrf"),
            (r"axios\.(?:post|put|delete|patch)\s*\([^)]*?(?:withCredentials\s*:\s*true)?", "axios_mutation"),
            (r"XMLHttpRequest\s*\(\).*?(?:open|send)\s*\([\"'](?:POST|PUT|DELETE|PATCH)", "xhr_mutation"),
            (r"(?:form|input).*?(?:action|method)\s*=\s*[\"']POST[\"']", "form_post_no_csrf"),
            (r"<form[^>]*?>\s*<input[^>]*?type=['\"]hidden['\"]", "form_hidden_input"),
            (r"@csrf\.exempt|@csrf_exempt|CSRFExempt", "csrf_exempt_decorator"),
            (r"csrf_protection\s*=\s*False|csrf=False|csrf_disabled", "csrf_disabled"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "high", "category": "csrf"})
        return findings

    def _scan_command_injection(self, code: str) -> list:
        findings = []
        patterns = [
            (r"(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_call|check_output))\s*\([^)]*?[+%f].*?\}", "command_injection_concat"),
            (r"(?:exec|eval|compile)\s*\([^)]*?(?:request|input|data|user|params|get|post|form)", "dynamic_code_execution"),
            (r"(?:`|exec|system|passthru|shell_exec|pcntl_exec)\s*\([^)]*?\$_", "php_command_injection"),
            (r"ProcessBuilder\s*\([^)]*?\.(?:inheritIO|directory)", "java_process_builder"),
            (r"(?:Runtime|Process)\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", "java_runtime_exec"),
            (r"subprocess\..*?shell\s*=\s*True", "subprocess_shell_true"),
            (r"(?:os\.system|os\.popen|subprocess)\s*\(.*?shell\s*=\s*True", "shell_true_injection"),
            (r"cmd\.exe|powershell\.exe|bash\s+-c|sh\s+-c", "shell_execution"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "critical", "category": "command_injection"})
        return findings

    def _scan_ssrf(self, code: str) -> list:
        findings = []
        patterns = [
            (r"(?:urlopen|urlopen|requests\.(?:get|post|put|delete|patch|head))\s*\([^)]*?(?:request|params|data|input|user|name|query|search)", "ssrf_user_input_url"),
            (r"(?:file_get_contents|fopen|curl_exec)\s*\([^)]*?\$_", "php_ssrf"),
            (r"(?:HttpURLConnection|URL|URI)\s*\([^)]*?(?:request|input|user|params)", "java_ssrf"),
            (r"axios\.(?:get|post)\s*\([^)]*?(?:request|input|user|params)", "axios_ssrf"),
            (r"fetch\s*\([^)]*?(?:request|input|user|params)", "fetch_ssrf"),
            (r"urllib\.(?:request|urlopen)\s*\([^)]*?(?:request|input|user|params)", "urllib_ssrf"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "high", "category": "ssrf"})
        return findings

    def _scan_insecure_crypto(self, code: str) -> list:
        findings = []
        patterns = [
            (r"MD5|md5\s*\(", "weak_hash_md5"),
            (r"SHA1|sha1\s*\(", "weak_hash_sha1"),
            (r"(?:DES|des)\s*\(", "weak_cipher_des"),
            (r"RC2|rc2\s*\(", "weak_cipher_rc2"),
            (r"RC4|rc4\s*\(", "weak_cipher_rc4"),
            (r"PKCS1_v1_5|PKCS1v15", "weak_padding_pkcs1"),
            (r"ECB\s*/\s*\w+\s*/\s*PKCS5|AES\.\s*ECB|'ECB'|\"ECB\"", "ecb_mode_insecure"),
            (r"(?:random|rand|mt_rand|Math\.random)\s*\(\s*\)\s*.*?(?:key|token|secret|password|nonce|iv)", "insecure_random_for_crypto"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "high", "category": "insecure_crypto"})
        return findings

    def _scan_path_traversal(self, code: str) -> list:
        findings = []
        patterns = [
            (r"(?:open|file|read|write|load|save|upload|download)\s*\([^)]*?\.\./|\.\.\\", "path_traversal"),
            (r"(?:open|file|read|write|load|save|upload|download)\s*\([^)]*?(?:request|input|user|params|query|search)", "user_input_file_path"),
            (r"os\.path\.join\s*\([^)]*?(?:request|input|user|params)", "unsafe_path_join"),
            (r"(?:Path|Paths|path)\s*\.\s*(?:get|of)\s*\([^)]*?(?:request|input|user|params)", "unsafe_path_get"),
            (r"__dirname\s*\+\s*['\"]\/.*?['\"]\s*\+\s*(?:request|input|user|params)", "unsafe_dirname_concat"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "high", "category": "path_traversal"})
        return findings

    def _scan_auth_bypass(self, code: str) -> list:
        findings = []
        patterns = [
            (r"(?:is_admin|is_authenticated|is_logged_in|check_auth|require_auth)\s*(?:=\s*True|=\s*1|:\s*True)", "auth_hardcoded_true"),
            (r"(?:@login_required|@auth_required|@permission_required)\s*\n?(?:def|class)", "auth_decorator_missing"),
            (r"if\s+(?:not\s+)?(?:user|request\.user|session)\s*(?:==|!=|is|is\s+not)\s*(?:None|null|undefined|false)", "weak_auth_check"),
            (r"(?:allow|permit|grant)_(?:all|any|everyone?|public)", "overly_permissive"),
            (r"(?:admin|root|superuser|super_admin)\s*(?:=\s*True|:\s*True|['\"]password['\"]|['\"]admin['\"])", "hardcoded_admin"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "critical", "category": "auth_bypass"})
        return findings

    def _scan_insecure_headers(self, code: str) -> list:
        findings = []
        patterns = [
            (r"Access-Control-Allow-Origin\s*:\s*\*", "cors_wildcard_origin"),
            (r"Access-Control-Allow-Credentials\s*:\s*true", "cors_credentials_wildcard"),
            (r"Content-Security-Policy\s*:\s*['\"]default-src\s+['\"]\*['\"]|['\"]default-src\s+\*['\"]", "csp_wildcard"),
            (r"(?:X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security)\s*(?::|=>|=)\s*(?!.*?(?:DENY|SAMEORIGIN|nosniff|max-age))", "missing_security_headers"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "high", "category": "insecure_headers"})
        return findings

    def _scan_insecure_deserialization(self, code: str) -> list:
        findings = []
        patterns = [
            (r"pickle\.loads?\s*\(", "insecure_pickle_deserialization"),
            (r"yaml\.load\s*\([^)]*?Loader\s*=\s*yaml\.Loader", "insecure_yaml_load"),
            (r"marshal\.loads?\s*\(", "insecure_marshal"),
            (r"jsonpickle\.decode\s*\(", "insecure_jsonpickle"),
            (r"(?:eval|exec)\s*\([^)]*?request", "eval_request_deserialization"),
            (r"PHP:\s*unserialize\s*\(", "php_unserialize"),
            (r"(?:ObjectInputStream|readObject|readUnshared)\s*\(", "java_deserialization"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "critical", "category": "insecure_deserialization"})
        return findings

    def _scan_config_exposure(self, code: str) -> list:
        findings = []
        patterns = [
            (r"DEBUG\s*=\s*True|debug\s*=\s*True|debug_mode\s*=\s*True", "debug_mode_enabled"),
            (r"(?:SECRET_KEY|secret_key|APP_SECRET|app_secret)\s*=\s*['\"](?:change|default|test|secret|key|password)[\"']", "weak_secret_key"),
            (r"(?:ALLOWED_HOSTS|allowed_hosts)\s*=\s*\[\s*['\"]\*['\"]", "wildcard_allowed_hosts"),
            (r"environment\s*=\s*['\"]development['\"]|env\s*=\s*['\"]dev['\"]", "development_env_in_prod"),
            (r"show_config\s*=\s*True|display_errors\s*=\s*On", "config_exposure"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                findings.append({"type": name, "severity": "high", "category": "config_exposure"})
        return findings

    def _scan_rate_limit(self, code: str) -> list:
        findings = []
        patterns = [
            (r"(?:for|while)\s+(?:\w+\s+in\s+range\s*\(\s*\d+\s*\)\s*:\s*\n\s*(?:requests\.(?:get|post)|urllib|fetch|axios))", "missing_rate_limit_unbounded_loop"),
            (r"(?:@ratelimit|@rate_limit|@throttle|@limiter)", "rate_limit_present"),
        ]
        has_limit = any(re.search(p, code, re.IGNORECASE | re.DOTALL) for p in [r"(?:@ratelimit|@rate_limit|@throttle|@limiter)"])
        loop_no_limit = any(re.search(p, code, re.IGNORECASE | re.DOTALL) for p in [r"(?:for|while)\s+(?:\w+\s+in\s+range\s*\(\s*\d+\s*\)\s*:\s*\n\s*(?:requests\.(?:get|post)|urllib|fetch|axios))"])
        if loop_no_limit and not has_limit:
            findings.append({"type": "missing_rate_limit", "severity": "medium", "category": "rate_limiting"})
        return findings

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="Vibe-code security scan: analyze generated code",
            details={"scan_type": "request", "note": "Response analysis performed on generated code"},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        code_blocks = self._extract_code_blocks(response)
        all_findings = []
        highest_severity = Severity.INFO
        sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        for lang, code in code_blocks:
            scanners = [
                self._scan_sql_injection, self._scan_xss, self._scan_csrf,
                self._scan_command_injection, self._scan_ssrf,
                self._scan_insecure_crypto, self._scan_path_traversal,
                self._scan_auth_bypass, self._scan_insecure_headers,
                self._scan_insecure_deserialization, self._scan_config_exposure,
                self._scan_rate_limit,
            ]
            for scanner in scanners:
                findings = scanner(code)
                for f in findings:
                    f["language"] = lang
                    all_findings.append(f)
                    f_sev = f.get("severity", "info")
                    if sev_order.get(f_sev, 0) > sev_order.get(highest_severity.value, 0):
                        highest_severity = Severity(f_sev) if f_sev in ("info","low","medium","high","critical") else Severity.MEDIUM

        passed = len(all_findings) == 0
        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=highest_severity,
            message=f"{'No vulnerabilities found in generated code' if passed else f'Found {len(all_findings)} security issue(s) in generated code'}",
            details={"findings": all_findings, "code_blocks_analyzed": len(code_blocks)},
            suggestion="Review flagged vulnerabilities before deploying AI-generated code." if not passed else None,
        )

    def _extract_code_blocks(self, text: str) -> list:
        blocks = []
        pattern = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
        for match in pattern.finditer(text):
            lang = match.group(1).lower() if match.group(1) else "unknown"
            code = match.group(2)
            blocks.append((lang, code))
        inline_pattern = re.compile(r"`([^`]+)`")
        for match in inline_pattern.finditer(text):
            code = match.group(1)
            blocks.append(("inline", code))
        return blocks
