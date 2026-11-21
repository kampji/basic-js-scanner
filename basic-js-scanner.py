#!/usr/bin/env python3
"""
basic-js-scanner.py - JavaScript recon & static analysis scanner for web app pentests.

Finds in client-side JavaScript:
  * API endpoints / URLs / paths (with HTTP method when it can be inferred)
  * Source maps (sourceMappingURL comments, SourceMap headers, and blind <file>.js.map probes),
    downloads them, extracts original sources and scans those too
  * Hardcoded secrets (cloud keys, tokens, JWTs, connection strings, generic creds)
  * Dangerous code: DOM XSS sinks, eval-family, postMessage issues, open-redirect sinks,
    Angular/React/Vue escape hatches, prototype pollution hints, token storage
  * Additional JS files referenced from JS (webpack chunk maps, Next.js build manifests, imports)

Input modes (combinable):
  -u / --url    https://target.com      crawl page(s), collect <script src>, inline scripts, preloads
  -j / --js     https://t.com/app.js    single JS file (URL or local path)
  -l / --list   jsfiles.txt             list of JS URLs and/or local paths, one per line

Examples:
  python3 basic-js-scanner.py -u https://app.example.com -o out/
  python3 basic-js-scanner.py -u https://app.example.com --depth 2 --recurse 2 -c "session=abc" -o out/
  python3 basic-js-scanner.py -j https://app.example.com/static/js/main.3f2a1.js
  python3 basic-js-scanner.py -l js_urls.txt --proxy http://127.0.0.1:8080 -k -o out/

Notes:
  Analysis is pattern-based (regex over raw source with context windows), not a full AST/taint
  engine. Treat "dangerous code" hits as leads for manual review, not confirmed vulns.
  Only scan systems you are authorized to test.
"""

from __future__ import annotations

import argparse
import base64
import bisect
import json
import math
import os
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from html import escape
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    sys.exit("[!] 'requests' is required:  pip install requests")

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

VERSION = "1.0"
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


# --------------------------------------------------------------------------------------------
# Console colors
# --------------------------------------------------------------------------------------------
class C:
    on = sys.stdout.isatty()
    codes = {"critical": "\033[1;97;41m", "high": "\033[1;91m", "medium": "\033[1;93m",
             "low": "\033[1;94m", "info": "\033[90m", "ok": "\033[92m", "dim": "\033[90m",
             "bold": "\033[1m", "reset": "\033[0m"}

    @classmethod
    def c(cls, key, text):
        return f"{cls.codes[key]}{text}{cls.codes['reset']}" if cls.on else text


def log(msg, kind="*"):
    sym = {"*": C.c("dim", "[*]"), "+": C.c("ok", "[+]"), "!": C.c("high", "[!]"),
           "-": C.c("dim", "[-]")}[kind]
    print(f"{sym} {msg}", file=sys.stderr)


# --------------------------------------------------------------------------------------------
# Helpers / validators
# --------------------------------------------------------------------------------------------
def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


PLACEHOLDER_RE = re.compile(
    r"(?i)(x{4,}|\*{3,}|your[_-]?|example|placeholder|changeme|dummy|sample|redacted|"
    r"undefined|null|true|false|<[^>]+>|\{\{|\$\{|%s|^test$|^password$|lorem)")


def v_generic_secret(val, m):
    v = m.group("val") if "val" in m.re.groupindex else val
    if PLACEHOLDER_RE.search(v):
        return False
    if re.fullmatch(r"[a-z_.\-]+", v) or re.fullmatch(r"[A-Z_.\-]+", v):  # i18n keys / words / consts
        return False
    if re.fullmatch(r"[\w.-]+\.[\w.-]+", v) and not re.search(r"\d", v):  # dotted property paths
        return False
    return shannon(v) >= 3.0


def v_jwt(val, m):
    try:
        head = val.split(".")[0]
        head += "=" * (-len(head) % 4)
        return b'"alg"' in base64.urlsafe_b64decode(head)
    except Exception:
        return False


def v_high_entropy(val, m):
    return shannon(val) >= 3.2


def v_not_placeholder(val, m):
    return not PLACEHOLDER_RE.search(val)


def v_api_path_has_slash(val, m):
    return True


# --------------------------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    category: str
    severity: str
    title: str
    pattern: str
    flags: int = 0
    group: int | str = 0
    validator: object = None
    advice: str = ""

    def __post_init__(self):
        self.regex = re.compile(self.pattern, self.flags)


RULES = [
    # ---------------- Secrets ----------------
    Rule("private-key", "secret", "critical", "Private key material",
         r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    Rule("aws-access-key", "secret", "high", "AWS access key ID",
         r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b",
         advice="Check for a paired secret key nearby; validate with `aws sts get-caller-identity`."),
    Rule("aws-secret-key", "secret", "critical", "AWS secret access key (assignment)",
         r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"`]([A-Za-z0-9/+=]{40})['\"`]", group=1,
         validator=v_high_entropy),
    Rule("azure-conn-string", "secret", "critical", "Azure Storage connection string",
         r"DefaultEndpointsProtocol=https?;AccountName=[^;'\"`\s]+;AccountKey=[A-Za-z0-9+/=]{20,}"),
    Rule("azure-sas", "secret", "high", "Azure SAS token",
         r"[?&]sv=\d{4}-\d{2}-\d{2}&[^'\"`\s]{0,300}?sig=[A-Za-z0-9%+/=]{20,}"),
    Rule("gcp-service-account", "secret", "critical", "GCP service account JSON",
         r"\"type\"\s*:\s*\"service_account\""),
    Rule("google-api-key", "secret", "medium", "Google API key",
         r"\bAIza[0-9A-Za-z\-_]{35}\b",
         advice="Often intentionally public (Maps/Firebase). Check API restrictions & enabled APIs."),
    Rule("google-oauth-secret", "secret", "high", "Google OAuth client secret",
         r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
    Rule("github-token", "secret", "critical", "GitHub token",
         r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    Rule("gitlab-token", "secret", "critical", "GitLab token", r"\bglpat-[A-Za-z0-9_-]{20}\b"),
    Rule("slack-token", "secret", "high", "Slack token", r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"),
    Rule("slack-webhook", "secret", "high", "Slack incoming webhook",
         r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]{20,}"),
    Rule("teams-webhook", "secret", "high", "MS Teams webhook",
         r"https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[^\s'\"`]+"),
    Rule("discord-webhook", "secret", "high", "Discord webhook",
         r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    Rule("stripe-secret", "secret", "critical", "Stripe secret/restricted key",
         r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b"),
    Rule("stripe-publishable", "secret", "info", "Stripe publishable key (public by design)",
         r"\bpk_live_[0-9a-zA-Z]{20,}\b"),
    Rule("sendgrid", "secret", "high", "SendGrid API key", r"\bSG\.[\w-]{22}\.[\w-]{43}\b"),
    Rule("twilio", "secret", "medium", "Twilio API key SID", r"\bSK[0-9a-f]{32}\b"),
    Rule("mailgun", "secret", "high", "Mailgun API key", r"\bkey-[0-9a-zA-Z]{32}\b"),
    Rule("openai", "secret", "critical", "OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b",
         validator=v_high_entropy),
    Rule("anthropic", "secret", "critical", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{40,}\b"),
    Rule("npm-token", "secret", "high", "npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    Rule("shopify", "secret", "high", "Shopify token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    Rule("square", "secret", "high", "Square token", r"\bEAAA[a-zA-Z0-9_-]{60}\b"),
    Rule("jwt", "secret", "medium", "Hardcoded JWT",
         r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", validator=v_jwt,
         advice="Decode it: check exp, roles, and whether it's accepted by the API."),
    Rule("basic-auth-url", "secret", "high", "Credentials embedded in URL",
         r"\b[a-z][a-z0-9+.-]{1,10}://[^/\s:@'\"`]{1,64}:[^/\s:@'\"`]{1,64}@[\w.-]+",
         validator=v_not_placeholder),
    Rule("auth-header", "secret", "high", "Hardcoded Authorization header",
         r"(?i)['\"`]?authorization['\"`]?\s*[:=]\s*['\"`]((?:Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{12,})['\"`]",
         group=1, validator=v_not_placeholder),
    Rule("generic-secret", "secret", "medium", "Possible hardcoded secret",
         r"(?i)['\"`]?\b(?P<key>[\w-]*(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|"
         r"auth[_-]?token|private[_-]?key|passw(?:or)?d|pwd|credential)s?)['\"`]?\s*[:=]\s*"
         r"['\"`](?P<val>[^'\"`\s]{8,200})['\"`]",
         group=0, validator=v_generic_secret),
    Rule("firebase-db", "infra", "info", "Firebase Realtime DB URL",
         r"\b[a-z0-9-]+\.firebaseio\.com\b",
         advice="Test unauthenticated read: GET https://<db>.firebaseio.com/.json"),
    Rule("firebase-storage", "infra", "info", "Firebase storage bucket", r"\b[a-z0-9-]+\.appspot\.com\b"),
    Rule("s3-bucket", "infra", "info", "AWS S3 bucket reference",
         r"\b[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\b|"
         r"\bs3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\b|\bs3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/[a-z0-9][a-z0-9.-]{1,61}",
         advice="Check listing/upload permissions (aws s3 ls s3://bucket --no-sign-request)."),
    Rule("azure-blob", "infra", "info", "Azure Blob storage reference",
         r"\b[a-z0-9]{3,24}\.blob\.core\.windows\.net(?:/[\w$.-]+)?",
         advice="Check for anonymous container listing: ?restype=container&comp=list"),
    Rule("gcs-bucket", "infra", "info", "Google Cloud Storage reference",
         r"\bstorage\.googleapis\.com/[a-z0-9][\w.-]+|\b[a-z0-9][\w.-]+\.storage\.googleapis\.com\b"),
    Rule("private-ip", "infra", "low", "Private/internal IP address",
         r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
         r"(?![\d.])"),
    Rule("internal-host", "infra", "low", "Internal / non-prod hostname",
         r"\bhttps?://[\w.-]*(?:\b|[-.])(?:dev|develop|staging|stage|stg|uat|qa|test|sandbox|preprod|internal|intranet|corp|local)"
         r"(?:\b|[-.\d])[\w.-]*(?::\d+)?(?:/[^\s'\"`]*)?", flags=re.I),
    Rule("localhost", "infra", "info", "localhost reference",
         r"\bhttps?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s'\"`]*"),

    # ---------------- Dangerous code / DOM sinks ----------------
    Rule("eval", "dangerous", "medium", "eval() usage", r"(?<![\w.$])eval\s*\(",
         advice="Trace the argument; attacker-influenced input here is script injection."),
    Rule("new-function", "dangerous", "medium", "new Function() usage", r"\bnew\s+Function\s*\("),
    Rule("timer-string", "dangerous", "medium", "setTimeout/setInterval with string argument",
         r"\bset(?:Timeout|Interval|Immediate)\s*\(\s*['\"`]"),
    Rule("inner-html", "dom-sink", "low", "innerHTML/outerHTML assignment",
         r"\.(?:inner|outer)HTML\s*\+?=(?!=)"),
    Rule("insert-adjacent-html", "dom-sink", "low", "insertAdjacentHTML()", r"\.insertAdjacentHTML\s*\("),
    Rule("document-write", "dom-sink", "medium", "document.write/writeln()", r"\bdocument\.write(?:ln)?\s*\("),
    Rule("dangerously-set-inner-html", "dom-sink", "low", "React dangerouslySetInnerHTML",
         r"\bdangerouslySetInnerHTML\b"),
    Rule("vue-v-html", "dom-sink", "low", "Vue v-html / domProps innerHTML",
         r"\bv-html\s*=|domProps\s*:\s*\{\s*innerHTML"),
    Rule("angular-bypass", "dom-sink", "medium", "Angular bypassSecurityTrust*",
         r"\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\("),
    Rule("jquery-html", "dom-sink", "low", "jQuery HTML sink (.html/.append/etc with argument)",
         r"(?:\$|jQuery)\([^)]{0,80}\)\.(?:html|append|prepend|after|before|replaceWith|wrap)\(\s*[^)\s]"),
    Rule("jquery-globaleval", "dangerous", "medium", "jQuery globalEval / parseHTML",
         r"(?:\$|jQuery)\.(?:globalEval|parseHTML)\s*\("),
    Rule("srcdoc", "dom-sink", "low", "iframe srcdoc assignment", r"\.srcdoc\s*=(?!=)"),
    Rule("range-fragment", "dom-sink", "low", "createContextualFragment()", r"\.createContextualFragment\s*\("),
    Rule("location-assign", "redirect", "low", "location assignment (open redirect / javascript: URI sink)",
         r"(?:\b(?:window|document|self|top)\.)?\blocation(?:\.href)?\s*=(?!=)|\blocation\.(?:assign|replace)\s*\("),
    Rule("window-open", "redirect", "info", "window.open()", r"\bwindow\.open\s*\("),
    Rule("postmessage-listener", "postmessage", "medium", "message event listener (verify origin check)",
         r"addEventListener\s*\(\s*['\"`]message['\"`]|\bonmessage\s*=(?!=)",
         advice="Confirm event.origin is strictly validated before using event.data."),
    Rule("postmessage-wildcard", "postmessage", "medium", "postMessage with '*' targetOrigin",
         r"\bpostMessage\s*\([^;]{1,200}?,\s*['\"`]\*['\"`]"),
    Rule("proto-pollution", "dangerous", "low", "__proto__ / constructor.prototype access",
         r"\[\s*['\"`]__proto__['\"`]\s*\]|\.__proto__\s*=|constructor\s*\[\s*['\"`]prototype['\"`]\s*\]"),
    Rule("token-storage", "storage", "low", "Auth token stored in Web Storage",
         r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"`][^'\"`]*(?:token|jwt|auth|session|bearer|secret|key)[^'\"`]*['\"`]",
         flags=re.I, advice="Tokens in Web Storage are readable by any XSS."),
    Rule("document-domain", "dangerous", "low", "document.domain relaxation", r"\bdocument\.domain\s*=(?!=)"),
    Rule("with-credentials", "cors", "info", "Cross-origin requests with credentials",
         r"\bwithCredentials\s*[:=]\s*(?:true|!0)\b|credentials\s*:\s*['\"`]include['\"`]"),
    Rule("insecure-http", "transport", "low", "Hardcoded cleartext http:// URL",
         r"['\"`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org|schemas\.|ns\.adobe|purl\.org|"
         r"www\.apple\.com/DTDs|json-schema\.org|xmlns)[\w.-]+\.[a-z]{2,}[^'\"`\s]*['\"`]"),
    Rule("debug-flag", "config", "low", "Debug / dev flag enabled",
         r"(?i)\b(?:debug|isDev|devMode|enableDebug|DEBUG_MODE)\s*[:=]\s*(?:true|!0)\b"),
    Rule("graphql-introspection", "api", "info", "GraphQL introspection query present",
         r"__schema\s*\{|IntrospectionQuery"),
    Rule("hidden-admin-flag", "authz", "low", "Client-side role/permission check",
         r"(?i)\b(?:isAdmin|is_admin|isSuperUser|isSuperuser|userRole|hasRole|role)\s*(?:===?|!==?)\s*['\"`]"
         r"(?:admin|administrator|superuser|root|super_admin|owner)['\"`]",
         advice="Client-side checks only hide UI; verify the API enforces the same check."),
]

DOM_SOURCE_RE = re.compile(
    r"\blocation\.(?:hash|search|href|pathname)\b|\bdocument\.(?:URL|documentURI|referrer|baseURI|cookie)\b|"
    r"\bwindow\.name\b|\bURLSearchParams\b|\.data\b(?=[^;]{0,40})")
DOM_SINK_CATEGORIES = {"dom-sink", "dangerous", "redirect"}
# a string literal (no template interpolation, no concatenation) followed by a statement/expr terminator
CONST_ARG_RE = re.compile(r"""\s*(?:(['"])(?:(?!\1)[^\\\n])*\1|`[^`$\\]*`)\s*(?=[;,)}:\n]|$)""")
ASSIGN_AFTER_RE = re.compile(r"\s*(?:\+?=(?!=))")


def find_dom_source(text, s, e, radius=250):
    """First DOM source near [s,e] that isn't the sink itself and isn't itself being assigned to."""
    lo = max(0, s - radius)
    for m in DOM_SOURCE_RE.finditer(text, lo, min(len(text), e + radius)):
        if m.start() < e and m.end() > s:                 # overlaps the sink match
            continue
        if ASSIGN_AFTER_RE.match(text, m.end()):          # `location.href = x` is a sink, not a source
            continue
        return m
    return None

# ---------------- Endpoint extraction ----------------
# Based on LinkFinder's regex (GerbenJavado/LinkFinder), adapted.
ENDPOINT_RE = re.compile(
    r"""(?:"|'|`)("""
    r"""(?:[a-zA-Z]{1,10}://|//)[^"'`/\s]{1,}\.[a-zA-Z]{2,}[^"'`\s]{0,}"""             # full URL
    r"""|(?:/|\.\./|\./)[^"'`><,;| *()%$^/\\\[\]\s][^"'`><,;|()\s]{1,}"""               # abs / rel path
    r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"'`]{0,}|)"""  # path w/ ext
    r"""|[a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[?#][^"'`]{0,}|)"""                 # REST path
    r"""|[a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|ashx|asmx|jsp|jspx|json|action|do|cgi|xml|txt)(?:[?#][^"'`]{0,}|)"""
    r""")(?:"|'|`)""")

API_CALL_RES = [
    # fetch("url", {method:"POST"})
    (re.compile(r"\bfetch\s*\(\s*(['\"`])((?:(?!\1).){1,400}?)\1(?P<rest>[^;]{0,250})"), 2, None),
    # axios.post("url") / http.get("url") / this.http.put(...)
    (re.compile(r"\.(get|post|put|patch|delete|head|options|request)\s*(?:<[^>]{0,80}>)?\s*\(\s*(['\"`])((?:(?!\2).){1,400}?)\2",
                re.I), 3, 1),
    # xhr.open("POST", "url")
    (re.compile(r"\.open\s*\(\s*['\"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"`]\s*,\s*(['\"`])((?:(?!\2).){1,400}?)\2",
                re.I), 3, 1),
    # { url: "/x", method: "post" }
    (re.compile(r"\burl\s*:\s*(['\"`])((?:(?!\1).){1,400}?)\1(?P<rest>[^}]{0,200})"), 2, None),
]
METHOD_IN_REST_RE = re.compile(r"""\b(?:method|type)\s*:\s*['"`](\w+)['"`]""", re.I)

ENDPOINT_NOISE_RE = re.compile(
    r"^(?:(?:text|application|image|audio|video|font|multipart|model|message)/[\w.+*-]+(?:;.*)?"
    r"|[MDYHhmsAa]{1,4}[/.-][MDYHhmsAa]{1,4}.*"                    # date formats
    r"|\.{1,2}/?|/+|//?[\s\S]?|[\w-]+/[\w-]+\.(?:png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|map)"
    r"|.*node_modules.*|\./[\w/.-]+\.(?:jsx?|tsx?|vue|scss|css|svelte|mjs)|.*\s.*)$", re.I)
NOISE_HOSTS = ("w3.org", "schema.org", "reactjs.org", "react.dev", "mozilla.org", "fb.me",
               "angular.io", "vuejs.org", "jquery.com", "jquery.org", "momentjs.com", "github.com/zloirock",
               "github.com/facebook", "feross.org", "xmlsoap.org", "purl.org", "opensource.org",
               "lodash.com", "npms.io", "babeljs.io", "webpack.js.org", "polyfill.io", "ogp.me",
               "json-schema.org", "apple.com/dtds", "ns.adobe.com", "microsoft.com/office")
INTERESTING_EP_RE = re.compile(
    r"(?i)(admin|internal|debug|test|staging|graphql|graphiql|swagger|openapi|api-docs|actuator|"
    r"upload|export|import|backup|config|token|oauth|auth|login|logout|password|reset|register|"
    r"invite|impersonat|sudo|role|permission|secret|private|key|webhook|callback|redirect|file|"
    r"download|report|billing|payment|/v\d+/|/api/)")

# ---------------- JS discovery ----------------
JS_REF_RE = re.compile(r"""['"`]((?:https?:)?(?://)?[^'"`\s<>(){},;*]{1,300}?\.m?js)(?:\?[^'"`\s<>]{0,200})?['"`]""")
WEBPACK_CHUNK_RE = re.compile(
    r"""(['"])([\w/.\-]*)\1\s*\+\s*(?:\(\s*\{[^{}]{0,20000}\}\s*\[\s*\w+\s*\]\s*\|\|\s*\w+\s*\)|\w+)\s*\+\s*"""
    r"""(['"])\.\3\s*\+\s*\{([^{}]{1,200000})\}\s*\[\s*\w+\s*\]\s*\+\s*(['"])([\w.\-]*\.js)\5""")
WEBPACK_MAP_ENTRY_RE = re.compile(r"""['"]?([\w-]+)['"]?\s*:\s*['"]([0-9a-f]{4,})['"]""")
SOURCEMAP_COMMENT_RE = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s'\"`*]+)")
NEXT_DATA_RE = re.compile(r'"buildId"\s*:\s*"([\w-]+)"')

SKIP_PAGE_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|pdf|zip|gz|tar|mp4|mp3|"
                           r"avi|mov|docx?|xlsx?|pptx?|exe|dmg|msi|js|map|json|xml|txt)(?:$|\?)", re.I)


# --------------------------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------------------------
@dataclass
class Finding:
    rule: str
    category: str
    severity: str
    title: str
    file: str
    line: int
    col: int
    match: str
    context: str
    advice: str = ""
    note: str = ""


@dataclass
class Endpoint:
    value: str
    kind: str                       # url | path
    methods: set = field(default_factory=set)
    files: set = field(default_factory=set)
    interesting: bool = False


@dataclass
class SourceMap:
    js: str
    map_url: str
    via: str
    sources_count: int
    has_content: bool
    sources: list
    saved_to: str = ""


@dataclass
class Resp:
    url: str
    final_url: str
    status: int
    headers: dict
    text: str
    error: str = ""


class LineIndex:
    def __init__(self, text):
        self.nl = [i for i, ch in enumerate(text) if ch == "\n"]

    def pos(self, offset):
        ln = bisect.bisect_left(self.nl, offset)
        col = offset - (self.nl[ln - 1] + 1 if ln else 0)
        return ln + 1, col + 1


def context_of(text, start, end, width=90):
    s = max(0, start - width)
    e = min(len(text), end + width)
    snippet = text[s:e].replace("\n", " ").replace("\r", " ").replace("\t", " ")
    snippet = re.sub(r"\s{2,}", " ", snippet)
    return ("…" if s > 0 else "") + snippet + ("…" if e < len(text) else "")


def looks_like_html(text):
    head = text.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or (head.startswith("<") and "<head" in text[:2000].lower())


def base_domain(host):
    host = (host or "").split(":")[0].lower()
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def safe_join(base, untrusted_path):
    """Join an attacker-controlled path under base without allowing traversal."""
    p = re.sub(r"^[a-zA-Z][\w+.-]*:/*", "", untrusted_path)          # webpack:///, file://
    p = p.replace("\\", "/")
    parts = [re.sub(r"[^\w.@+-]", "_", seg) for seg in p.split("/") if seg not in ("", ".", "..")]
    if not parts:
        parts = ["_unnamed"]
    full = os.path.normpath(os.path.join(base, *parts))
    if not full.startswith(os.path.normpath(base) + os.sep):
        full = os.path.join(base, "_unsafe_" + "_".join(parts)[-150:])
    return full


# --------------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------------
class Fetcher:
    def __init__(self, a):
        self.s = requests.Session()
        ad = HTTPAdapter(pool_connections=a.threads * 2, pool_maxsize=a.threads * 2, max_retries=1)
        self.s.mount("http://", ad)
        self.s.mount("https://", ad)
        self.s.headers["User-Agent"] = a.user_agent
        for h in a.header or []:
            k, _, v = h.partition(":")
            self.s.headers[k.strip()] = v.strip()
        if a.cookie:
            self.s.headers["Cookie"] = a.cookie
        if a.proxy:
            self.s.proxies = {"http": a.proxy, "https": a.proxy}
        self.verify = not a.insecure
        self.timeout = a.timeout
        self.delay = a.delay
        self.max_bytes = int(a.max_size * 1024 * 1024)
        self.lock = threading.Lock()
        self.last = 0.0
        self.cache = {}
        self.count = 0

    def get(self, url):
        with self.lock:
            if url in self.cache:
                return self.cache[url]
        if self.delay:
            with self.lock:
                wait = self.last + self.delay - time.time()
                if wait > 0:
                    time.sleep(wait)
                self.last = time.time()
        try:
            r = self.s.get(url, timeout=self.timeout, verify=self.verify, stream=True, allow_redirects=True)
            buf = bytearray()
            for chunk in r.iter_content(65536):
                buf += chunk
                if len(buf) > self.max_bytes:
                    break
            r.close()
            resp = Resp(url, r.url, r.status_code, r.headers, buf.decode("utf-8", errors="replace"))
        except requests.RequestException as e:
            resp = Resp(url, url, 0, {}, "", error=str(e).splitlines()[0][:200])
        with self.lock:
            self.cache[url] = resp
            self.count += 1
        return resp


# --------------------------------------------------------------------------------------------
# HTML parsing
# --------------------------------------------------------------------------------------------
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.inline, self.links = [], [], []
        self._in, self._buf, self._type, self._id = False, [], "", ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in, self._buf, self._type, self._id = True, [], a.get("type", ""), a.get("id", "")
        elif tag == "link":
            rel = a.get("rel", "").lower()
            href = a.get("href")
            if href and ("modulepreload" in rel or (("preload" in rel or "prefetch" in rel)
                                                     and a.get("as", "").lower() == "script")):
                self.scripts.append(href)
        elif tag in ("a", "area") and a.get("href"):
            (self.scripts if re.search(r"\.m?js(?:$|\?)", a["href"]) else self.links).append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.links.append(a["src"])

    def handle_data(self, data):
        if self._in:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in:
            code = "".join(self._buf).strip()
            if code:
                self.inline.append((self._type, self._id, code))
            self._in = False


# --------------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------------
def analyze_text(name, text, max_per_rule=25):
    findings, endpoints = [], {}
    li = LineIndex(text)
    seen = set()

    for rule in RULES:
        hits = 0
        extra = 0
        for m in rule.regex.finditer(text):
            val = m.group(rule.group) if rule.group else m.group(0)
            if rule.validator and not rule.validator(val, m):
                continue
            # secrets/infra: dedupe by value; code sinks: every occurrence matters
            key = (rule.id, m.start()) if rule.category in DOM_SINK_CATEGORIES | {"postmessage", "storage"} \
                else (rule.id, val[:200])
            if key in seen:
                continue
            seen.add(key)
            if hits >= max_per_rule:
                extra += 1
                continue
            hits += 1
            ln, col = li.pos(m.start())
            sev, note = rule.severity, ""
            if rule.category in DOM_SINK_CATEGORIES and CONST_ARG_RE.match(text, m.end()):
                # sink fed by a plain string literal, e.g. location.href="/Home" -> not attacker controlled
                sev, note = "info", "argument is a constant string literal — almost certainly not exploitable"
            elif rule.category in DOM_SINK_CATEGORIES:
                src = find_dom_source(text, m.start(), m.end())
                if src and src.group(0) != ".data":
                    sev = "high" if SEV_RANK[sev] > SEV_RANK["high"] else sev
                    note = f"DOM source '{src.group(0)}' within ~250 chars — possible source→sink flow"
                elif src and rule.id in ("eval", "new-function", "inner-html", "document-write", "location-assign") \
                        and re.search(r"addEventListener\s*\(\s*['\"`]message", text[max(0, m.start() - 1500): m.end()]):
                    sev = "high"
                    note = "event.data used near a message listener — possible postMessage→sink flow"
            findings.append(Finding(rule.id, rule.category, sev, rule.title, name, ln, col,
                                    val[:300], context_of(text, m.start(), m.end()), rule.advice, note))
        if extra:
            findings.append(Finding(rule.id, rule.category, "info", f"{rule.title} (+{extra} more, truncated)",
                                    name, 0, 0, "", "", "", "raise --max-per-rule to see all"))

    def add_ep(raw, pos, method=None):
        ep = raw.strip()
        if not ep or len(ep) < 2 or len(ep) > 500 or "\n" in ep:
            return
        if ENDPOINT_NOISE_RE.match(ep):
            return
        low = ep.lower()
        if any(h in low for h in NOISE_HOSTS):
            return
        kind = "url" if re.match(r"^(?:[a-z][\w+.-]*:)?//", ep, re.I) else "path"
        if kind == "path" and "/" not in ep and not re.search(r"\.\w{2,5}(?:$|\?)", ep):
            return
        e = endpoints.get(ep)
        if not e:
            e = endpoints[ep] = Endpoint(ep, kind, interesting=bool(INTERESTING_EP_RE.search(ep)))
        ln, _ = li.pos(pos)
        e.files.add(f"{name}:{ln}")
        if method:
            e.methods.add(method.upper())

    for m in ENDPOINT_RE.finditer(text):
        add_ep(m.group(1), m.start(1))

    for rx, url_grp, method_grp in API_CALL_RES:
        for m in rx.finditer(text):
            url = m.group(url_grp)
            if "/" not in url and "${" not in url:
                continue
            method = None
            if method_grp:
                method = m.group(method_grp)
                if method.lower() == "request":
                    method = None
            elif "rest" in rx.groupindex and m.group("rest"):
                mm = METHOD_IN_REST_RE.search(m.group("rest"))
                method = mm.group(1) if mm else ("GET" if rx.pattern.startswith(r"\bfetch") else None)
            add_ep(url, m.start(url_grp), method)

    return findings, endpoints


def discover_js_refs(text, js_url):
    """Return candidate JS URLs referenced inside a JS file."""
    out = set()
    if not js_url or not js_url.startswith("http"):
        return out
    p = urlparse(js_url)
    origin = f"{p.scheme}://{p.netloc}/"

    def cands(ref):
        if ref.startswith(("http://", "https://")):
            return [ref]
        if ref.startswith("//"):
            return [f"{p.scheme}:{ref}"]
        if ref.startswith("/"):
            return [urljoin(origin, ref)]
        if "/_next/" in js_url and ref.startswith("static/"):
            return [urljoin(origin, "_next/" + ref)]
        return list(dict.fromkeys([urljoin(js_url, ref), urljoin(origin, ref)]))

    for m in JS_REF_RE.finditer(text):
        ref = m.group(1)
        if "node_modules" in ref or ref.count("/") > 12 or ref.endswith((".min.js",)) and "/" not in ref:
            continue
        if re.fullmatch(r"[\w.-]+\.js", ref) and "." not in ref[:-3]:
            # bare 'foo.js' is usually a module name in comments/strings; try only relative to the JS dir
            out.add(urljoin(js_url, ref))
            continue
        for c in cands(ref):
            out.add(c)

    # webpack: prefix + id + "." + {id:hash}[id] + ".chunk.js"
    for m in WEBPACK_CHUNK_RE.finditer(text):
        prefix, suffix, table = m.group(2), m.group(6), m.group(4)
        for cid, h in WEBPACK_MAP_ENTRY_RE.findall(table):
            for c in cands(f"{prefix}{cid}.{h}{suffix}"):
                out.add(c)
    return out


# --------------------------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------------------------
class Scanner:
    def __init__(self, a):
        self.a = a
        self.f = Fetcher(a)
        self.lock = threading.Lock()
        self.findings: list[Finding] = []
        self.endpoints: dict[str, Endpoint] = {}
        self.sourcemaps: list[SourceMap] = []
        self.files = []                 # {"name", "status", "size", "note"}
        self.seen_js = set()
        self.seen_maps = set()
        self.scope = set(s.lower() for s in (a.scope or []))
        self.outdir = a.output

    # ---------- scope ----------
    def in_scope(self, url):
        host = (urlparse(url).hostname or "").lower()
        if not self.scope:
            return True
        return any(host == s or host.endswith("." + s) for s in self.scope)

    # ---------- merge ----------
    def merge(self, name, text, size_note=""):
        fnd, eps = analyze_text(name, text, self.a.max_per_rule)
        with self.lock:
            self.findings.extend(fnd)
            for k, e in eps.items():
                if k in self.endpoints:
                    self.endpoints[k].files |= e.files
                    self.endpoints[k].methods |= e.methods
                else:
                    self.endpoints[k] = e
        return fnd, eps

    # ---------- crawl ----------
    def crawl(self, start):
        if not re.match(r"^https?://", start, re.I):
            start = "https://" + start
        sp = urlparse(start)
        if not self.scope:
            self.scope.add(base_domain(sp.hostname))
        log(f"Crawling {start} (depth={self.a.depth}, max pages={self.a.max_pages}, scope={','.join(sorted(self.scope))})")
        queue, seen_pages, js = [(start, 0)], {start}, set()
        pages = 0
        while queue and pages < self.a.max_pages:
            url, d = queue.pop(0)
            r = self.f.get(url)
            pages += 1
            if r.status == 0:
                log(f"{url} -> error: {r.error}", "!")
                continue
            ctype = r.headers.get("Content-Type", "")
            log(f"page {r.status} {url}", "-")
            if "html" not in ctype.lower() and not looks_like_html(r.text):
                continue
            p = PageParser()
            try:
                p.feed(r.text)
            except Exception:
                pass
            base = r.final_url
            m = re.search(r"<base\s[^>]*href=['\"]([^'\"]+)", r.text, re.I)
            if m:
                base = urljoin(base, m.group(1))
            for s in p.scripts:
                js.add(urldefrag(urljoin(base, s.strip()))[0])
            for i, (stype, sid, code) in enumerate(p.inline, 1):
                tag = f"{r.final_url} [inline #{i}{' id=' + sid if sid else ''}{' ' + stype if stype else ''}]"
                self.files.append({"name": tag, "status": "inline", "size": len(code), "note": ""})
                self.merge(tag, code)
                bm = NEXT_DATA_RE.search(code) if sid == "__NEXT_DATA__" else None
                if bm:
                    for f_ in ("_buildManifest.js", "_ssgManifest.js"):
                        js.add(urljoin(base, f"/_next/static/{bm.group(1)}/{f_}"))
            if d < self.a.depth:
                for l in p.links:
                    nu = urldefrag(urljoin(base, l.strip()))[0]
                    if not nu.startswith(("http://", "https://")) or SKIP_PAGE_EXT.search(urlparse(nu).path):
                        continue
                    if urlparse(nu).netloc != urlparse(r.final_url).netloc:
                        continue
                    if nu not in seen_pages:
                        seen_pages.add(nu)
                        queue.append((nu, d + 1))
        # CRA / generic asset manifest
        am = self.f.get(urljoin(f"{sp.scheme}://{sp.netloc}/", "asset-manifest.json"))
        if am.status == 200 and am.text.lstrip().startswith("{"):
            try:
                def walk(o):
                    if isinstance(o, dict):
                        for v in o.values():
                            yield from walk(v)
                    elif isinstance(o, list):
                        for v in o:
                            yield from walk(v)
                    elif isinstance(o, str):
                        yield o
                for v in walk(json.loads(am.text)):
                    if v.endswith(".js"):
                        js.add(urljoin(f"{sp.scheme}://{sp.netloc}/", v))
                log("asset-manifest.json found — added its JS entries", "+")
            except ValueError:
                pass
        if self.a.same_domain:
            js = {u for u in js if self.in_scope(u)}
        log(f"Crawl done: {pages} page(s), {len(js)} script URL(s)", "+")
        return js

    # ---------- per JS ----------
    def process_js(self, target):
        """Returns set of newly discovered JS URLs."""
        is_url = bool(re.match(r"^https?://", target, re.I))
        if is_url:
            r = self.f.get(target)
            if r.status != 200 or not r.text.strip():
                with self.lock:
                    self.files.append({"name": target, "status": r.status or "ERR", "size": 0,
                                       "note": r.error or "non-200"})
                return set()
            if looks_like_html(r.text):
                with self.lock:
                    self.files.append({"name": target, "status": r.status, "size": len(r.text),
                                       "note": "returned HTML (SPA fallback / soft 404) — skipped"})
                return set()
            text, headers, name = r.text, r.headers, r.final_url
        else:
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read(self.f.max_bytes)
            except OSError as e:
                with self.lock:
                    self.files.append({"name": target, "status": "ERR", "size": 0, "note": str(e)})
                return set()
            headers, name = {}, os.path.abspath(target)

        with self.lock:
            self.files.append({"name": name, "status": 200 if is_url else "local", "size": len(text), "note": ""})
        fnd, eps = self.merge(name, text)
        if not self.a.quiet:
            crit = sum(1 for f in fnd if SEV_RANK[f.severity] <= SEV_RANK["high"])
            log(f"{name}  ({len(text) // 1024} KB) — {len(eps)} endpoints, {len(fnd)} findings"
                + (C.c("high", f", {crit} high+") if crit else ""), "+")

        if self.outdir and self.a.save_js and is_url:
            pth = safe_join(os.path.join(self.outdir, "js"), urlparse(name).netloc.replace(":", "_") + urlparse(name).path)
            os.makedirs(os.path.dirname(pth), exist_ok=True)
            with open(pth, "w", encoding="utf-8") as fh:
                fh.write(text)

        # ---- source maps ----
        refs = []
        for h in ("SourceMap", "X-SourceMap"):
            if headers.get(h):
                refs.append((headers[h], f"{h} header"))
        tail = text[-4000:] if len(text) > 4000 else text
        for m in SOURCEMAP_COMMENT_RE.finditer(tail):
            refs.append((m.group(1), "sourceMappingURL comment"))
        handled = False
        for ref, via in refs:
            if ref.startswith("data:"):
                handled |= self.handle_map(name, ref, via + " (inline data URI)")
            elif is_url:
                handled |= self.handle_map(name, urljoin(name, ref), via)
            else:
                lp = os.path.join(os.path.dirname(name), ref)
                if os.path.exists(lp):
                    handled |= self.handle_map(name, lp, via)
        if is_url and not handled and not self.a.no_probe_maps:
            pu = urlparse(name)
            self.handle_map(name, pu._replace(query="", fragment="", path=pu.path + ".map").geturl(),
                            "blind probe (.js.map)")

        if is_url and self.a.recurse:
            return {u for u in discover_js_refs(text, name) if self.in_scope(u)}
        return set()

    def handle_map(self, js_name, map_ref, via):
        key = map_ref[:200]
        with self.lock:
            if key in self.seen_maps:
                return True
            self.seen_maps.add(key)
        raw, map_url = None, map_ref
        if map_ref.startswith("data:"):
            try:
                hdr, _, data = map_ref.partition(",")
                raw = base64.b64decode(data).decode("utf-8", "replace") if ";base64" in hdr else data
                map_url = f"{js_name} (inline)"
            except Exception:
                return False
        elif re.match(r"^https?://", map_ref, re.I):
            r = self.f.get(map_ref)
            if r.status != 200:
                return False
            raw = r.text
        else:
            try:
                with open(map_ref, encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            except OSError:
                return False
        raw = raw.lstrip()
        if raw.startswith(")]}'"):
            raw = raw.split("\n", 1)[-1]
        try:
            sm = json.loads(raw)
        except ValueError:
            return False
        if not isinstance(sm, dict) or not ("mappings" in sm or "sections" in sm):
            return False

        sections = [s.get("map", {}) for s in sm.get("sections", [])] if "sections" in sm else [sm]
        sources, contents = [], []
        for s in sections:
            srcs = s.get("sources") or []
            cont = s.get("sourcesContent") or []
            for i, sname in enumerate(srcs):
                sources.append(sname or f"source_{i}")
                contents.append(cont[i] if i < len(cont) else None)
        has_content = any(c for c in contents)

        saved = ""
        if self.outdir and has_content:
            host = re.sub(r"[^\w.-]", "_", urlparse(map_url).netloc or "local")
            mbase = os.path.join(self.outdir, "sourcemaps", host,
                                 re.sub(r"[^\w.-]", "_", os.path.basename(urlparse(map_url).path) or "inline"))
            for sname, c in zip(sources, contents):
                if c:
                    pth = safe_join(mbase, sname)
                    os.makedirs(os.path.dirname(pth), exist_ok=True)
                    with open(pth, "w", encoding="utf-8") as fh:
                        fh.write(c)
            saved = mbase

        smo = SourceMap(js_name, map_url, via, len(sources), has_content, sources[:1000], saved)
        own = [s for s in sources if "node_modules" not in s and "webpack/" not in s]
        sev = "medium" if has_content else "low"
        title = "JavaScript source map exposed"
        third_party = re.match(r"^https?://", map_url, re.I) and self.scope and not self.in_scope(map_url)
        if third_party:
            sev, title = "info", "Third-party source map (library/CDN code, not target code)"
        f = Finding("sourcemap-exposed", "sourcemap", sev, title, js_name, 0, 0,
                    map_url, f"{len(sources)} sources ({len(own)} first-party); sourcesContent "
                             f"{'PRESENT' if has_content else 'absent'}; via {via}",
                    "Original source code is recoverable. Review first-party sources for secrets, "
                    "hidden routes, and logic flaws. Remove maps from production.", "")
        with self.lock:
            self.sourcemaps.append(smo)
            self.findings.append(f)
        log(C.c("medium", f"SOURCE MAP: {map_url}") + f"  [{len(sources)} sources, content={'yes' if has_content else 'no'}, via {via}]", "+")

        if has_content and not self.a.no_map_analysis and not third_party:
            for sname, c in zip(sources, contents):
                if not c:
                    continue
                if not self.a.include_vendor and ("node_modules" in sname or "webpack/bootstrap" in sname
                                                  or "(webpack)" in sname):
                    continue
                self.merge(f"{map_url} ! {sname}", c)
        return True

    # ---------- run ----------
    def run(self, initial):
        batch = [u for u in dict.fromkeys(initial)]
        level = 0
        while batch:
            batch = [u for u in batch if u not in self.seen_js]
            room = self.a.max_js - len(self.seen_js)
            if room <= 0:
                log(f"--max-js {self.a.max_js} reached; stopping discovery", "!")
                break
            batch = batch[:room]
            self.seen_js.update(batch)
            if not batch:
                break
            if level:
                log(f"Recursion level {level}: {len(batch)} candidate JS URL(s) discovered in JS")
            discovered = set()
            with ThreadPoolExecutor(max_workers=self.a.threads) as ex:
                for res in ex.map(self.process_js, batch):
                    discovered |= res
            level += 1
            if level > self.a.recurse:
                break
            batch = sorted(discovered - self.seen_js)
        # quietly drop probe misses from the file list for discovered-but-404 chunks
        self.files = [f for f in self.files if not (f["status"] == 404 and f.get("note") == "non-200"
                                                    and f["name"] not in initial)]


# --------------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------------
def dedupe_findings(findings):
    seen, out = set(), []
    for f in findings:
        k = (f.rule, f.match, f.file, f.line)
        if k not in seen:
            seen.add(k)
            out.append(f)
    out.sort(key=lambda f: (SEV_RANK[f.severity], f.category, f.rule, f.file))
    return out


def print_summary(sc, findings, min_sev):
    eps = sorted(sc.endpoints.values(), key=lambda e: (not e.interesting, e.kind, e.value))
    print()
    print(C.c("bold", "=" * 78))
    print(C.c("bold", f" basic-js-scanner {VERSION} — {len(sc.files)} files, {sc.f.count} requests"))
    print(C.c("bold", "=" * 78))
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    print("  " + "  ".join(C.c(s, f"{s.upper()}: {counts[s]}") for s in SEVERITIES))
    print(f"  Endpoints: {len(eps)} ({sum(e.interesting for e in eps)} flagged interesting)   "
          f"Source maps: {len(sc.sourcemaps)}")

    if sc.sourcemaps:
        print("\n" + C.c("bold", "[ Source maps ]"))
        for s in sc.sourcemaps:
            print(f"  {C.c('medium', s.map_url)}\n     {s.sources_count} sources, content={'yes' if s.has_content else 'no'}"
                  + (f", saved: {s.saved_to}" if s.saved_to else ""))

    shown = [f for f in findings if SEV_RANK[f.severity] <= SEV_RANK[min_sev] and f.rule != "sourcemap-exposed"]
    if shown:
        print("\n" + C.c("bold", f"[ Findings (>= {min_sev}) ]"))
        for f in shown:
            loc = f"{f.file}:{f.line}:{f.col}" if f.line else f.file
            print(f"  {C.c(f.severity, f'[{f.severity.upper():8}]')} {f.title}")
            print(f"      {C.c('dim', loc)}")
            if f.match:
                print(f"      match: {f.match[:160]}")
            if f.note:
                print(f"      {C.c('high', 'note')}: {f.note}")

    if eps:
        print("\n" + C.c("bold", "[ Endpoints ]"))
        for e in eps[:400]:
            m = ",".join(sorted(e.methods))
            star = C.c("medium", "*") if e.interesting else " "
            print(f"  {star} {e.value}" + (C.c("dim", f"  [{m}]") if m else ""))
        if len(eps) > 400:
            print(C.c("dim", f"  … {len(eps) - 400} more (see output files)"))
    print()


def write_outputs(sc, findings, outdir, args):
    os.makedirs(outdir, exist_ok=True)
    eps = sorted(sc.endpoints.values(), key=lambda e: (not e.interesting, e.kind, e.value))
    data = {
        "tool": f"basic-js-scanner {VERSION}",
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": {"url": args.url, "js": args.js, "list": args.list},
        "stats": {"files": len(sc.files), "requests": sc.f.count, "findings": len(findings),
                  "endpoints": len(eps), "sourcemaps": len(sc.sourcemaps)},
        "files": sc.files,
        "sourcemaps": [asdict(s) for s in sc.sourcemaps],
        "findings": [asdict(f) for f in findings],
        "endpoints": [{"value": e.value, "kind": e.kind, "methods": sorted(e.methods),
                       "interesting": e.interesting, "seen_in": sorted(e.files)[:50]} for e in eps],
    }
    with open(os.path.join(outdir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    with open(os.path.join(outdir, "endpoints.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(e.value for e in eps) + "\n")
    with open(os.path.join(outdir, "urls.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(e.value for e in eps if e.kind == "url") + "\n")
    with open(os.path.join(outdir, "js_files.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(f["name"] for f in sc.files if f["status"] in (200, "local")) + "\n")
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(html_report(sc, findings, eps, data))
    log(f"Wrote findings.json, endpoints.txt, urls.txt, js_files.txt, report.html -> {outdir}", "+")


def html_report(sc, findings, eps, data):
    e = escape
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity] += 1
    sev_cards = "".join(f'<div class="card {s}"><b>{counts[s]}</b><span>{s}</span></div>' for s in SEVERITIES)
    frows = "".join(
        f'<tr class="{e(f.severity)}"><td><span class="sev {e(f.severity)}">{e(f.severity)}</span></td>'
        f'<td>{e(f.title)}<div class="sub">{e(f.category)} · {e(f.rule)}</div>'
        f'{"<div class=note>" + e(f.note) + "</div>" if f.note else ""}'
        f'{"<div class=adv>" + e(f.advice) + "</div>" if f.advice else ""}</td>'
        f'<td class="mono">{e(f.file)}{(":" + str(f.line) + ":" + str(f.col)) if f.line else ""}</td>'
        f'<td class="mono"><b>{e(f.match[:200])}</b><div class="ctx">{e(f.context[:400])}</div></td></tr>'
        for f in findings)
    erows = "".join(
        f'<tr><td class="mono">{"★ " if x.interesting else ""}{e(x.value)}</td><td>{e(",".join(sorted(x.methods)))}</td>'
        f'<td>{e(x.kind)}</td><td class="mono sub">{e(" | ".join(sorted(x.files)[:3]))}'
        f'{" …" if len(x.files) > 3 else ""}</td></tr>' for x in eps)
    srows = "".join(
        f'<tr><td class="mono">{e(s.map_url)}</td><td>{s.sources_count}</td><td>{"yes" if s.has_content else "no"}</td>'
        f'<td>{e(s.via)}</td><td class="mono sub">{e(", ".join(x for x in s.sources if "node_modules" not in x)[:600])}</td></tr>'
        for s in sc.sourcemaps)
    jrows = "".join(f'<tr><td class="mono">{e(str(x["name"]))}</td><td>{e(str(x["status"]))}</td>'
                    f'<td>{x["size"]}</td><td>{e(x.get("note", ""))}</td></tr>' for x in sc.files)
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>basic-js-scanner report</title><style>
:root{{--bg:#fff;--fg:#1a1a1a;--mut:#666;--bd:#e3e3e3;--alt:#f7f7f7;--crit:#b00020;--high:#d93025;--med:#e37400;--low:#1a73e8;--info:#777}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16181c;--fg:#e8e8e8;--mut:#9aa0a6;--bd:#2c2f35;--alt:#1d2025}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:24px}}
h1{{margin:0 0 4px}} h2{{margin:32px 0 8px;border-bottom:1px solid var(--bd);padding-bottom:4px}}
.meta{{color:var(--mut)}} .cards{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
.card{{border:1px solid var(--bd);border-radius:8px;padding:10px 16px;min-width:90px}} .card b{{display:block;font-size:24px}}
.card span{{text-transform:uppercase;font-size:11px;color:var(--mut)}}
.card.critical b{{color:var(--crit)}} .card.high b{{color:var(--high)}} .card.medium b{{color:var(--med)}} .card.low b{{color:var(--low)}} .card.info b{{color:var(--info)}}
table{{border-collapse:collapse;width:100%;table-layout:fixed}} td,th{{border-bottom:1px solid var(--bd);padding:6px 8px;vertical-align:top;text-align:left;word-break:break-word}}
th{{background:var(--alt);position:sticky;top:0}} .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
.sub{{color:var(--mut);font-size:12px}} .ctx{{color:var(--mut);font-size:11px;margin-top:4px}}
.note{{color:var(--high);font-size:12px}} .adv{{color:var(--low);font-size:12px}}
.sev{{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;text-transform:uppercase}}
.sev.critical{{background:var(--crit)}} .sev.high{{background:var(--high)}} .sev.medium{{background:var(--med)}} .sev.low{{background:var(--low)}} .sev.info{{background:var(--info)}}
input{{padding:6px 10px;width:320px;max-width:100%;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--fg)}}
</style></head><body>
<h1>basic-js-scanner report</h1><div class="meta">{e(data["generated"])} · {data["stats"]["files"]} files · {data["stats"]["requests"]} requests ·
targets: {e(str(data["targets"]["url"] or ""))} {e(str(data["targets"]["js"] or ""))} {e(str(data["targets"]["list"] or ""))}</div>
<div class="cards">{sev_cards}<div class="card"><b>{len(eps)}</b><span>endpoints</span></div><div class="card"><b>{len(sc.sourcemaps)}</b><span>source maps</span></div></div>
<input id="q" placeholder="Filter all tables…" oninput="flt(this.value)">
<h2>Source maps</h2><table><tr><th style="width:30%">Map</th><th style="width:7%">Sources</th><th style="width:7%">Content</th><th style="width:14%">Via</th><th>First-party sources</th></tr>{srows or '<tr><td colspan=5>None found</td></tr>'}</table>
<h2>Findings</h2><table><tr><th style="width:8%">Severity</th><th style="width:24%">Finding</th><th style="width:24%">Location</th><th>Match / context</th></tr>{frows}</table>
<h2>Endpoints</h2><table><tr><th style="width:45%">Endpoint (★ = interesting)</th><th style="width:8%">Methods</th><th style="width:6%">Kind</th><th>Seen in</th></tr>{erows}</table>
<h2>Files scanned</h2><table><tr><th style="width:60%">File</th><th style="width:8%">Status</th><th style="width:8%">Size</th><th>Note</th></tr>{jrows}</table>
<script>function flt(q){{q=q.toLowerCase();document.querySelectorAll('table tr').forEach(function(r,i){{if(r.querySelector('th'))return;r.style.display=r.textContent.toLowerCase().indexOf(q)>-1?'':'none'}})}}</script>
</body></html>"""


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="JavaScript recon & static vulnerability scanner",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Examples:")[1])
    g = ap.add_argument_group("input (at least one)")
    g.add_argument("-u", "--url", help="Target page/domain to crawl for JS")
    g.add_argument("-j", "--js", action="append", help="Single JS URL or local file (repeatable)")
    g.add_argument("-l", "--list", help="File with JS URLs / local paths, one per line")

    c = ap.add_argument_group("crawl & discovery")
    c.add_argument("--depth", type=int, default=1, help="Page crawl depth from --url (default 1; 0 = start page only)")
    c.add_argument("--max-pages", type=int, default=30, help="Max HTML pages to crawl (default 30)")
    c.add_argument("--recurse", type=int, default=1, help="Levels of JS-referenced-in-JS discovery (default 1; 0 = off)")
    c.add_argument("--max-js", type=int, default=400, help="Max JS files to fetch (default 400)")
    c.add_argument("--scope", action="append", help="In-scope domain for recursion (repeatable). Default: base domain of --url")
    c.add_argument("--same-domain", action="store_true", help="Also skip third-party <script src> (CDNs etc.)")
    c.add_argument("--no-probe-maps", action="store_true", help="Don't blind-probe <file>.js.map")
    c.add_argument("--no-map-analysis", action="store_true", help="Don't scan sources recovered from source maps")
    c.add_argument("--include-vendor", action="store_true", help="Also scan node_modules sources from source maps")

    h = ap.add_argument_group("http")
    h.add_argument("-H", "--header", action="append", help="Extra header 'Name: value' (repeatable)")
    h.add_argument("-c", "--cookie", help="Cookie header value")
    h.add_argument("-A", "--user-agent", default=DEFAULT_UA)
    h.add_argument("-p", "--proxy", help="Proxy, e.g. http://127.0.0.1:8080")
    h.add_argument("-k", "--insecure", action="store_true", help="Don't verify TLS certs")
    h.add_argument("-t", "--threads", type=int, default=8)
    h.add_argument("--timeout", type=float, default=15)
    h.add_argument("--delay", type=float, default=0, help="Min seconds between requests (global)")
    h.add_argument("--max-size", type=float, default=15, help="Max MB to read per file (default 15)")

    o = ap.add_argument_group("output")
    o.add_argument("-o", "--output", help="Output directory (JSON, HTML report, endpoints, extracted sources)")
    o.add_argument("--save-js", action="store_true", help="Save fetched JS files into the output dir")
    o.add_argument("--min-severity", choices=SEVERITIES, default="low", help="Console threshold (default low)")
    o.add_argument("--max-per-rule", type=int, default=25, help="Max hits per rule per file (default 25)")
    o.add_argument("-q", "--quiet", action="store_true", help="Less per-file progress output")
    o.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
    if not (a.url or a.js or a.list):
        ap.error("provide at least one of -u/--url, -j/--js, -l/--list")
    if a.no_color:
        C.on = False
    return a


def main():
    a = parse_args()
    sc = Scanner(a)
    initial = []
    if a.url:
        initial += sorted(sc.crawl(a.url))
    for j in a.js or []:
        initial.append(j.strip())
        if re.match(r"^https?://", j) and not a.scope and not a.url:
            sc.scope.add(base_domain(urlparse(j).hostname))
    if a.list:
        with open(a.list, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    initial.append(line)
                    if re.match(r"^https?://", line) and not a.scope and not a.url:
                        sc.scope.add(base_domain(urlparse(line).hostname))
    log(f"Analyzing {len(initial)} JS target(s) with {a.threads} threads")
    t0 = time.time()
    try:
        sc.run(initial)
    except KeyboardInterrupt:
        log("Interrupted — reporting partial results", "!")
    findings = dedupe_findings(sc.findings)
    print_summary(sc, findings, a.min_severity)
    if a.output:
        write_outputs(sc, findings, a.output, a)
    log(f"Done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()