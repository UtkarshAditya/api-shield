/**
 * What the gateway's rules actually do, for the Rules detail panel.
 *
 * Every statement here was checked against the gateway source:
 *   gateway/apishield_gateway/rules.py      SIGNATURES, Rule.matches, RulesStage.on_request
 *   gateway/apishield_gateway/normalize.py  what goes into payload_text (decoding, body handling)
 *   gateway/apishield_gateway/main.py       MONITOR vs ENFORCE handling, client IP
 *   gateway/apishield_gateway/auth.py       which callers pass a challenge
 *   gateway/rules/builtin.yaml              ids, priorities, the deny-list placeholder
 * Example strings are inert illustrations of each pattern family, not payloads from traffic.
 * Keep this file frontend-only; the gateway and Admin API do not read it.
 */
import type { Action, Rule } from "@/api/schemas";

export type RuleDoc = {
  /** "What it catches": 2-3 plain sentences. */
  catches: string;
  /** "Why it matters": the attack and its consequence. */
  why: string;
  /** Only references that genuinely apply. */
  refs?: string[];
  how: {
    summary: string;
    /** Which request parts are inspected. */
    inspects: string[];
    /** Pattern families (summarized, not the full regex list). */
    families: string[];
    /** Inert example strings. */
    examples: string[];
  };
  /** "Known limits": true of this implementation. */
  limits: string[];
};

/** The text a signature scans, as built by NormalizeStage (normalize.py). */
const PAYLOAD_PARTS = [
  "Request path, percent-decoded up to three times (so %2527 still shows the quote)",
  "Query parameter names and values, each decoded the same way",
  "JSON body (application/json or +json): every object key and every string value, recursively; numbers and booleans are not included",
  "Any other body: its text (form bodies are URL-decoded first)",
  "Not inspected: headers, cookies, and the response",
];
const PAYLOAD_CAP = "At most 262,144 characters of that text are scanned; anything beyond is not checked.";
const NO_DECODE =
  "Only percent-encoding is undone. Other encodings (base64, HTML entities like &lt;, \\u escapes outside JSON) reach the API unseen.";

export const SIGNATURE_DOCS: Record<string, RuleDoc> = {
  sqli: {
    catches:
      "Request text that looks like SQL being injected into a query: a quote or number followed by an always-true comparison, UNION SELECT, a stacked statement after a semicolon, a quote followed by a comment, time-delay functions, or references to database catalog tables.",
    why: "If the API builds SQL from input (as /search does in the demo API), an attacker can read or change data they should not reach, or dump whole tables.",
    refs: ["CWE-89", "OWASP API Security Top 10 2019: API8 Injection"],
    how: {
      summary: "Seven case-insensitive regular expressions run over the request text; one match is enough. There is no SQL parsing.",
      inspects: PAYLOAD_PARTS,
      families: [
        "Always-true comparison after a quote or number (' OR '1'='1, 1 AND 1=1, LIKE)",
        "UNION [ALL] SELECT",
        "Stacked statement: ; DROP / DELETE / INSERT / UPDATE / ALTER / CREATE / TRUNCATE",
        "Quote followed by a comment: '-- , '/* , ' # at the end",
        "Time delay: sleep(n), benchmark(n, pg_sleep(n), WAITFOR DELAY",
        "Catalog tables: information_schema, sqlite_master, pg_catalog",
      ],
      examples: ["' OR '1'='1", "x' UNION SELECT name FROM users --", "1; DROP TABLE users", "' AND sleep(5)"],
    },
    limits: [
      "Pattern matching, not a full WAF: obfuscated SQL (comments inside keywords like UN/**/ION, CHAR() or hex encodings) can pass.",
      "Legitimate text can trigger it, for example a search or comment containing \"union select\" or \"information_schema\".",
      NO_DECODE,
    ],
  },
  nosqli: {
    catches:
      "MongoDB-style query operators arriving in the request: a dollar sign followed by an operator name such as $ne, $gt, $regex, $where or $or, in a JSON key, a JSON string, a query parameter name or value, or the path.",
    why: "If the API passes JSON or query input straight into a document-database query, {\"password\": {\"$ne\": null}} can match every record, bypassing a login or exposing data.",
    refs: ["CWE-943", "OWASP API Security Top 10 2019: API8 Injection"],
    how: {
      summary: "One case-insensitive regular expression: \"$\" followed by one of 16 operator names as a whole word.",
      inspects: PAYLOAD_PARTS,
      families: ["$where $ne $gt $gte $lt $lte $in $nin $regex $exists $or $and $not $nor $expr $function"],
      examples: ['{"password": {"$ne": null}}', "user[$ne]=x", '{"$where": "1 == 1"}'],
    },
    limits: [
      "Operators outside that list ($elemMatch, $all, $size, $type, $text, …) are not matched.",
      "Legitimate text containing one of the operator words after a \"$\" (for example \"$in\" in a note) triggers it.",
      NO_DECODE,
    ],
  },
  xss: {
    catches:
      "HTML or JavaScript that could run in a browser if the API stores it and a page later renders it: <script tags, javascript: URLs, tags with common on-event handlers, embedding tags (iframe, object, embed, svg, math) and document.cookie / location / write.",
    why: "Stored script runs in other users' browsers with their session, which can steal cookies or tokens and act on their behalf.",
    refs: ["CWE-79"],
    how: {
      summary: "Five case-insensitive regular expressions over the request text; one match is enough. Only requests are checked, never responses.",
      inspects: PAYLOAD_PARTS,
      families: [
        "<script",
        "javascript: URLs",
        "A tag with onerror / onload / onclick / onmouseover / onfocus / ontoggle / onstart / onbegin / onanimation… =",
        "<iframe, <object, <embed, <svg, <math",
        "document.cookie, document.location, document.write",
      ],
      examples: ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg onload=…>"],
    },
    limits: [
      "Event handlers outside that list (for example onpointerdown) pass.",
      "Text that legitimately contains markup, such as code snippets in a comment or an SVG upload, is blocked in ENFORCE.",
      NO_DECODE,
    ],
  },
  path_traversal: {
    catches:
      "Attempts to step out of a directory or name well-known system files: \"..\" path segments with / or \\ separators, /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/, boot.ini and win.ini.",
    why: "If the API turns input into a file path, traversal can read configuration, credentials or source code from the server.",
    refs: ["CWE-22"],
    how: {
      summary: "Four case-insensitive regular expressions over the request text. The raw path is decoded before matching, so encoded ../ (%2e%2e%2f) is still seen.",
      inspects: PAYLOAD_PARTS,
      families: ["\"..\" as a whole path segment (../ or ..\\)", "/etc/passwd, /etc/shadow, /etc/hosts", "/proc/self/", "boot.ini, win.ini"],
      examples: ["../../etc/passwd", "..\\..\\windows\\win.ini", "/proc/self/environ"],
    },
    limits: [
      "Other sensitive absolute paths (for example /var/log/… or an application's own config file) are not on the list.",
      "Legitimate text containing \"../\", such as a relative link in a comment, triggers it.",
      NO_DECODE,
    ],
  },
  bad_user_agent: {
    catches:
      "Requests whose User-Agent header names a known attack or scanning tool: sqlmap, nikto, nmap, masscan, acunetix, nessus, dirbuster, gobuster, wpscan, zgrab, havij, hydra, metasploit, nuclei, ffuf, wfuzz, burpsuite or openvas.",
    why: "Automated tools probe many endpoints quickly; stopping the obvious ones early cuts noise and slows unsophisticated attacks.",
    how: {
      summary: "One case-insensitive substring match on the User-Agent header only. The body, path and query are not checked by this rule.",
      inspects: ["User-Agent request header only"],
      families: ["18 tool names (listed above)"],
      examples: ["sqlmap/1.7", "Nikto/2.5", "Mozilla/5.0 (Nuclei)"],
    },
    limits: [
      "The User-Agent is set by the client, so any tool can send a browser string and pass.",
      "Generic clients (curl, python-requests) are not matched.",
    ],
  },
};

const IP_DENYLIST: RuleDoc = {
  catches:
    "Requests from client addresses inside the listed CIDR ranges. As shipped, the list holds 203.0.113.0/24, a documentation range (TEST-NET-3) that matches no real client: it is a placeholder to replace with real addresses.",
  why: "Lets you cut off a known-bad source (an abusive scraper, an attacker's address) before any other check runs; it has the lowest priority number, so it runs first.",
  how: {
    summary:
      "The client IP is compared with each network in the list. The client IP is the TCP peer address, or the first X-Forwarded-For entry when the gateway is configured to trust that header (APISHIELD_TRUST_FORWARDED_FOR, off by default).",
    inspects: ["Client IP address only"],
    families: ["IPv4 or IPv6 networks in CIDR notation"],
    examples: ["203.0.113.0/24", "198.51.100.7/32"],
  },
  limits: [
    "Behind a proxy or load balancer without the trust setting, every request appears to come from the proxy.",
    "Attackers can change addresses; a deny list only stops a known source.",
    "With the trust setting on and nothing in front that overwrites X-Forwarded-For, a client can claim any address.",
  ],
};

/** Docs keyed by rule id (the gateway's built-ins, gateway/rules/builtin.yaml). */
export const BUILTIN_RULE_DOCS: Record<string, RuleDoc> = {
  "builtin-ip-denylist": IP_DENYLIST,
  "builtin-bad-user-agent": SIGNATURE_DOCS.bad_user_agent,
  "builtin-sqli": SIGNATURE_DOCS.sqli,
  "builtin-nosqli": SIGNATURE_DOCS.nosqli,
  "builtin-xss": SIGNATURE_DOCS.xss,
  "builtin-path-traversal": SIGNATURE_DOCS.path_traversal,
};

/** A rule's doc: by id first, then by the signature it uses (scanner/analyst rules reuse them). */
export function docFor(rule: Pick<Rule, "id" | "match">): RuleDoc | undefined {
  return BUILTIN_RULE_DOCS[rule.id] ?? (rule.match.signature ? SIGNATURE_DOCS[rule.match.signature] : undefined);
}

export { PAYLOAD_CAP };

/** What each action does per gateway mode (main.py _run_stages, rules.py RulesStage). */
export const MODE_BEHAVIOR: Record<Action, { monitor: string; enforce: string }> = {
  block: {
    monitor: "Recorded as a hit (shown as Log). The request reaches the API.",
    enforce: "403 Forbidden, error code blocked_by_rule. The request never reaches the API.",
  },
  throttle: {
    monitor: "Requests are counted; over the limit the hit is recorded and the request still reaches the API.",
    enforce:
      "Over the limit: 429 Too Many Requests with a Retry-After header in seconds. Counted per rule and caller (token bucket: limit per window, bursts up to the limit).",
  },
  challenge: {
    monitor: "An unauthenticated request is recorded as a hit and reaches the API.",
    enforce:
      "401 with WWW-Authenticate: Bearer, unless the caller sent a valid API key or JWT, or a well-formed JWT the gateway cannot verify because no JWT key is configured.",
  },
  log: {
    monitor: "Recorded as a hit; the request reaches the API.",
    enforce: "Same as MONITOR: recorded, request passes. Later rules are still checked.",
  },
  allow: {
    monitor: "Recorded; the remaining rules are skipped and the request reaches the API.",
    enforce: "Same: the remaining rules are skipped for this request.",
  },
};

/** Applies to every rule; true of RulesStage. */
export const EVALUATION_NOTE =
  "Rules run in priority order (lower first). The first rule that would stop a request ends rule evaluation for it; in MONITOR that rule is recorded and the later rules are not checked for that request.";
