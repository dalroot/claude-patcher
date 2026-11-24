"""
Claude Patcher Constants & Security Configuration Matrix.
"""
import platform

VERSION = "1.0.0-beta"
CURRENT_OS = platform.system()

# -----------------------------------------------------------------------------
# Official Claude Asterisk / Starburst Logo (Exact SVG Vector Rasterization)
# -----------------------------------------------------------------------------
CLAUDE_COLOR = "#D97757"  # Official Anthropic Terracotta
CLAUDE_ASCII_LOGO = [
    "     ██    █▄       ",
    "     ▀██  ▄█▀ ▄██   ",
    " ▀██▄ ▀██ ██ ▄██▀   ",
    "   ▀███████████     ",
    "▄▄▄▄▄▄▀███████▄████▀",
    "▀▀▀▀▀▀▀████████▄▄▄▄▄",
    "   ▄▄██▀██████▄ ▀▀▀▀",
    "  ██▀ ▄█▀██ ██▀█▄   ",
    "    ▄█▀  ██  ▀█▄ ▀  ",
    "         █▀   ▀     "
]

# -----------------------------------------------------------------------------
# Evidence-Based MDM Policy Matrix & Sinks
# -----------------------------------------------------------------------------
MANAGED_POLICIES = [
    {
        "key": "disableEssentialTelemetry",
        "label": "Essential Telemetry (Crash / Sentry)",
        "code_consumer": "Q9s() disables Sentry SDK; Yva() disables native crash reporting (admin_opt_out); mc() in preload signals renderer to skip Sentry init Js()",
        "scope": "Main, Subprocess & Renderer Sentry",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableNonessentialTelemetry",
        "label": "Non-Essential Telemetry (Event Logging)",
        "code_consumer": "uN() checks !telemetry.disableNonessential; qTr() returns \"off\" halting network transport to /api/event_logging/v2/batch",
        "scope": "Main process batching & child process env",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableNonessentialServices",
        "label": "Non-Essential Services (CDNs / Spellcheck)",
        "code_consumer": "bFs() shuts down Linux dictionary downloads; eEa() disables spellcheck menu; blocks connector-favicons & artifact-sandbox assets",
        "scope": "Spellcheck dictionaries & remote sandbox assets",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableAutoUpdates",
        "label": "Automatic Updates Ingestion",
        "code_consumer": "yWt(e, 'disableAutoUpdates') in updater endpoint; inhibits background update polling and did query string transmission",
        "scope": "Periodic update timer & release polling",
        "confidence": "MEDIUM (Schema & Updater Logic)"
    }
]

TRACKER_SINKS = [
    ("browser-intake-us5-datadoghq.com", "Primary Datadog RUM Ingest (Anthropic us5 cluster)", "CODE_VERIFIED", "Extracted from ion-dist.asar Datadog configuration: us5.datadoghq.com"),
    ("browser-intake-datadoghq.com", "Global Datadog RUM Telemetry Ingest", "CODE_VERIFIED", "Extracted from ion-dist.asar fallback intake domain table"),
    ("browser-intake-us3-datadoghq.com", "Datadog RUM Telemetry Ingest (us3)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint from ion-dist.asar"),
    ("browser-intake-ap1-datadoghq.com", "Datadog RUM Telemetry Ingest (ap1)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint from ion-dist.asar"),
    ("browser-intake-ap2-datadoghq.com", "Datadog RUM Telemetry Ingest (ap2)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint from ion-dist.asar"),
    ("browser-intake-datadoghq.eu", "Datadog RUM Telemetry Ingest (eu)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint from ion-dist.asar"),
    ("browser-intake-ddog-gov.com", "Datadog RUM Telemetry Ingest (gov)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint from ion-dist.asar"),
    ("us5.datadoghq.com", "Datadog API Cluster (us5)", "CODE_VERIFIED", "Extracted from ion-dist.asar Datadog site config"),
    ("api.us5.datadoghq.com", "Datadog Metric/Tracing API (us5)", "PROACTIVE_DEFENSE", "Subdomain intake target for Datadog tracing"),
    ("o1158394.ingest.us.sentry.io", "Anthropic Dedicated Sentry Ingest", "CODE_VERIFIED", "Endpoint table firewallAlso target; backed up by Q9s code kill-switch"),
    ("sentry.io", "Global Sentry Error Reporting", "CODE_VERIFIED", "Global error reporting ingest; backed up by Q9s code kill-switch"),
    ("hexagon-analytics.com", "Sift Anti-Fraud Beacon Destination", "PROACTIVE_DEFENSE", "Extracted from s.js beacon; unobserved in standalone desktop binary"),
    ("s-cdn.anthropic.com", "Sift JavaScript Distribution CDN", "PROACTIVE_DEFENSE", "Found in coworker/frame egress allowlist; loaded by claude.ai frontend"),
    ("api.segment.io", "Segment User Behavioral Analytics", "PROACTIVE_DEFENSE", "Web analytics ingestion sinkhole"),
    ("cdn.segment.com", "Segment Script Distribution CDN", "PROACTIVE_DEFENSE", "Web analytics script distribution sinkhole")
]

ANTI_LEAK_SWITCHES = [
    ("WebRTC IP Leak Shield", "--disable-webrtc", "Completely disables WebRTC P2P stack; prevents STUN UDP queries from leaking real interface IP"),
    ("WebRTC Proxy Enforcement", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "Strictly forbids WebRTC from using any interface not routed through proxy"),
    ("WebRTC Permission Enforcer", "--enforce-webrtc-ip-permission-check", "Enforces strict permission check before any WebRTC address exposure"),
    ("DNS Prefetch Shield", "--dns-prefetch-disable", "Disables speculative DNS pre-resolution; translated to --blink-settings=dnsPrefetchingEnabled=false"),
    ("Background Network Shield", "--disable-background-networking", "Inhibits Chromium internal background network queries and phone-home pings"),
    ("Component Auto-Update Shield", "--disable-component-update", "Prevents independent browser engine component downloads"),
    ("Domain Reliability Telemetry", "--disable-domain-reliability", "Stops Chromium from sending domain connectivity metrics to telemetry servers"),
    ("Hyperlink Ping Shield", "--no-pings", "Disables HTML hyperlink auditing and background pings"),
    ("Phishing Telemetry Shield", "--disable-client-side-phishing-detection", "Prevents client metadata transmission to Google SafeBrowsing clusters"),
    ("Crashpad Dump Containment", "--disable-breakpad", "Disables native Breakpad minidump exfiltration (Crashpad upload inhibited via MDM)"),
    ("Language & Locale Cloaking", "--lang=en-US", "Forces standard US English UI language to prevent regional locale leakage")
]

COUNTRY_TIMEZONES = {
    "NL": "Europe/Amsterdam",
    "DE": "Europe/Berlin",
    "GB": "Europe/London",
    "FR": "Europe/Paris",
    "US": "America/New_York",
    "SE": "Europe/Stockholm",
    "CH": "Europe/Zurich",
    "CA": "America/Toronto",
    "TR": "Europe/Istanbul",
    "AE": "Asia/Dubai",
    "FI": "Europe/Helsinki"
}

# -----------------------------------------------------------------------------
# ASAR Surgical In-Place Patch Signatures (Zero-Byte Drift Mandate)
# -----------------------------------------------------------------------------
STOCK_ASAR_TARGET = b"function Awt(){return Kf(),kwt}"
PATCHED_ASAR_TARGET = b"function Awt(){return/*clp*/!1}"

SURGICAL_PATCHES = [
    {
        "id": "growthbook_header",
        "file_key": "asar_path",
        "name": "GrowthBook device-id header ($Zt)",
        "stock": b"function Awt(){return Kf(),kwt}",
        "patched": b"function Awt(){return/*clp*/!1}",
        "expected_count": 1,
        "description": "Neutralizes anthropic-device-id header injection in feature flag queries"
    },
    {
        "id": "event_logging_transport",
        "file_key": "asar_path",
        "name": "EventLogging telemetry transport (uN)",
        "stock": b"function uN(){return!J().telemetry.disableNonessential}",
        "patched": b"function uN(){return/*clp-kill-telemetry-transport*/!1}",
        "expected_count": 1,
        "description": "Silences /api/event_logging/v2/batch pipeline uploading CPU, RAM, and install_id"
    },
    {
        "id": "sentry_startup_init",
        "file_key": "asar_path",
        "name": "Sentry crash reporter startup init (Cde)",
        "stock": b"function Cde(e){return!e()&&!process.env.CI}",
        "patched": b"function Cde(e){return/*clp_kill_sentry*/!1}",
        "expected_count": 1,
        "description": "Bypasses Sentry client DSN initialization and crashReporter startup"
    },
    {
        "id": "sentry_egress_lock",
        "file_key": "asar_path",
        "name": "Sentry egress gate permanent lock (Ycr)",
        "stock": b'Ycr=()=>qcr("open","held")',
        "patched": b'Ycr=()=>qcr("blocked"    )',
        "expected_count": 1,
        "description": "Locks Sentry egress verdict gate to 'blocked', preventing open status"
    },
    {
        "id": "electron_webrequest_firewall",
        "file_key": "asar_path",
        "name": "Electron in-memory firewall (webRequest)",
        "stock": b'if(zv?.("evenWhenOff")?.artifactAppMayRequest?.(e)===!1)return t({cancel:!0});',
        "patched": b'if(/datadoghq|sentry\\.io|segment\\.io/.test(e.url))return t({cancel:!0});      ',
        "expected_count": 1,
        "description": "Cancels any Datadog, Sentry, or Segment telemetry egress while preserving local vendor assets"
    },
    {
        "id": "oauth_device_id",
        "file_key": "asar_path",
        "name": "OAuth authorize device-id neutralize (mgr)",
        "stock": b'async function mgr(){try{let e=$k();return eA(await u.session.defaultSession.cookies.get({url:e,name:KQt.DEVICE_ID_KEY}),new URL(e).hostname)?.value||void 0}catch{return}}',
        "patched": b'async function mgr(){return/*clp_neutralize_device_id_cookie_read_for_oauth*/void 0;                                                                                      }',
        "expected_count": 1,
        "description": "Prevents device-id cookie injection into OAuth authorize requests"
    },
    {
        "id": "datadog_beforesend_drop",
        "file_key": "ion_asar_path",
        "name": "Datadog RUM beforeSend drop-all (Ect)",
        "stock": b'function Ect(e,t){if($st(e,lp().siftCdnHost,t))return!1;',
        "patched": b'function Ect(e,t){return/*clp_drop*/!1;                }',
        "expected_count": 1,
        "description": "Forces Datadog RUM beforeSend hook to drop 100% of telemetry events"
    },
    {
        "id": "datadog_sample_rate_zero",
        "file_key": "ion_asar_path",
        "name": "Datadog RUM 0% session sampling",
        "stock": b'sessionSampleRate:100',
        "patched": b'sessionSampleRate:  0',
        "expected_count": 2,
        "description": "Reduces Datadog RUM browser session sample rate from 100% to 0%"
    }
]
