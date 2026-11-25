"""
Claude Patcher Constants & Security Configuration Matrix.
"""
import platform
import re

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
        "code_consumer": "Q9s() disables Sentry SDK; Yva() disables native crash reporting; preload mc() skips Sentry init (unlocked for 1p via ASAR patch)",
        "scope": "Main, Subprocess & Renderer Sentry (1p + 3p)",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableNonessentialTelemetry",
        "label": "Non-Essential Telemetry (Event Logging)",
        "code_consumer": "uN() returns false halting /api/event_logging/v2/batch & GrowthBook exposure events (unlocked for 1p via ASAR patch)",
        "scope": "Main process batching & child process env (1p + 3p)",
        "confidence": "HIGH (AST & Runtime Verified)"
    },
    {
        "key": "disableNonessentialServices",
        "label": "Non-Essential Services (CDNs / Spellcheck)",
        "code_consumer": "bFs() shuts down Linux dictionary downloads; eEa() disables spellcheck menu; blocks connector-favicons & artifact-sandbox assets",
        "scope": "Spellcheck dictionaries & remote sandbox assets (1p + 3p)",
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
    ("browser-intake-us5-datadoghq.com", "Primary Datadog RUM Ingest (Anthropic us5 cluster)", "CODE_VERIFIED", "Datadog RUM fallback intake domain"),
    ("browser-intake-datadoghq.com", "Global Datadog RUM Telemetry Ingest", "CODE_VERIFIED", "Datadog RUM fallback intake domain table"),
    ("browser-intake-us3-datadoghq.com", "Datadog RUM Telemetry Ingest (us3)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint"),
    ("browser-intake-ap1-datadoghq.com", "Datadog RUM Telemetry Ingest (ap1)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint"),
    ("browser-intake-ap2-datadoghq.com", "Datadog RUM Telemetry Ingest (ap2)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint"),
    ("browser-intake-datadoghq.eu", "Datadog RUM Telemetry Ingest (eu)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint"),
    ("browser-intake-ddog-gov.com", "Datadog RUM Telemetry Ingest (gov)", "PROACTIVE_DEFENSE", "Regional Datadog intake endpoint"),
    ("us5.datadoghq.com", "Datadog API Cluster (us5)", "CODE_VERIFIED", "Datadog RUM site configuration"),
    ("api.us5.datadoghq.com", "Datadog Metric/Tracing API (us5)", "PROACTIVE_DEFENSE", "Subdomain intake target for Datadog tracing"),
    ("o1158394.ingest.us.sentry.io", "Anthropic Dedicated Sentry Ingest", "CODE_VERIFIED", "Primary Sentry DSN ingest host"),
    ("sentry.io", "Global Sentry Error Reporting", "CODE_VERIFIED", "Global error reporting ingest"),
    ("a-cdn.anthropic.com", "Anthropic Tag Manager CDN", "CODE_VERIFIED", "Isolated Segment / ATM bridge script CDN"),
    ("a-api.anthropic.com", "Anthropic Analytics API", "CODE_VERIFIED", "Isolated Segment / ATM analytics endpoint"),
    ("api.segment.io", "Segment User Behavioral Analytics", "PROACTIVE_DEFENSE", "Web analytics ingestion sinkhole"),
    ("cdn.segment.com", "Segment Script Distribution CDN", "PROACTIVE_DEFENSE", "Web analytics script distribution sinkhole")
]

# Verified against Electron 45 / Chrome 156 ELF binary strings (#RE-BINARY)
ANTI_LEAK_SWITCHES = [
    ("QUIC/HTTP3 UDP Bypass Shield", "--disable-quic", "Disables HTTP/3 QUIC over UDP so all traffic routes strictly through TCP proxy"),
    ("Language & Locale Cloaking", "--lang=en-US", "Forces Chromium UI language (aligned with proxy exit locale when cloaked)"),
    ("Chromium Logging Suppression", "--disable-logging", "Disables Chromium internal diagnostic logging to disk")
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

COUNTRY_LANGS = {
    "US": "en-US",
    "GB": "en-GB",
    "CA": "en-CA",
    "DE": "de-DE",
    "NL": "nl-NL",
    "FR": "fr-FR",
    "SE": "sv-SE",
    "CH": "de-CH",
    "TR": "tr-TR",
    "AE": "ar-AE",
    "FI": "fi-FI",
}


def get_lang_for_country(country_code: str | None) -> str:
    """Returns a Chromium --lang tag matching the proxy exit country, defaulting to en-US."""
    if not country_code:
        return "en-US"
    return COUNTRY_LANGS.get(country_code.strip().upper(), "en-US")


CHROMIUM_HARDENING_PREFS = {
    "webrtc": {
        "ip_handling_policy": "disable_non_proxied_udp",
        "multiple_routes_enabled": False,
    },
    "dns_prefetching": {
        "enabled": False,
    },
    "profile": {
        "default_content_setting_values": {
            "geolocation": 2,
            "notifications": 2,
        }
    },
}

# Tracking cookies safe to purge without invalidating Cloudflare/auth session state
TELEMETRY_COOKIE_NAMES = ("_dd_s_v2", "ajs_anonymous_id", "_fbp")


def build_webrequest_iife(strict_sift: bool = False) -> bytes:
    """
    Builds the comma-safe webRequest + session-created + web-contents-created IIFE
    injected into .vite/build/index.chunk-DqepnCaA.js.
    - Preserves chained app listeners (artifactAppMayRequest, file_preview, cowork-artifact).
    - Blocks third-party trackers AND first-party /api/v2/rum, /api/event_logging/, /api/landfill/,
      /api/organizations/*/experiences/track, and a.claude.ai/isolated-segment.html.
    - Leaves s-cdn.anthropic.com / hexagon-analytics.com allowed by default (anti-ban) unless strict_sift=True.
    - Enforces WebRTC disable_non_proxied_udp and denies invasive permissions on all sessions/WebContents.
    """
    sift_hosts = "|s-cdn\\.anthropic\\.com|hexagon-analytics\\.com" if strict_sift else ""
    js = (
        "(()=>{if(globalThis.__clpWebReqInstalled)return;globalThis.__clpWebReqInstalled=!0;"
        "const blk=/^https:\\/\\/(([^/]+\\.)?(datadoghq\\.com|datadoghq\\.eu|ddog-gov\\.com|sentry\\.io|segment\\.io|segment\\.com|doubleclick\\.net|gvt1\\.com)"
        "|a-cdn\\.anthropic\\.com|a-api\\.anthropic\\.com|www\\.googletagmanager\\.com|www\\.googleadservices\\.com|connect\\.facebook\\.net"
        f"|analytics\\.tiktok\\.com|www\\.redditstatic\\.com|bat\\.bing\\.(com|net)|js\\.hs-(scripts|analytics)\\.net|widget\\.intercom\\.io{sift_hosts})\\//i,"
        "fp=/^https:\\/\\/((claude\\.ai|claude\\.com|api\\.anthropic\\.com)\\/api\\/(v2\\/rum|event_logging\\/|landfill\\/)"
        "|(claude\\.ai|claude\\.com)\\/api\\/organizations\\/[^/]+\\/experiences\\/track|a\\.claude\\.ai\\/isolated-segment\\.html)/i,"
        "denyPerms=new Set([\"geolocation\",\"media\",\"notifications\",\"hid\",\"usb\",\"serial\",\"bluetooth\",\"midi-sysex\"]),"
        "isBlk=u=>typeof u===\"string\"&&(blk.test(u)||fp.test(u)),"
        "wrap=s=>{if(!s||s.__clpWrapped)return;s.__clpWrapped=!0;const wr=s.webRequest,orig=wr.onBeforeRequest.bind(wr);let next=null;"
        "const handler=(d,cb)=>{if(isBlk(d?.url))return cb({cancel:!0});return next?next(d,cb):cb({});};"
        "orig(handler);"
        "wr.onBeforeRequest=(a,b)=>{if(typeof a===\"function\"||a===null){next=a;orig(handler);}else{next=b||null;orig(a,handler);}};"
        "try{s.setPermissionRequestHandler((_,p,cb)=>cb(!denyPerms.has(p)));}catch{}"
        "try{s.setPermissionCheckHandler((_,p)=>!denyPerms.has(p));}catch{}};"
        "try{wrap(u.session.defaultSession);}catch{}"
        "u.app.on(\"session-created\",s=>wrap(s));"
        "u.app.on(\"web-contents-created\",(_,wc)=>{try{wc.setWebRTCIPHandlingPolicy(\"disable_non_proxied_udp\");}catch{}});})()"
    )
    return js.encode("utf-8")


# -----------------------------------------------------------------------------
# ASAR Surgical Patches (Applied via AsarArchive Rebuild + V8 Cache Removal)
# -----------------------------------------------------------------------------
SURGICAL_PATCHES = [
    # --- .vite/build/index.pre.js ---
    {
        "id": "sentry_startup_init",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.pre.js",
        "name": "Sentry crash reporter startup init (Cde)",
        "stock": b"function Cde(e){return!e()&&!process.env.CI}",
        "patched": b"function Cde(e){return/*clp_kill_sentry*/!1}",
        "expected_count": 1,
        "description": "Bypasses Sentry client DSN initialization in index.pre.js"
    },
    {
        "id": "crashpad_sentry_start",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.pre.js",
        "name": "Sentry Electron crashReporter.start stub",
        "stock": b'A.log("Starting Electron crashReporter"),y.crashReporter.start({companyName:"",ignoreSystemCrashHandler:!0,productName:y.app.name||y.app.getName(),submitURL:"https://f.a.k/e",uploadToServer:!1,compress:!0})',
        "patched": b"/*clp_kill_crashpad*/void 0",
        "expected_count": 1,
        "description": "Prevents @sentry/electron from spawning chrome_crashpad_handler"
    },
    {
        "id": "crashpad_controller_stub",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.pre.js",
        "name": "Main crashReporter API no-op stub",
        "stock": b'let m=y.crashReporter.start.bind(y.crashReporter);if(y.crashReporter.start=e=>{y.crashReporter.start=m,d8("__claudeCrashReporterStartMs"),m(e),d8("__claudeCrashReporterStartedMs")},',
        "patched": b"let m=()=>{};y.crashReporter&&(y.crashReporter.start=m,y.crashReporter.setUploadToServer=m,y.crashReporter.addExtraParameter=m,y.crashReporter.removeExtraParameter=m);if(/*clp*/",
        "expected_count": 1,
        "description": "Stubs crashReporter start/setUploadToServer/addExtraParameter as safe no-ops"
    },
    {
        "id": "mdm_1p_essential_pre",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.pre.js",
        "name": "MDM 1p unlock: disableEssentialTelemetry (pre)",
        "stock": b'flatKey:"disableEssentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p"]',
        "patched": b'flatKey:"disableEssentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]',
        "expected_count": 1,
        "description": "Allows disableEssentialTelemetry MDM policy on 1p accounts"
    },
    {
        "id": "mdm_1p_nonessential_pre",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.pre.js",
        "name": "MDM 1p unlock: disableNonessentialTelemetry (pre)",
        "stock": b'flatKey:"disableNonessentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p"]',
        "patched": b'flatKey:"disableNonessentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]',
        "expected_count": 1,
        "description": "Allows disableNonessentialTelemetry MDM policy on 1p accounts"
    },
    {
        "id": "mdm_1p_services_pre",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.pre.js",
        "name": "MDM 1p unlock: disableNonessentialServices (pre)",
        "stock": b'flatKey:"disableNonessentialServices",support:{enabled:{scopes:["3p"]',
        "patched": b'flatKey:"disableNonessentialServices",support:{enabled:{scopes:["3p","1p"]',
        "expected_count": 1,
        "description": "Allows disableNonessentialServices MDM policy on 1p accounts"
    },

    # --- .vite/build/index.chunk-DqepnCaA.js ---
    {
        "id": "event_logging_transport",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "EventLogging telemetry transport (uN)",
        "stock": b"function uN(){return!J().telemetry.disableNonessential}",
        "patched": b"function uN(){return/*clp*/!1}",
        "expected_count": 1,
        "description": "Silences /api/event_logging/v2/batch & GrowthBook exposure pipeline"
    },
    {
        "id": "sentry_egress_lock",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "Sentry egress gate permanent lock (Ycr)",
        "stock": b'Ycr=()=>qcr("open","held")',
        "patched": b'Ycr=()=>qcr("blocked")',
        "expected_count": 1,
        "description": "Locks Sentry egress verdict gate to 'blocked'"
    },
    {
        "id": "sentry_mdm_kill_9s",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "Sentry SDK & native crash kill ($9s)",
        "stock": b'$9s=()=>{J().telemetry.disableEssential&&(Q9s("disableEssentialTelemetry"),Yva())}',
        "patched": b'$9s=()=>{Q9s("clp"),Yva()}',
        "expected_count": 1,
        "description": "Unconditionally invokes Q9s() and Yva() to disable main-process Sentry"
    },
    {
        "id": "nonessential_services_guard",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "Non-essential services guard (bFs) & 1p unlock (xFs)",
        "stock": b"if(!J().telemetry.disableNonessentialServices)return;",
        "patched": b"if(!J().telemetry.disableNonessentialServices&&J().telemetry.disableNonessential!==!0)return;",
        "expected_count": 1,
        "description": "Honors disableNonessentialServices and disableNonessential in bFs()"
    },
    {
        "id": "xfs_1p_unlock",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "Enable xFs() on 1p accounts",
        "stock": b'U().type==="3p"&&(CIn(),NTt(),xFs(),POa())',
        "patched": b'xFs(),U().type==="3p"&&(CIn(),NTt(),POa())',
        "expected_count": 1,
        "description": "Activates xFs() telemetry cleanup on 1p accounts without breaking 3p hooks"
    },
    {
        "id": "growthbook_header",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "GrowthBook device-id header strip ($Zt)",
        "stock": b'headers:Awt()?{...r,"anthropic-device-id":fke(Kf())}:r',
        "patched": b"headers:/*clp_gb*/r",
        "expected_count": 1,
        "description": "Strips anthropic-device-id in GrowthBook $Zt() while preserving Awt()/Lus() consent"
    },
    {
        "id": "mdm_1p_essential_chunk",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "MDM 1p unlock: disableEssentialTelemetry (chunk)",
        "stock": b'flatKey:"disableEssentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p"]',
        "patched": b'flatKey:"disableEssentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]',
        "expected_count": 1,
        "description": "Allows disableEssentialTelemetry MDM policy on 1p accounts"
    },
    {
        "id": "mdm_1p_nonessential_chunk",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "MDM 1p unlock: disableNonessentialTelemetry (chunk)",
        "stock": b'flatKey:"disableNonessentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p"]',
        "patched": b'flatKey:"disableNonessentialTelemetry",readers:["desktop","code"],support:{enabled:{scopes:["3p","1p"]',
        "expected_count": 1,
        "description": "Allows disableNonessentialTelemetry MDM policy on 1p accounts"
    },
    {
        "id": "mdm_1p_services_chunk",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "MDM 1p unlock: disableNonessentialServices (chunk)",
        "stock": b'flatKey:"disableNonessentialServices",support:{enabled:{scopes:["3p"]',
        "patched": b'flatKey:"disableNonessentialServices",support:{enabled:{scopes:["3p","1p"]',
        "expected_count": 1,
        "description": "Allows disableNonessentialServices MDM policy on 1p accounts"
    },
    {
        "id": "electron_webrequest_firewall",
        "file_key": "asar_path",
        "archive_path": ".vite/build/index.chunk-DqepnCaA.js",
        "name": "Session-aware webRequest firewall & WebRTC policy",
        "stock": b'u.app.on("session-created",(e=>aOe(e)))',
        "patched": build_webrequest_iife(strict_sift=False) + b',u.app.on("session-created",(e=>aOe(e)))',
        "check_marker": b"globalThis.__clpWebReqInstalled=!0",
        "expected_count": 1,
        "description": "Chains defaultSession + session-created webRequest, preserves artifactAppMayRequest, blocks 1p/3p telemetry, enforces WebRTC disable_non_proxied_udp"
    },

    # --- Preload Sentry Neutralization (4 files) ---
    {
        "id": "preload_sentry_main",
        "file_key": "asar_path",
        "archive_path": ".vite/build/mainWindow.js",
        "name": "Preload Sentry disable (mainWindow.js)",
        "stock_regex": re.compile(rb"![A-Za-z0-9_$]+&&!\{\}\.CI&&[A-Za-z0-9_$]+\(\)"),
        "stock": b"!Ac&&!{}.CI&&ic()",
        "patched": b"!1",
        "check_marker": b"return!1",
        "expected_count": 1,
        "description": "Disables preload Sentry initialization in mainWindow.js"
    },
    {
        "id": "preload_sentry_quick",
        "file_key": "asar_path",
        "archive_path": ".vite/build/quickWindow.js",
        "name": "Preload Sentry disable (quickWindow.js)",
        "stock_regex": re.compile(rb"![A-Za-z0-9_$]+&&!\{\}\.CI&&[A-Za-z0-9_$]+\(\)"),
        "stock": b"!yc&&!{}.CI&&pc()",
        "patched": b"!1",
        "check_marker": b"return!1",
        "expected_count": 1,
        "description": "Disables preload Sentry initialization in quickWindow.js"
    },
    {
        "id": "preload_sentry_about",
        "file_key": "asar_path",
        "archive_path": ".vite/build/aboutWindow.js",
        "name": "Preload Sentry disable (aboutWindow.js)",
        "stock_regex": re.compile(rb"![A-Za-z0-9_$]+&&!\{\}\.CI&&[A-Za-z0-9_$]+\(\)"),
        "stock": b"!yc&&!{}.CI&&pc()",
        "patched": b"!1",
        "check_marker": b"return!1",
        "expected_count": 1,
        "description": "Disables preload Sentry initialization in aboutWindow.js"
    },
    {
        "id": "preload_sentry_find",
        "file_key": "asar_path",
        "archive_path": ".vite/build/findInPage.js",
        "name": "Preload Sentry disable (findInPage.js)",
        "stock_regex": re.compile(rb"![A-Za-z0-9_$]+&&!\{\}\.CI&&[A-Za-z0-9_$]+\(\)"),
        "stock": b"!pc&&!{}.CI&&sc()",
        "patched": b"!1",
        "check_marker": b"return!1",
        "expected_count": 1,
        "description": "Disables preload Sentry initialization in findInPage.js"
    },
]
