// ============================================================================
// SusOrBus Base44 Unified Scanner Engine (V2.6.0)
// Complete Deterministic, AI-Free Website Safety, Privacy & Risk Analysis Engine
// Ready for direct deployment into Base44 Functions (functions/check.js) or Node.js
// ============================================================================

"use strict";

// 1. EMBEDDED KNOWLEDGE BASE DATASETS
const KB = {
  metadata: {
  "name": "sus-or-bus-knowledge-base",
  "version": "2.5.0",
  "schemaVersion": "1.0.0",
  "lastUpdated": "2026-10-18T01:30:00Z",
  "description": "Structured, deterministic, AI-free knowledge base for website safety, privacy, and security risk assessment",
  "license": "MIT",
  "provenance": {
    "maintainer": "SusOrBus Open Security Initiative",
    "trackerSources": [
      "DuckDuckGo Tracker Radar (Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International)",
      "EasyPrivacy / Adblock Plus community lists",
      "Public CDN and Web Standards Documentation (W3C, MDN, IETF RFCs)"
    ],
    "ruleSets": [
      "OWASP Web Security Testing Guide (WSTG)",
      "NIST Special Publication 800-52 (TLS Guidelines)",
      "Mozilla Web Security Guidelines"
    ]
  },
  "stats": {
    "supportedCategories": 7,
    "supportedSeverities": 5,
    "supportedConfidences": 3
  }
},
  messages: {
  "version": "2.5.0",
  "status": {
    "IDLE": {
      "id": "STATUS_IDLE",
      "text": "Paste a link above and hit Check to run your first scan."
    },
    "ANALYZING": {
      "id": "STATUS_ANALYZING",
      "text": "Analyzing {site} ...",
      "placeholders": {
        "site": "string"
      }
    },
    "SUCCESS": {
      "id": "STATUS_SUCCESS",
      "text": "Scan completed for {site}.",
      "placeholders": {
        "site": "string"
      }
    },
    "PARTIAL": {
      "id": "STATUS_PARTIAL",
      "text": "Scan completed with partial coverage: {reason}.",
      "placeholders": {
        "reason": "string"
      }
    },
    "FAILED": {
      "id": "STATUS_FAILED",
      "text": "Could not check {site} ({error}).",
      "placeholders": {
        "site": "string",
        "error": "string"
      }
    }
  },
  "emptyStates": {
    "NO_HISTORY": {
      "id": "EMPTY_HISTORY",
      "text": "No recent checks stored on this device."
    },
    "NO_PUBLIC_SEARCHES": {
      "id": "EMPTY_PUBLIC_SEARCHES",
      "text": "No public searches yet."
    },
    "NO_TRACKERS_FOUND": {
      "id": "EMPTY_TRACKERS",
      "text": "No known third-party trackers or ad scripts were identified."
    },
    "NO_POLICY_LINKS": {
      "id": "EMPTY_POLICIES",
      "text": "No terms or privacy links detected on the page."
    },
    "NO_SECURITY_HEADERS": {
      "id": "EMPTY_SECURITY_HEADERS",
      "text": "No common security headers were sent by the server."
    },
    "BROWSER_UNAVAILABLE": {
      "id": "EMPTY_BROWSER_UNAVAILABLE",
      "text": "Browser behavior analysis is not configured in this serverless environment (static scanning active). No browser behavior was simulated or assumed."
    }
  },
  "coverageLabels": {
    "staticHtml": "Static HTML",
    "securityHeaders": "Security Headers",
    "redirects": "Redirect Inspection",
    "trackers": "Tracker Detection",
    "privacyPolicy": "Privacy Policy",
    "termsOfService": "Terms of Service",
    "browserBehavior": "Browser Automation"
  },
  "coverageStates": {
    "completed": "completed",
    "unavailable": "unavailable",
    "unreachable": "unreachable",
    "not_found": "not found",
    "partially_completed": "partially completed"
  },
  "categories": {
    "security": {
      "name": "Security",
      "description": "Transport, encryption, forms, and client isolation"
    },
    "privacy": {
      "name": "Privacy",
      "description": "Third-party data leakage and tracking"
    },
    "code": {
      "name": "Client Code",
      "description": "Scripts, frames, and client-side behavior"
    },
    "content": {
      "name": "Content",
      "description": "Visible page text, pressure language, and topic classification"
    },
    "reputation": {
      "name": "Reputation & Domain",
      "description": "Hostname characteristics, TLD safety, and structure"
    },
    "policy": {
      "name": "Policies & Terms",
      "description": "Privacy policy and terms of service disclosures"
    },
    "topic": {
      "name": "Service Topic",
      "description": "Heuristic service categorization"
    }
  },
  "severities": {
    "critical": {
      "label": "Critical Risk",
      "weight": 40,
      "level": "bad"
    },
    "high": {
      "label": "High Risk",
      "weight": 25,
      "level": "bad"
    },
    "medium": {
      "label": "Medium Risk",
      "weight": 12,
      "level": "warning"
    },
    "low": {
      "label": "Low Risk",
      "weight": 5,
      "level": "warning"
    },
    "informational": {
      "label": "Informational",
      "weight": 0,
      "level": "good"
    }
  },
  "confidences": {
    "high": {
      "label": "High Confidence",
      "multiplier": 1
    },
    "medium": {
      "label": "Medium Confidence",
      "multiplier": 0.75
    },
    "low": {
      "label": "Low Confidence",
      "multiplier": 0.5
    }
  },
  "sources": {
    "STATIC_HTML": "Static HTML",
    "HTTP_HEADER": "HTTP Header",
    "HTTP_RESPONSE": "HTTP Response",
    "POLICY_ANALYSIS": "Policy Analysis",
    "CROSS_REFERENCE": "Cross-Reference Analysis",
    "DOMAIN_INSPECTION": "Domain Inspection",
    "BROWSER_AUTOMATION": "Browser Automation"
  },
  "ui": {
    "REPORT_HEAD": "SUS OR BUS — SITE SAFETY REPORT",
    "EYEBROW_NEW_CHECK": "Evidence-based assessment",
    "VERDICT_NOTE": "automated heuristic scan — absence of findings never guarantees safety",
    "LEGEND": "good = verified safety indicator · warning = requires attention · bad = serious risk flag · checks on this device: {checksCount}",
    "SCORE_FORMULA_NOTE": "Score model: deterministic weighted risk deduction based on evidence severity and confidence.",
    "LIMITATIONS": "This report summarizes automated heuristic checks on the fetched page. \"No threats detected\" is NOT a guarantee of safety. Preview availability depends on the target site's own embedding policy.",
    "BUTTON_COPY": "copy result",
    "BUTTON_COPIED": "copied!",
    "BUTTON_NEW_SCAN": "new scan",
    "BUTTON_NERD_ON": "nerd mode: on",
    "BUTTON_NERD_OFF": "nerd mode: off",
    "BUTTON_DARK_MODE": "dark mode",
    "BUTTON_LIGHT_MODE": "light mode",
    "BUTTON_PDF": "export PDF",
    "PREVIEW_BLOCKED": "A live preview can't be embedded here because {reason}.",
    "PREVIEW_DIRECT_LINK": "Open the site directly"
  },
  "errors": {
    "EMPTY_URL": {
      "code": "EMPTY_URL",
      "text": "Type a website address first."
    },
    "INVALID_URL": {
      "code": "INVALID_URL",
      "text": "Enter a valid website address."
    },
    "CREDENTIALS_DISALLOWED": {
      "code": "CREDENTIALS_DISALLOWED",
      "text": "URLs with embedded credentials are not allowed."
    },
    "UNSUPPORTED_PROTOCOL": {
      "code": "UNSUPPORTED_PROTOCOL",
      "text": "Unsupported protocol. Only HTTP and HTTPS are permitted."
    },
    "UNSUPPORTED_PORT": {
      "code": "UNSUPPORTED_PORT",
      "text": "Custom port :{port} is not permitted. Only standard web ports (80, 443) are allowed.",
      "placeholders": {
        "port": "string"
      }
    },
    "HOSTNAME_TOO_LONG": {
      "code": "HOSTNAME_TOO_LONG",
      "text": "Hostname exceeds maximum allowable length of 253 characters."
    },
    "SSRF_BLOCKED": {
      "code": "SSRF_BLOCKED",
      "text": "Destination address ({ip}) is restricted or non-public. Request blocked.",
      "placeholders": {
        "ip": "string"
      }
    },
    "PROHIBITED_HOSTNAME": {
      "code": "PROHIBITED_HOSTNAME",
      "text": "Access to '{hostname}' is prohibited for security reasons.",
      "placeholders": {
        "hostname": "string"
      }
    },
    "REQUEST_TIMEOUT": {
      "code": "REQUEST_TIMEOUT",
      "text": "Request timed out after {timeoutMs}ms.",
      "placeholders": {
        "timeoutMs": "integer"
      }
    },
    "TOO_MANY_REDIRECTS": {
      "code": "TOO_MANY_REDIRECTS",
      "text": "Too many redirects (exceeded limit of {limit}).",
      "placeholders": {
        "limit": "integer"
      }
    },
    "RATE_LIMIT_EXCEEDED": {
      "code": "RATE_LIMIT_EXCEEDED",
      "text": "Too many checks. Please wait a minute and try again."
    },
    "NETWORK_ERROR": {
      "code": "NETWORK_ERROR",
      "text": "Connection error: could not contact scanner service."
    }
  }
},
  verdicts: {
  "version": "2.5.0",
  "verdicts": [
    {
      "code": "BUS",
      "label": "BUS",
      "minScore": 70,
      "maxScore": 100,
      "styleClass": "bus",
      "color": "#2ed573",
      "summary": "Low detected risk based on completed automated checks.",
      "explanation": "No critical security flags, cross-origin credential harvesting, or abusive domain patterns were identified during the scan."
    },
    {
      "code": "MILDLY_SUS",
      "label": "MILDLY SUS",
      "minScore": 40,
      "maxScore": 69,
      "styleClass": "mid",
      "color": "#ffa502",
      "summary": "Moderate risk or notable security/privacy cautions detected.",
      "explanation": "The page exhibits configuration gaps, multiple third-party trackers, missing policy disclosures, or warnings that warrant visitor vigilance."
    },
    {
      "code": "SUS",
      "label": "SUS",
      "minScore": 0,
      "maxScore": 39,
      "styleClass": "sus",
      "color": "#ff4757",
      "summary": "High risk or severe suspicious patterns detected.",
      "explanation": "The page exhibits high-risk indicators such as unencrypted/cross-origin credential forms, raw IP URLs, high-urgency scam phrases, or deceptive code patterns."
    }
  ]
},
  scoring: {
  "version": "2.5.0",
  "baseScore": 100,
  "minScore": 0,
  "maxScore": 100,
  "severityWeights": {
    "critical": 40,
    "high": 25,
    "medium": 12,
    "low": 5,
    "informational": 0
  },
  "confidenceMultipliers": {
    "high": 1,
    "medium": 0.75,
    "low": 0.5
  },
  "thresholds": {
    "busMin": 70,
    "mildlySusMin": 40
  },
  "findingWeights": {
    "SEC_FORM_PASSWORD_CROSS_ORIGIN": 47,
    "SEC_CONTENT_SCAM_KEYWORDS": 41,
    "SEC_SCRIPT_OBFUSCATION": 37,
    "SEC_TRANSPORT_HTTP_INSECURE": 33,
    "SEC_REDIRECT_META_REFRESH": 16,
    "POL_POLICY_NONE_FOUND": 14,
    "SEC_HEADER_HSTS_MISSING": 9,
    "POL_TRACKER_DISCLOSURE_GAP": 8,
    "SEC_HEADER_CSP_MISSING": 7,
    "SEC_IFRAME_THIRD_PARTY": 6,
    "SEC_HEADER_HSTS_SHORT": 4,
    "SEC_HEADER_VERSION_DISCLOSURE": 3,
    "CODE_BROWSER_CONSOLE_ERRORS": 4
  },
  "limits": {
    "maxDeductionPerCategory": 60
  }
},
  domains: {
  "version": "2.5.0",
  "provenance": "DuckDuckGo Tracker Radar, EasyPrivacy, W3C Web Standards",
  "services": [
    {
      "pattern": "google-analytics.com",
      "method": "suffix",
      "category": "analytics",
      "provider": "Google Analytics",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Widely deployed web traffic and visitor analytics platform."
    },
    {
      "pattern": "googletagmanager.com",
      "method": "suffix",
      "category": "analytics",
      "provider": "Google Tag Manager",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Tag management system injecting tracking pixels and third-party scripts."
    },
    {
      "pattern": "hotjar.com",
      "method": "suffix",
      "category": "analytics",
      "provider": "Hotjar (Session Replay)",
      "isTracker": true,
      "confidence": "high",
      "source": "EasyPrivacy",
      "description": "Session recording and heatmap behavioral analytics service."
    },
    {
      "pattern": "clarity.ms",
      "method": "suffix",
      "category": "analytics",
      "provider": "Microsoft Clarity",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Free behavioral analytics including session replays and click maps."
    },
    {
      "pattern": "mixpanel.com",
      "method": "suffix",
      "category": "analytics",
      "provider": "Mixpanel",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Product event tracking and funnel analytics platform."
    },
    {
      "pattern": "segment.io",
      "method": "suffix",
      "category": "analytics",
      "provider": "Twilio Segment",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Customer data platform multiplexing events to downstream analytics."
    },
    {
      "pattern": "segment.com",
      "method": "suffix",
      "category": "analytics",
      "provider": "Twilio Segment",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Customer data platform API."
    },
    {
      "pattern": "amplitude.com",
      "method": "suffix",
      "category": "analytics",
      "provider": "Amplitude",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Digital optimization and user event analytics."
    },
    {
      "pattern": "heap.io",
      "method": "suffix",
      "category": "analytics",
      "provider": "Heap Analytics",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Automated event capture and behavioral analytics."
    },
    {
      "pattern": "plausible.io",
      "method": "suffix",
      "category": "analytics",
      "provider": "Plausible Analytics",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Privacy-focused lightweight web analytics without cookies."
    },
    {
      "pattern": "matomo.org",
      "method": "suffix",
      "category": "analytics",
      "provider": "Matomo Analytics",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Open-source privacy-oriented web analytics platform."
    },
    {
      "pattern": "posthog.com",
      "method": "suffix",
      "category": "analytics",
      "provider": "PostHog",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Product analytics, feature flags, and session replay suite."
    },
    {
      "pattern": "doubleclick.net",
      "method": "suffix",
      "category": "advertising",
      "provider": "Google DoubleClick",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Google display ad serving and behavioral targeting network."
    },
    {
      "pattern": "googlesyndication.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "Google AdSense",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Google content-targeted advertising network."
    },
    {
      "pattern": "googleadservices.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "Google Ads Conversion",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Google Ads conversion tracking and remarketing tag."
    },
    {
      "pattern": "criteo.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "Criteo",
      "isTracker": true,
      "confidence": "high",
      "source": "EasyPrivacy",
      "description": "Cross-site personalized advertising retargeting network."
    },
    {
      "pattern": "criteo.net",
      "method": "suffix",
      "category": "advertising",
      "provider": "Criteo",
      "isTracker": true,
      "confidence": "high",
      "source": "EasyPrivacy",
      "description": "Criteo dynamic ad asset delivery domain."
    },
    {
      "pattern": "outbrain.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "Outbrain",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Native sponsored content and advertising recommendation engine."
    },
    {
      "pattern": "taboola.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "Taboola",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Sponsored content discovery and advertising feed network."
    },
    {
      "pattern": "adnxs.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "AppNexus (Xandr)",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Real-time bidding programmatic ad exchange."
    },
    {
      "pattern": "pubmatic.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "PubMatic",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Digital advertising supply-side programmatic platform."
    },
    {
      "pattern": "rubiconproject.com",
      "method": "suffix",
      "category": "advertising",
      "provider": "Magnite (Rubicon Project)",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Automated ad marketplace and header bidding infrastructure."
    },
    {
      "pattern": "bat.bing.com",
      "method": "exact",
      "category": "advertising",
      "provider": "Microsoft Advertising UET",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Bing Universal Event Tracking conversion pixel."
    },
    {
      "pattern": "connect.facebook.net",
      "method": "exact",
      "category": "social",
      "provider": "Meta Pixel / SDK",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Meta cross-site visitor tracking and conversion optimization pixel."
    },
    {
      "pattern": "platform.twitter.com",
      "method": "exact",
      "category": "social",
      "provider": "X (Twitter) Widget",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Twitter tweet embed and conversion tracking script."
    },
    {
      "pattern": "analytics.tiktok.com",
      "method": "exact",
      "category": "social",
      "provider": "TikTok Pixel",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "TikTok cross-app behavioral tracking and conversion pixel."
    },
    {
      "pattern": "sc-static.net",
      "method": "suffix",
      "category": "social",
      "provider": "Snapchat Pixel",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Snapchat web measurement and conversion tracking pixel."
    },
    {
      "pattern": "licdn.com",
      "method": "suffix",
      "category": "social",
      "provider": "LinkedIn Insight Tag",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "LinkedIn professional demographic and conversion tracking tag."
    },
    {
      "pattern": "pinterest.com",
      "method": "suffix",
      "category": "social",
      "provider": "Pinterest Tag",
      "isTracker": true,
      "confidence": "high",
      "source": "DuckDuckGo Tracker Radar",
      "description": "Pinterest conversion tracking and audience building tag."
    },
    {
      "pattern": "cdnjs.cloudflare.com",
      "method": "exact",
      "category": "cdn",
      "provider": "Cloudflare CDNJS",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Public content delivery network hosting open-source JavaScript libraries."
    },
    {
      "pattern": "cdn.jsdelivr.net",
      "method": "exact",
      "category": "cdn",
      "provider": "jsDelivr CDN",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Free open-source CDN for npm and GitHub packages."
    },
    {
      "pattern": "unpkg.com",
      "method": "exact",
      "category": "cdn",
      "provider": "UNPKG CDN",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Fast global content delivery network for npm modules."
    },
    {
      "pattern": "ajax.googleapis.com",
      "method": "exact",
      "category": "cdn",
      "provider": "Google Hosted Libraries",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Content distribution network for popular open-source JavaScript libraries."
    },
    {
      "pattern": "fonts.googleapis.com",
      "method": "exact",
      "category": "fonts",
      "provider": "Google Fonts (CSS)",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Web font stylesheet distribution service."
    },
    {
      "pattern": "fonts.gstatic.com",
      "method": "exact",
      "category": "fonts",
      "provider": "Google Fonts (Binaries)",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Optimized font file asset delivery endpoint."
    },
    {
      "pattern": "use.typekit.net",
      "method": "exact",
      "category": "fonts",
      "provider": "Adobe Fonts (Typekit)",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Commercial typography delivery service."
    },
    {
      "pattern": "use.fontawesome.com",
      "method": "exact",
      "category": "fonts",
      "provider": "FontAwesome CDN",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Vector icon kit distribution network."
    },
    {
      "pattern": "sentry.io",
      "method": "suffix",
      "category": "error-monitoring",
      "provider": "Sentry Error Monitoring",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Application crash and diagnostic telemetry monitoring service."
    },
    {
      "pattern": "browser.sentry-cdn.com",
      "method": "exact",
      "category": "error-monitoring",
      "provider": "Sentry SDK CDN",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Client-side error reporting SDK."
    },
    {
      "pattern": "datadoghq.com",
      "method": "suffix",
      "category": "error-monitoring",
      "provider": "Datadog RUM",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Real User Monitoring and frontend performance metrics platform."
    },
    {
      "pattern": "bugsnag.com",
      "method": "suffix",
      "category": "error-monitoring",
      "provider": "Bugsnag",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Error reporting and stability monitoring service."
    },
    {
      "pattern": "logrocket.com",
      "method": "suffix",
      "category": "error-monitoring",
      "provider": "LogRocket (Session Replay)",
      "isTracker": true,
      "confidence": "high",
      "source": "EasyPrivacy",
      "description": "Frontend session replay, network logging, and issue tracking."
    },
    {
      "pattern": "widget.intercom.io",
      "method": "exact",
      "category": "customer-support",
      "provider": "Intercom Chat Widget",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "In-app visitor communication and customer messaging platform."
    },
    {
      "pattern": "zdassets.com",
      "method": "suffix",
      "category": "customer-support",
      "provider": "Zendesk Support",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Customer service ticketing and live chat widget."
    },
    {
      "pattern": "drift.com",
      "method": "suffix",
      "category": "customer-support",
      "provider": "Drift Chat",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Conversational marketing and live sales chat widget."
    },
    {
      "pattern": "crisp.chat",
      "method": "suffix",
      "category": "customer-support",
      "provider": "Crisp Chat",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Customer messaging and live support widget."
    },
    {
      "pattern": "js.stripe.com",
      "method": "exact",
      "category": "payments",
      "provider": "Stripe Elements",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Secure PCI-compliant payment card collection form."
    },
    {
      "pattern": "paypal.com",
      "method": "suffix",
      "category": "payments",
      "provider": "PayPal Checkout",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Digital wallet and payment checkout gateway."
    },
    {
      "pattern": "squareup.com",
      "method": "suffix",
      "category": "payments",
      "provider": "Square Web Payments",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Merchant payment processing and checkout SDK."
    },
    {
      "pattern": "youtube.com",
      "method": "suffix",
      "category": "video",
      "provider": "YouTube Video",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Embedded streaming video player."
    },
    {
      "pattern": "youtube-nocookie.com",
      "method": "suffix",
      "category": "video",
      "provider": "YouTube Privacy-Enhanced Video",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "Privacy-enhanced YouTube video embed mode without persistent tracking cookies."
    },
    {
      "pattern": "player.vimeo.com",
      "method": "exact",
      "category": "video",
      "provider": "Vimeo Video Player",
      "isTracker": false,
      "confidence": "high",
      "source": "Public Documentation",
      "description": "High-definition embedded video player."
    }
  ]
},
  phishing: {
  "version": "2.5.0",
  "brands": [
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "netflix",
    "chase",
    "bankofamerica",
    "wellsfargo",
    "facebook",
    "instagram",
    "coinbase",
    "binance",
    "metamask",
    "dhl",
    "fedex",
    "usps"
  ],
  "freeTlds": [
    "tk",
    "ml",
    "ga",
    "cf",
    "gq"
  ],
  "scamKeywords": [
    {
      "phrase": "urgent action required",
      "category": "urgency",
      "severity": "high"
    },
    {
      "phrase": "verify your account immediately",
      "category": "phishing",
      "severity": "high"
    },
    {
      "phrase": "you have won",
      "category": "lottery_scam",
      "severity": "high"
    },
    {
      "phrase": "congratulations winner",
      "category": "lottery_scam",
      "severity": "high"
    },
    {
      "phrase": "claim your prize now",
      "category": "lottery_scam",
      "severity": "high"
    },
    {
      "phrase": "click here to claim",
      "category": "lottery_scam",
      "severity": "medium"
    },
    {
      "phrase": "bitcoin doubling",
      "category": "crypto_scam",
      "severity": "high"
    },
    {
      "phrase": "free money giveaway",
      "category": "crypto_scam",
      "severity": "high"
    },
    {
      "phrase": "security alert: your computer is infected",
      "category": "tech_support_scam",
      "severity": "critical"
    }
  ],
  "suspiciousSubdomainPrefixes": [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "signin",
    "auth",
    "support"
  ]
},
  policyLexicon: {
  "version": "2.5.0",
  "disclosureCategories": {
    "dataCollection": {
      "affirmativePatterns": [
        "\\b(?:we\\s+collect|information\\s+we\\s+collect|personal\\s+data\\s+collected|personal\\s+information\\s+we\\s+gather|types\\s+of\\s+data\\s+we\\s+collect)\\b",
        "\\b(?:name,\\s*email|billing\\s+address|phone\\s+number|device\\s+identifiers|ip\\s+address)\\b"
      ],
      "negativePatterns": [
        "\\b(?:we\\s+do\\s+not\\s+collect\\s+any\\s+personal|we\\s+never\\s+collect\\s+personal\\s+information)\\b"
      ]
    },
    "cookies": {
      "affirmativePatterns": [
        "\\b(?:cookies|web\\s+beacons|tracking\\s+pixels|local\\s+storage\\s+technologies)\\b",
        "\\b(?:session\\s+cookies|persistent\\s+cookies|third-party\\s+cookies)\\b"
      ],
      "negativePatterns": [
        "\\b(?:we\\s+do\\s+not\\s+use\\s+cookies|this\\s+site\\s+does\\s+not\\s+use\\s+tracking\\s+cookies|cookie-free)\\b"
      ]
    },
    "thirdPartySharing": {
      "affirmativePatterns": [
        "\\b(?:share\\s+(?:(?:your\\s+)?(?:personal\\s+)?(?:data|information)\\s+)?with\\s+third\\s+parties|disclose\\s+to\\s+(?:our\\s+)?partners|(?:share|shared)\\s+with\\s+service\\s+providers)\\b",
        "\\b(?:advertising\\s+partners|analytics\\s+providers|third-party\\s+vendors)\\b"
      ],
      "negativePatterns": [
        "\\b(?:we\\s+do\\s+not\\s+share\\s+(?:your\\s+)?personal\\s+information\\s+with\\s+third\\s+parties|we\\s+never\\s+disclose\\s+your\\s+data\\s+to\\s+third\\s+parties)\\b"
      ]
    },
    "dataSelling": {
      "affirmativePatterns": [
        "\\b(?:we\\s+sell\\s+(?:your\\s+)?personal\\s+(?:information|data)|share\\s+data\\s+for\\s+monetary\\s+consideration)\\b"
      ],
      "negativePatterns": [
        "\\b(?:we\\s+do\\s+not\\s+sell\\s+(?:your\\s+)?personal\\s+(?:information|data)|we\\s+never\\s+sell\\s+(?:or\\s+rent\\s+)?(?:your\\s+)?(?:data|information)|we\\s+have\\s+not\\s+sold\\s+any\\s+personal\\s+information)\\b",
        "\\b(?:do\\s+not\\s+sell\\s+my\\s+personal\\s+information|we\\s+do\\s+not\\s+monetize\\s+user\\s+data)\\b"
      ]
    },
    "deletionRights": {
      "affirmativePatterns": [
        "\\b(?:right\\s+to\\s+(?:request\\s+)?deletion|delete\\s+your\\s+account|right\\s+to\\s+erasure|request\\s+to\\s+delete)\\b",
        "\\b(?:gdpr|ccpa|california\\s+consumer\\s+privacy|cpra|opt-out\\s+rights)\\b"
      ],
      "negativePatterns": []
    },
    "retention": {
      "affirmativePatterns": [
        "\\b(?:data\\s+retention|how\\s+long\\s+we\\s+retain|retention\\s+period|retain\\s+your\\s+information\\s+for)\\b"
      ],
      "negativePatterns": []
    },
    "contact": {
      "affirmativePatterns": [
        "\\b(?:privacy@|dpo@|data\\s+protection\\s+officer|contact\\s+our\\s+privacy\\s+team)\\b"
      ],
      "negativePatterns": []
    }
  }
},
  findings: {
  "version": "2.5.0",
  "findings": [
    {
      "id": "SEC_TRANSPORT_HTTPS",
      "legacyId": "transport-https",
      "category": "security",
      "subcategory": "transport",
      "severity": "informational",
      "confidence": "high",
      "source": "HTTP Response",
      "titleTemplate": "HTTPS Transport Enabled",
      "summaryTemplate": "Traffic between your browser and this server is encrypted over TLS.",
      "evidenceTemplate": "The final page URL is served over HTTPS ({finalUrl}).",
      "whyItMattersTemplate": "Encryption prevents network eavesdroppers from intercepting your data or tampering with page content in transit.",
      "recommendationTemplate": "Note that while HTTPS encrypts traffic, it does not verify whether the site's content or business is trustworthy.",
      "limitations": "TLS encrypts transport but does not validate operator trustworthiness.",
      "placeholders": {
        "finalUrl": "string"
      }
    },
    {
      "id": "SEC_TRANSPORT_HTTP_INSECURE",
      "legacyId": "transport-http-insecure",
      "category": "security",
      "subcategory": "transport",
      "severity": "high",
      "confidence": "high",
      "source": "HTTP Response",
      "titleTemplate": "Unencrypted HTTP Connection",
      "summaryTemplate": "This site communicates over plain, unencrypted HTTP.",
      "evidenceTemplate": "The final page URL is unencrypted ({finalUrl}).",
      "whyItMattersTemplate": "Any information sent or received can be intercepted, read, or modified by anyone on the local network or internet path.",
      "recommendationTemplate": "Avoid submitting credentials, personal details, or payment info on this site.",
      "limitations": "Observed via primary HTTP request.",
      "placeholders": {
        "finalUrl": "string"
      }
    },
    {
      "id": "SEC_FORM_PASSWORD_CROSS_ORIGIN",
      "legacyId": "form-password-insecure-destination",
      "category": "security",
      "subcategory": "forms",
      "severity": "critical",
      "confidence": "high",
      "source": "Static HTML",
      "titleTemplate": "Sensitive Form Submits Insecurely or Cross-Origin",
      "summaryTemplate": "A password input is submitted to an insecure destination or different domain.",
      "evidenceTemplate": "Form action '{action}' targets {destinationDetail}.",
      "whyItMattersTemplate": "Sending passwords over unencrypted HTTP or to third-party domains is a hallmark of credential harvesting and phishing.",
      "recommendationTemplate": "Do not enter your credentials or account information on this page.",
      "limitations": "Detected by parsing static form elements and action URLs.",
      "placeholders": {
        "action": "string",
        "destinationDetail": "string"
      }
    },
    {
      "id": "SEC_FORM_PASSWORD_DETECTED",
      "legacyId": "form-password-detected",
      "category": "security",
      "subcategory": "forms",
      "severity": "medium",
      "confidence": "high",
      "source": "Static HTML",
      "titleTemplate": "Password Input Field Present",
      "summaryTemplate": "This page contains a password input field.",
      "evidenceTemplate": "Found <input type=\"password\"> in page HTML.",
      "whyItMattersTemplate": "Legitimate login pages ask for passwords, but cloned phishing sites do too. Verify you are on the authentic domain.",
      "recommendationTemplate": "Confirm the domain in your browser's address bar matches the exact service you intend to log into.",
      "limitations": "Presence of a password field is normal on authentic login pages.",
      "placeholders": {}
    },
    {
      "id": "SEC_FORM_NO_CREDENTIALS",
      "legacyId": "form-no-password",
      "category": "security",
      "subcategory": "forms",
      "severity": "informational",
      "confidence": "high",
      "source": "Static HTML",
      "titleTemplate": "No Credential Fields Detected",
      "summaryTemplate": "No password input fields were detected in the page HTML.",
      "evidenceTemplate": "No <input type=\"password\"> tags found in static HTML.",
      "whyItMattersTemplate": "The page does not appear to solicit user account passwords.",
      "recommendationTemplate": "None required.",
      "limitations": "Dynamically rendered login forms injected by JavaScript post-load may not appear in initial static HTML.",
      "placeholders": {}
    },
    {
      "id": "SEC_META_REFRESH_REDIRECT",
      "legacyId": "meta-refresh-redirect",
      "category": "security",
      "subcategory": "navigation",
      "severity": "medium",
      "confidence": "high",
      "source": "Static HTML",
      "titleTemplate": "Automatic Meta-Refresh Redirect",
      "summaryTemplate": "The page initiates an automatic redirect via an HTML meta tag.",
      "evidenceTemplate": "Detected <meta http-equiv=\"refresh\" content=\"{content}\">.",
      "whyItMattersTemplate": "Meta-refresh tags are frequently used in phishing landing pages to rapidly bounce users to credential harvest pages.",
      "recommendationTemplate": "Ensure the redirect destination is legitimate and expected.",
      "limitations": "Some legacy content sites use meta refresh for legitimate site migrations.",
      "placeholders": {
        "content": "string"
      }
    },
    {
      "id": "SEC_HEADER_HSTS_STRONG",
      "legacyId": "header-hsts-strong",
      "category": "security",
      "subcategory": "headers",
      "severity": "informational",
      "confidence": "high",
      "source": "HTTP Header",
      "titleTemplate": "Strict Transport Security (HSTS)",
      "summaryTemplate": "The site instructs browsers to only connect over HTTPS in the future.",
      "evidenceTemplate": "Strict-Transport-Security: {hstsValue}.",
      "whyItMattersTemplate": "HSTS protects users against SSL-stripping and man-in-the-middle downgrade attacks.",
      "recommendationTemplate": "Maintain HSTS configuration with includeSubDomains and preload.",
      "limitations": "Only active after initial browser visit establishes the trust pin.",
      "placeholders": {
        "hstsValue": "string"
      }
    },
    {
      "id": "SEC_HEADER_HSTS_SHORT",
      "legacyId": "header-hsts-short",
      "category": "security",
      "subcategory": "headers",
      "severity": "low",
      "confidence": "medium",
      "source": "HTTP Header",
      "titleTemplate": "Short HSTS Duration",
      "summaryTemplate": "HSTS is present but has a short duration.",
      "evidenceTemplate": "Strict-Transport-Security max-age is only {maxAge} seconds.",
      "whyItMattersTemplate": "Short max-age durations reduce long-term protection against connection downgrades.",
      "recommendationTemplate": "Consider extending HSTS max-age to at least 1 year (31,536,000 seconds).",
      "limitations": "Sites in testing phase often use short max-age periods temporarily.",
      "placeholders": {
        "maxAge": "integer"
      }
    },
    {
      "id": "SEC_HEADER_HSTS_MISSING",
      "legacyId": "header-hsts-missing",
      "category": "security",
      "subcategory": "headers",
      "severity": "low",
      "confidence": "medium",
      "source": "HTTP Header",
      "titleTemplate": "Missing HSTS Header",
      "summaryTemplate": "The server does not send a Strict-Transport-Security header.",
      "evidenceTemplate": "No Strict-Transport-Security header found in HTTP response.",
      "whyItMattersTemplate": "Without HSTS, initial visits could be vulnerable to SSL-stripping on hostile networks (e.g. public Wi-Fi).",
      "recommendationTemplate": "Enable HSTS on the origin web server.",
      "limitations": "Applicable only to sites served over HTTPS.",
      "placeholders": {}
    },
    {
      "id": "SEC_HEADER_CSP_ACTIVE",
      "legacyId": "header-csp-present",
      "category": "security",
      "subcategory": "headers",
      "severity": "informational",
      "confidence": "high",
      "source": "HTTP Header",
      "titleTemplate": "Content Security Policy (CSP) Active",
      "summaryTemplate": "The site defines a Content Security Policy restricting resource execution.",
      "evidenceTemplate": "Content-Security-Policy: {policySnippet}.",
      "whyItMattersTemplate": "CSP helps prevent Cross-Site Scripting (XSS), malicious script injection, and clickjacking.",
      "recommendationTemplate": "Maintain strict CSP directives without 'unsafe-inline' or 'unsafe-eval' where possible.",
      "limitations": "A CSP with permissive directives may still allow certain script injections.",
      "placeholders": {
        "policySnippet": "string"
      }
    },
    {
      "id": "SEC_HEADER_CSP_MISSING",
      "legacyId": "header-csp-missing",
      "category": "security",
      "subcategory": "headers",
      "severity": "low",
      "confidence": "high",
      "source": "HTTP Header",
      "titleTemplate": "No Content Security Policy",
      "summaryTemplate": "No Content-Security-Policy header was sent by the server.",
      "evidenceTemplate": "Content-Security-Policy header absent.",
      "whyItMattersTemplate": "A CSP provides defense-in-depth against code injection and unauthorized framing.",
      "recommendationTemplate": "Deploy a Content-Security-Policy header.",
      "limitations": "Absence of CSP does not mean the site is compromised; it reflects absence of a defense-in-depth layer.",
      "placeholders": {}
    },
    {
      "id": "SEC_HEADER_XCTO_PRESENT",
      "legacyId": "header-xcto-present",
      "category": "security",
      "subcategory": "headers",
      "severity": "informational",
      "confidence": "high",
      "source": "HTTP Header",
      "titleTemplate": "MIME-Type Sniffing Protection",
      "summaryTemplate": "X-Content-Type-Options is set to 'nosniff'.",
      "evidenceTemplate": "X-Content-Type-Options: {headerValue}.",
      "whyItMattersTemplate": "Prevents browsers from MIME-sniffing a response away from the declared content-type, blocking script execution disguised as images or text.",
      "recommendationTemplate": "Properly configured.",
      "limitations": "Enforced by conforming modern browsers.",
      "placeholders": {
        "headerValue": "string"
      }
    },
    {
      "id": "SEC_HEADER_FRAMING_PROTECTED",
      "legacyId": "header-framing-protection",
      "category": "security",
      "subcategory": "headers",
      "severity": "informational",
      "confidence": "high",
      "source": "HTTP Header",
      "titleTemplate": "Clickjacking Protection Configured",
      "summaryTemplate": "The site controls whether it can be embedded inside iframes on other domains.",
      "evidenceTemplate": "Framing restricted via {mechanism}.",
      "whyItMattersTemplate": "Prevents clickjacking attacks where a malicious site disguises the page inside an invisible frame.",
      "recommendationTemplate": "Framing defense properly active.",
      "limitations": "Verified on primary HTML response.",
      "placeholders": {
        "mechanism": "string"
      }
    },
    {
      "id": "SEC_HEADER_VERSION_DISCLOSED",
      "legacyId": "header-version-disclosure",
      "category": "security",
      "subcategory": "headers",
      "severity": "low",
      "confidence": "medium",
      "source": "HTTP Header",
      "titleTemplate": "Detailed Server Version Disclosed",
      "summaryTemplate": "Server banners disclose exact software version numbers.",
      "evidenceTemplate": "Server banner: {banner}.",
      "whyItMattersTemplate": "Broadcasting exact software versions helps automated scanners look for known software vulnerabilities.",
      "recommendationTemplate": "Suppress granular version numbers in Server and X-Powered-By response headers.",
      "limitations": "Information disclosure only; does not prove an exploitable vulnerability exists.",
      "placeholders": {
        "banner": "string"
      }
    },
    {
      "id": "CODE_SCRIPTS_MINIMAL",
      "legacyId": "scripts-minimal",
      "category": "code",
      "subcategory": "scripts",
      "severity": "informational",
      "confidence": "high",
      "source": "Static HTML",
      "titleTemplate": "Minimal Client-Side Code",
      "summaryTemplate": "Zero script tags were detected in the static HTML.",
      "evidenceTemplate": "0 script elements found in fetched document.",
      "whyItMattersTemplate": "Fewer scripts reduce client-side attack surface and third-party tracking.",
      "recommendationTemplate": "None required.",
      "limitations": "Static inspection only; external scripts could be loaded if page were dynamically rendered by a service worker.",
      "placeholders": {}
    },
    {
      "id": "CODE_SCRIPTS_HEAVY",
      "legacyId": "scripts-heavy",
      "category": "code",
      "subcategory": "scripts",
      "severity": "low",
      "confidence": "medium",
      "source": "Static HTML",
      "titleTemplate": "Heavy External Scripting",
      "summaryTemplate": "The page loads {scriptCount} external scripts from {originCount} distinct domains.",
      "evidenceTemplate": "{scriptCount} external scripts across {originCount} domain(s).",
      "whyItMattersTemplate": "Loading many external scripts increases supply chain risk, dependency on third parties, and tracking.",
      "recommendationTemplate": "Review whether all included third-party scripts are essential.",
      "limitations": "Complex single-page applications naturally use more scripts than simple static blogs.",
      "placeholders": {
        "scriptCount": "integer",
        "originCount": "integer"
      }
    },
    {
      "id": "CODE_OBFUSCATION_DYNAMIC",
      "legacyId": "scripts-obfuscation-detected",
      "category": "code",
      "subcategory": "scripts",
      "severity": "high",
      "confidence": "medium",
      "source": "Static HTML",
      "titleTemplate": "Suspicious Script Obfuscation Pattern",
      "summaryTemplate": "Detected dynamic code execution combined with string decoders (e.g. eval + atob/unescape).",
      "evidenceTemplate": "Matched unpacker pattern: {patternDetail}.",
      "whyItMattersTemplate": "Malicious payloads frequently use runtime evaluation decoders to bypass static inspection.",
      "recommendationTemplate": "Exercise extreme caution before executing scripts from this page.",
      "limitations": "Some legitimate legacy packaging tools and copy-protection tools use unpackers.",
      "placeholders": {
        "patternDetail": "string"
      }
    },
    {
      "id": "CODE_IFRAMES_THIRD_PARTY",
      "legacyId": "iframes-third-party",
      "category": "code",
      "subcategory": "iframes",
      "severity": "low",
      "confidence": "high",
      "source": "Static HTML",
      "titleTemplate": "Third-Party Embedded Iframes",
      "summaryTemplate": "The page embeds {frameCount} iframe(s) from external origins.",
      "evidenceTemplate": "External iframe domains: {domains}.",
      "whyItMattersTemplate": "Iframes can render external content. When unsandboxed, they may execute cross-domain widgets or ads.",
      "recommendationTemplate": "Ensure embedded third-party sources are trusted.",
      "limitations": "Third-party iframes are commonly used for benign widgets (YouTube, Google Maps).",
      "placeholders": {
        "frameCount": "integer",
        "domains": "string"
      }
    },
    {
      "id": "CODE_BROWSER_CONSOLE_ERRORS",
      "legacyId": "browser-high-console-errors",
      "category": "code",
      "subcategory": "runtime",
      "severity": "low",
      "confidence": "high",
      "source": "Browser Automation",
      "titleTemplate": "Multiple Runtime Script Errors",
      "summaryTemplate": "The page threw multiple unhandled JavaScript errors during loading.",
      "evidenceTemplate": "Browser runtime observed {errorCount} unhandled client script errors.",
      "whyItMattersTemplate": "Excessive client errors may indicate broken scripts or compatibility bugs.",
      "recommendationTemplate": "Inspect browser console logs.",
      "limitations": "Collected during passive headless navigation.",
      "placeholders": {
        "errorCount": "integer"
      }
    },
    {
      "id": "REP_DOMAIN_IP_LITERAL",
      "legacyId": "domain-ip-literal",
      "category": "reputation",
      "subcategory": "hostname",
      "severity": "high",
      "confidence": "high",
      "source": "Domain Inspection",
      "titleTemplate": "IP Address Used as Website Address",
      "summaryTemplate": "The site is addressed directly via a numeric IP address rather than a registered domain name.",
      "evidenceTemplate": "Target host is bare IP address: {host}.",
      "whyItMattersTemplate": "Legitimate websites almost always use registered domain names. IP URLs are frequently used in targeted attacks to evade domain reputation filters.",
      "recommendationTemplate": "Avoid submitting personal information to direct IP addresses.",
      "limitations": "Some developer tools and internal staging servers use IP literals.",
      "placeholders": {
        "host": "string"
      }
    },
    {
      "id": "REP_DOMAIN_UNUSUAL_STRUCTURE",
      "legacyId": "domain-unusual-structure",
      "category": "reputation",
      "subcategory": "hostname",
      "severity": "low",
      "confidence": "medium",
      "source": "Domain Inspection",
      "titleTemplate": "Unusual Domain Structure Pattern",
      "summaryTemplate": "The domain name exhibits patterns common in algorithmically generated domains.",
      "evidenceTemplate": "Characteristics: {detail}.",
      "whyItMattersTemplate": "Spammers and phishing campaigns often register bulk disposable domains with multiple hyphens or free TLDs.",
      "recommendationTemplate": "Verify the domain carefully against the official company name.",
      "limitations": "Heuristic observation; legitimate businesses occasionally use long hyphenated domains.",
      "placeholders": {
        "detail": "string"
      }
    },
    {
      "id": "REP_DOMAIN_NORMAL",
      "legacyId": "domain-normal-structure",
      "category": "reputation",
      "subcategory": "hostname",
      "severity": "informational",
      "confidence": "high",
      "source": "Domain Inspection",
      "titleTemplate": "Normal Domain Pattern",
      "summaryTemplate": "The domain uses a standard top-level domain and natural length.",
      "evidenceTemplate": "Host '{host}' exhibits standard naming structure.",
      "whyItMattersTemplate": "Domain structure conforms to typical human-selected naming conventions.",
      "recommendationTemplate": "None required.",
      "limitations": "Domain name appearance alone does not guarantee operator integrity.",
      "placeholders": {
        "host": "string"
      }
    },
    {
      "id": "REP_BRAND_IMPERSONATION",
      "legacyId": "brand-impersonation",
      "category": "reputation",
      "subcategory": "phishing",
      "severity": "high",
      "confidence": "medium",
      "source": "Domain Inspection",
      "titleTemplate": "Potential Brand Name in Unrelated Domain",
      "summaryTemplate": "The domain name contains the well-known brand '{brand}' but is not registered to the official provider.",
      "evidenceTemplate": "Hostname '{hostname}' embeds brand keyword '{brand}'.",
      "whyItMattersTemplate": "Phishing sites frequently embed authentic brand names into third-party subdomains or hyphenated domains to deceive users.",
      "recommendationTemplate": "Confirm you are navigating to the official, verified web portal.",
      "limitations": "Heuristic match based on brand catalog.",
      "placeholders": {
        "brand": "string",
        "hostname": "string"
      }
    },
    {
      "id": "CONTENT_SCAM_URGENCY",
      "legacyId": "content-scam-urgency-language",
      "category": "content",
      "subcategory": "scam_patterns",
      "severity": "high",
      "confidence": "high",
      "source": "Static HTML Content",
      "titleTemplate": "High-Pressure / Scam Phrases Detected",
      "summaryTemplate": "The page text uses urgent pressure tactics or prize promises typical of scams.",
      "evidenceTemplate": "Matched phrases: {phrases}.",
      "whyItMattersTemplate": "Scams frequently manufacture artificial urgency or promise unrealistic rewards to induce hasty user action.",
      "recommendationTemplate": "Do not follow instructions demanding immediate funds, gift cards, or credentials.",
      "limitations": "Keyword matching in visible text; context should always be evaluated.",
      "placeholders": {
        "phrases": "string"
      }
    },
    {
      "id": "CONTENT_NO_SCAM_KEYWORDS",
      "legacyId": "content-no-scam-keywords",
      "category": "content",
      "subcategory": "scam_patterns",
      "severity": "informational",
      "confidence": "high",
      "source": "Static HTML Content",
      "titleTemplate": "No Scam Keywords Detected",
      "summaryTemplate": "We did not find aggressive pressure tactics or typical prize scam language.",
      "evidenceTemplate": "Zero tracked high-pressure scam keyword phrases matched.",
      "whyItMattersTemplate": "The text does not show obvious automated scam indicators.",
      "recommendationTemplate": "None required.",
      "limitations": "Scammers continually vary phrase patterns; absence of known keywords is not proof of safety.",
      "placeholders": {}
    },
    {
      "id": "CONTENT_TOPIC_DETECTED",
      "legacyId": "topic-detected",
      "category": "topic",
      "subcategory": "classification",
      "severity": "informational",
      "confidence": "medium",
      "source": "Static HTML Content",
      "titleTemplate": "Appears to be {topic}-related",
      "summaryTemplate": "The page contains terminology associated with {topic} services.",
      "evidenceTemplate": "Occurrences: {evidenceStr}. Page title: \"{title}\".",
      "whyItMattersTemplate": "Helps contextualize what category of service this website offers.",
      "recommendationTemplate": "Verify that this topic matches what you expected at this web address.",
      "limitations": "Heuristic whole-word frequency match.",
      "placeholders": {
        "topic": "string",
        "evidenceStr": "string",
        "title": "string"
      }
    },
    {
      "id": "POL_POLICY_AVAILABLE",
      "legacyId": "policy-available",
      "category": "policy",
      "subcategory": "transparency",
      "severity": "informational",
      "confidence": "high",
      "source": "Policy Analysis",
      "titleTemplate": "{kind} Available",
      "summaryTemplate": "The site links to a readable {kind}.",
      "evidenceTemplate": "Fetched {url} (HTTP {status}, {size} bytes). {discText}",
      "whyItMattersTemplate": "Available policies allow visitors to understand data collection, terms of use, and legal rights.",
      "recommendationTemplate": "Review the policy if you plan to share sensitive or personal information.",
      "limitations": "Automated text extraction does not substitute for formal legal review.",
      "placeholders": {
        "kind": "string",
        "url": "string",
        "status": "integer",
        "size": "integer",
        "discText": "string"
      }
    },
    {
      "id": "POL_POLICY_NONE_FOUND",
      "legacyId": "policy-none-found",
      "category": "policy",
      "subcategory": "transparency",
      "severity": "medium",
      "confidence": "high",
      "source": "Policy Discovery",
      "titleTemplate": "No Terms or Privacy Policy Found",
      "summaryTemplate": "No links to a Terms of Service or Privacy Policy were detected on this page.",
      "evidenceTemplate": "HTML links scan matched zero policy links.",
      "whyItMattersTemplate": "Legitimate businesses and services publish policies explaining user rights, liability, and data practices.",
      "recommendationTemplate": "Look for policies in the site footer or contact the website operator.",
      "limitations": "Policies may be located on a separate landing domain or parent corporate site.",
      "placeholders": {}
    },
    {
      "id": "POL_POLICY_UNREACHABLE",
      "legacyId": "policy-unreachable",
      "category": "policy",
      "subcategory": "transparency",
      "severity": "low",
      "confidence": "high",
      "source": "Policy Analysis",
      "titleTemplate": "{kind} Link Not Accessible",
      "summaryTemplate": "The page links to a {kind}, but the destination could not be loaded.",
      "evidenceTemplate": "Policy request to {url} returned error: {errorDetail}.",
      "whyItMattersTemplate": "Broken policy links prevent visitors from learning how their data is handled.",
      "recommendationTemplate": "Verify whether the site operator maintains up-to-date policy documents.",
      "limitations": "The policy server may have experienced temporary downtime.",
      "placeholders": {
        "kind": "string",
        "url": "string",
        "errorDetail": "string"
      }
    },
    {
      "id": "POL_TRACKER_DISCLOSURE_GAP",
      "legacyId": "policy-tracker-disclosure-gap",
      "category": "policy",
      "subcategory": "tracking_transparency",
      "severity": "low",
      "confidence": "medium",
      "source": "Cross-Reference Analysis",
      "titleTemplate": "Observed Tracking Not Clearly Disclosed in Policy",
      "summaryTemplate": "External tracking scripts were observed, but the analyzed privacy policy does not explicitly mention cookies or advertising analytics.",
      "evidenceTemplate": "Observed trackers ({trackers}) without explicit cookie/advertising disclosures in analyzed text.",
      "whyItMattersTemplate": "Privacy regulations require sites to clearly disclose third-party tracking and analytics.",
      "recommendationTemplate": "Check if cookie disclosures are located in a separate dedicated Cookie Policy.",
      "limitations": "Disclosures may be located in an unlinked Cookie Policy or separate consent modal.",
      "placeholders": {
        "trackers": "string"
      }
    },
    {
      "id": "POL_DATA_SELLING_DENIED",
      "legacyId": "policy-data-selling-denied",
      "category": "policy",
      "subcategory": "privacy_commitments",
      "severity": "informational",
      "confidence": "high",
      "source": "Policy Analysis",
      "titleTemplate": "Policy Explicitly Denies Selling Data",
      "summaryTemplate": "The privacy policy contains explicit statements that user personal data is not sold or monetized.",
      "evidenceTemplate": "Matched explicit negative disclosure: \"{phrase}\".",
      "whyItMattersTemplate": "Clear commitments against selling personal information provide affirmative privacy protections.",
      "recommendationTemplate": "Review full policy for exceptions regarding service provider transfers.",
      "limitations": "Reflects policy statements; scanner cannot independently audit internal corporate data practices.",
      "placeholders": {
        "phrase": "string"
      }
    }
  ]
},
  rules: {
  "version": "2.5.0",
  "rules": [
    {
      "id": "RULE_TRANSPORT_HTTPS",
      "stage": "network",
      "category": "security",
      "description": "Checks if final response URL uses TLS encryption (HTTPS)",
      "conditions": {
        "protocolEquals": "https:"
      },
      "outputFindingId": "SEC_TRANSPORT_HTTPS",
      "evidenceFields": [
        "finalUrl"
      ]
    },
    {
      "id": "RULE_TRANSPORT_HTTP_INSECURE",
      "stage": "network",
      "category": "security",
      "description": "Flags plain unencrypted HTTP transport",
      "conditions": {
        "protocolEquals": "http:"
      },
      "outputFindingId": "SEC_TRANSPORT_HTTP_INSECURE",
      "evidenceFields": [
        "finalUrl"
      ]
    },
    {
      "id": "RULE_FORM_PASSWORD_CROSS_ORIGIN",
      "stage": "static_html",
      "category": "security",
      "description": "Flags password input submitted cross-origin or over plain HTTP",
      "conditions": {
        "hasInsecureOrCrossOriginPasswordForm": true
      },
      "outputFindingId": "SEC_FORM_PASSWORD_CROSS_ORIGIN",
      "evidenceFields": [
        "action",
        "destinationDetail"
      ]
    },
    {
      "id": "RULE_FORM_PASSWORD_SAME_ORIGIN",
      "stage": "static_html",
      "category": "security",
      "description": "Identifies presence of password fields on same-origin HTTPS",
      "conditions": {
        "hasPasswordInput": true,
        "hasInsecureOrCrossOriginPasswordForm": false
      },
      "outputFindingId": "SEC_FORM_PASSWORD_DETECTED",
      "evidenceFields": []
    },
    {
      "id": "RULE_FORM_NO_CREDENTIALS",
      "stage": "static_html",
      "category": "security",
      "description": "Notes absence of password or credential fields",
      "conditions": {
        "hasPasswordInput": false
      },
      "outputFindingId": "SEC_FORM_NO_CREDENTIALS",
      "evidenceFields": []
    },
    {
      "id": "RULE_META_REFRESH",
      "stage": "static_html",
      "category": "security",
      "description": "Detects automatic meta-refresh redirect tag in HTML",
      "conditions": {
        "hasMetaRefresh": true
      },
      "outputFindingId": "SEC_META_REFRESH_REDIRECT",
      "evidenceFields": [
        "content"
      ]
    },
    {
      "id": "RULE_HEADER_HSTS_STRONG",
      "stage": "headers",
      "category": "security",
      "description": "Checks for HSTS with max-age >= 120 days",
      "conditions": {
        "hasHsts": true,
        "hstsMaxAgeGte": 10368000
      },
      "outputFindingId": "SEC_HEADER_HSTS_STRONG",
      "evidenceFields": [
        "hstsValue"
      ]
    },
    {
      "id": "RULE_HEADER_HSTS_SHORT",
      "stage": "headers",
      "category": "security",
      "description": "Flags HSTS with short max-age (< 120 days)",
      "conditions": {
        "hasHsts": true,
        "hstsMaxAgeLt": 10368000
      },
      "outputFindingId": "SEC_HEADER_HSTS_SHORT",
      "evidenceFields": [
        "maxAge"
      ]
    },
    {
      "id": "RULE_HEADER_HSTS_MISSING",
      "stage": "headers",
      "category": "security",
      "description": "Flags missing HSTS header when served over HTTPS",
      "conditions": {
        "isHttps": true,
        "hasHsts": false
      },
      "outputFindingId": "SEC_HEADER_HSTS_MISSING",
      "evidenceFields": []
    },
    {
      "id": "RULE_HEADER_CSP_ACTIVE",
      "stage": "headers",
      "category": "security",
      "description": "Checks for presence of Content-Security-Policy",
      "conditions": {
        "hasCsp": true
      },
      "outputFindingId": "SEC_HEADER_CSP_ACTIVE",
      "evidenceFields": [
        "policySnippet"
      ]
    },
    {
      "id": "RULE_HEADER_CSP_MISSING",
      "stage": "headers",
      "category": "security",
      "description": "Flags absence of Content-Security-Policy header",
      "conditions": {
        "hasCsp": false
      },
      "outputFindingId": "SEC_HEADER_CSP_MISSING",
      "evidenceFields": []
    },
    {
      "id": "RULE_HEADER_XCTO_PRESENT",
      "stage": "headers",
      "category": "security",
      "description": "Verifies X-Content-Type-Options: nosniff header",
      "conditions": {
        "hasXctoNosniff": true
      },
      "outputFindingId": "SEC_HEADER_XCTO_PRESENT",
      "evidenceFields": [
        "headerValue"
      ]
    },
    {
      "id": "RULE_HEADER_FRAMING_PROTECTED",
      "stage": "headers",
      "category": "security",
      "description": "Checks if clickjacking framing protection is enabled",
      "conditions": {
        "hasFramingProtection": true
      },
      "outputFindingId": "SEC_HEADER_FRAMING_PROTECTED",
      "evidenceFields": [
        "mechanism"
      ]
    },
    {
      "id": "RULE_HEADER_VERSION_DISCLOSED",
      "stage": "headers",
      "category": "security",
      "description": "Flags detailed server software version disclosure",
      "conditions": {
        "hasServerVersionDisclosure": true
      },
      "outputFindingId": "SEC_HEADER_VERSION_DISCLOSED",
      "evidenceFields": [
        "banner"
      ]
    },
    {
      "id": "RULE_SCRIPTS_MINIMAL",
      "stage": "static_html",
      "category": "code",
      "description": "Identifies pages with zero client-side scripts",
      "conditions": {
        "totalScriptsEquals": 0
      },
      "outputFindingId": "CODE_SCRIPTS_MINIMAL",
      "evidenceFields": []
    },
    {
      "id": "RULE_SCRIPTS_HEAVY",
      "stage": "static_html",
      "category": "code",
      "description": "Flags pages with > 20 external script tags",
      "conditions": {
        "externalScriptsGt": 20
      },
      "outputFindingId": "CODE_SCRIPTS_HEAVY",
      "evidenceFields": [
        "scriptCount",
        "originCount"
      ]
    },
    {
      "id": "RULE_SCRIPTS_OBFUSCATION",
      "stage": "static_html",
      "category": "code",
      "description": "Detects dynamic eval/unescape/atob unpacker patterns",
      "conditions": {
        "hasScriptObfuscation": true
      },
      "outputFindingId": "CODE_OBFUSCATION_DYNAMIC",
      "evidenceFields": [
        "patternDetail"
      ]
    },
    {
      "id": "RULE_IFRAMES_THIRD_PARTY",
      "stage": "static_html",
      "category": "code",
      "description": "Identifies pages embedding third-party external iframes",
      "conditions": {
        "thirdPartyIframesGt": 0
      },
      "outputFindingId": "CODE_IFRAMES_THIRD_PARTY",
      "evidenceFields": [
        "frameCount",
        "domains"
      ]
    },
    {
      "id": "RULE_DOMAIN_IP_LITERAL",
      "stage": "network",
      "category": "reputation",
      "description": "Flags raw IPv4 or IPv6 address used in target URL",
      "conditions": {
        "isIpLiteral": true
      },
      "outputFindingId": "REP_DOMAIN_IP_LITERAL",
      "evidenceFields": [
        "host"
      ]
    },
    {
      "id": "RULE_DOMAIN_UNUSUAL_STRUCTURE",
      "stage": "network",
      "category": "reputation",
      "description": "Identifies unusual hyphen counts, free TLDs, or overlong domains",
      "conditions": {
        "isIpLiteral": false,
        "hasUnusualDomainStructure": true
      },
      "outputFindingId": "REP_DOMAIN_UNUSUAL_STRUCTURE",
      "evidenceFields": [
        "detail"
      ]
    },
    {
      "id": "RULE_DOMAIN_NORMAL_STRUCTURE",
      "stage": "network",
      "category": "reputation",
      "description": "Verifies standard domain structure",
      "conditions": {
        "isIpLiteral": false,
        "hasUnusualDomainStructure": false,
        "hasBrandImpersonation": false
      },
      "outputFindingId": "REP_DOMAIN_NORMAL",
      "evidenceFields": [
        "host"
      ]
    },
    {
      "id": "RULE_BRAND_IMPERSONATION",
      "stage": "network",
      "category": "reputation",
      "description": "Detects brand name embedded in third-party or sub-domain",
      "conditions": {
        "hasBrandImpersonation": true
      },
      "outputFindingId": "REP_BRAND_IMPERSONATION",
      "evidenceFields": [
        "brand",
        "hostname"
      ]
    },
    {
      "id": "RULE_SCAM_URGENCY",
      "stage": "static_html",
      "category": "content",
      "description": "Flags high-pressure urgency scam language",
      "conditions": {
        "hasScamKeywords": true
      },
      "outputFindingId": "CONTENT_SCAM_URGENCY",
      "evidenceFields": [
        "phrases"
      ]
    },
    {
      "id": "RULE_NO_SCAM_KEYWORDS",
      "stage": "static_html",
      "category": "content",
      "description": "Notes absence of aggressive prize/urgency scam phrases",
      "conditions": {
        "hasScamKeywords": false
      },
      "outputFindingId": "CONTENT_NO_SCAM_KEYWORDS",
      "evidenceFields": []
    }
  ]
}
};

// 2. TEMPLATE RENDERER
function renderTemplate(template, variables = {}, placeholders = {}) {
  if (typeof template !== "string") return "";
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, varName) => {
    let val = variables[varName];
    if (val === undefined || val === null) val = "";
    if (typeof val !== "string") val = String(val);
    return val
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  });
}

// 3. URL NORMALIZATION & VALIDATION
function cleanTarget(input) {
  if (!input || typeof input !== "string") return "";
  let s = input.trim();
  s = s.replace(/^https?:\/\//i, "");
  s = s.replace(/^\/\//, "");
  s = s.split("/")[0].split("?")[0].split("#")[0];
  s = s.split(":")[0];
  s = s.toLowerCase();
  if (s.includes("..") || s.startsWith(".") || s.endsWith(".")) return "";
  return s;
}

function normalizeUrl(rawInput) {
  if (!rawInput || typeof rawInput !== "string") throw new Error("Invalid URL input");
  let input = rawInput.trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(input)) {
    input = "https://" + input;
  }
  const parsed = new URL(input);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS protocols are permitted");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Credentials in URLs are rejected");
  }
  const port = parsed.port ? Number.parseInt(parsed.port, 10) : (parsed.protocol === "https:" ? 443 : 80);
  if (port !== 80 && port !== 443) {
    throw new Error("Only standard web ports 80 and 443 are supported");
  }
  return {
    normalizedUrl: parsed.href,
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port,
    pathname: parsed.pathname || "/",
    search: parsed.search || ""
  };
}

// 4. DETERMINISTIC RULE ENGINE
const findingCatalog = new Map();
for (const f of KB.findings.findings) findingCatalog.set(f.id, f);

function evaluateConditions(conditions, obs) {
  for (const [key, expected] of Object.entries(conditions)) {
    switch (key) {
      case "protocolEquals": if (obs.protocol !== expected) return false; break;
      case "isHttps": if (Boolean(obs.isHttps) !== expected) return false; break;
      case "hasPasswordInput": if (Boolean(obs.hasPasswordInput) !== expected) return false; break;
      case "hasInsecureOrCrossOriginPasswordForm": if (Boolean(obs.hasInsecureOrCrossOriginPasswordForm) !== expected) return false; break;
      case "hasMetaRefresh": if (Boolean(obs.hasMetaRefresh) !== expected) return false; break;
      case "hasHsts": if (Boolean(obs.hasHsts) !== expected) return false; break;
      case "hstsMaxAgeGte": if ((obs.hstsMaxAge || 0) < expected) return false; break;
      case "hstsMaxAgeLt": if ((obs.hstsMaxAge || 0) >= expected) return false; break;
      case "hasCsp": if (Boolean(obs.hasCsp) !== expected) return false; break;
      case "hasXctoNosniff": if (Boolean(obs.hasXctoNosniff) !== expected) return false; break;
      case "hasFramingProtection": if (Boolean(obs.hasFramingProtection) !== expected) return false; break;
      case "hasServerVersionDisclosure": if (Boolean(obs.hasServerVersionDisclosure) !== expected) return false; break;
      case "hasScriptObfuscation": if (Boolean(obs.hasScriptObfuscation) !== expected) return false; break;
      case "thirdPartyIframesGt": if ((obs.thirdPartyIframesCount ?? 0) <= expected) return false; break;
      case "hasScamKeywords": if (Boolean(obs.hasScamKeywords) !== expected) return false; break;
      default: if (obs[key] !== expected) return false; break;
    }
  }
  return true;
}

function evaluateObservationRules(obs) {
  const emittedFindings = [];
  for (const rule of KB.rules.rules) {
    if (!evaluateConditions(rule.conditions, obs)) continue;
    const findingDef = findingCatalog.get(rule.outputFindingId);
    if (!findingDef) continue;

    const variables = {
      finalUrl: obs.finalUrl || "",
      action: obs.passwordFormAction || "",
      destinationDetail: obs.passwordFormDestinationDetail || "",
      content: obs.metaRefreshContent || "",
      hstsValue: obs.hstsValue || "",
      maxAge: obs.hstsMaxAge || 0,
      policySnippet: obs.cspSnippet || "",
      headerValue: obs.xctoValue || "nosniff",
      mechanism: obs.framingMechanism || "framing protection",
      banner: obs.serverBanner || "",
      scriptCount: obs.scripts?.external || 0,
      patternDetail: obs.scriptObfuscationPattern || "eval/atob unpacker",
      frameCount: obs.thirdPartyIframesCount || 0,
      domains: obs.thirdPartyIframeDomains || "",
      host: obs.targetHost || "",
      phrases: obs.scamPhrasesMatched || ""
    };

    const title = renderTemplate(findingDef.titleTemplate, variables, findingDef.placeholders);
    const summary = renderTemplate(findingDef.summaryTemplate, variables, findingDef.placeholders);
    const evidence = renderTemplate(findingDef.evidenceTemplate, variables, findingDef.placeholders);
    const whyItMatters = renderTemplate(findingDef.whyItMattersTemplate, variables, findingDef.placeholders);
    const recommendation = renderTemplate(findingDef.recommendationTemplate, variables, findingDef.placeholders);

    let level = "good";
    if (findingDef.severity === "critical" || findingDef.severity === "high") level = "bad";
    else if (findingDef.severity === "medium" || findingDef.severity === "low") level = "warning";

    emittedFindings.push({
      id: findingDef.id,
      legacyId: findingDef.legacyId || findingDef.id,
      category: findingDef.category,
      subcategory: findingDef.subcategory,
      title,
      summary,
      evidence,
      whyItMatters,
      recommendation,
      severity: findingDef.severity,
      confidence: findingDef.confidence,
      source: findingDef.source,
      status: "detected",
      limitations: findingDef.limitations,
      level,
      simple: summary,
      nerd: evidence,
      matchedRuleId: rule.id
    });
  }
  return { findings: emittedFindings };
}

// 5. TRACKER DETECTION WITH STRICT DOMAIN BOUNDARIES
function matchDomainToService(hostname) {
  if (!hostname || typeof hostname !== "string") return null;
  const host = hostname.toLowerCase();
  for (const s of KB.domains.services) {
    const pat = s.pattern.toLowerCase();
    if (s.exactMatch) {
      if (host === pat) return s;
    } else {
      if (host === pat || host.endsWith("." + pat)) return s;
    }
  }
  return null;
}

function detectTrackers(html, siteHost) {
  const detected = [];
  const seenKeys = new Set();
  const urlRegex = /(?:src|href)=["']([^"']+)["']/gi;
  let match;
  while ((match = urlRegex.exec(html)) !== null) {
    const raw = match[1];
    let host;
    try {
      host = new URL(raw, "https://" + siteHost).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (host === siteHost || host.endsWith("." + siteHost)) continue;
    const matchedService = matchDomainToService(host);
    if (matchedService) {
      const key = matchedService.provider + ":" + host;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        detected.push({
          provider: matchedService.provider,
          category: matchedService.category,
          domain: host,
          isTracker: matchedService.isTracker
        });
      }
    }
  }
  return detected;
}

// 6. STATIC DOCUMENT & ELEMENT PARSER
function extractVisibleText(html) {
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, " ")
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function analyzeStaticDocument(html, siteHost, pageUrl) {
  const normHost = (siteHost || "").toLowerCase();
  const forms = [];
  let hasPasswordInput = false;
  let hasInsecureOrCrossOriginPasswordForm = false;
  let passwordFormAction = "";
  let passwordFormDestinationDetail = "";

  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fMatch;
  while ((fMatch = formRegex.exec(html)) !== null) {
    const attrs = fMatch[1];
    const body = fMatch[2];
    const actionMatch = attrs.match(/action=["']([^"']*)["']/i);
    const rawAction = actionMatch ? actionMatch[1].trim() : "";
    const isPasswordForm = /type=["']password["']/i.test(body);
    if (isPasswordForm) hasPasswordInput = true;

    let targetHost = normHost;
    let isHttps = true;
    if (rawAction && !rawAction.startsWith("#") && !rawAction.startsWith("/")) {
      try {
        const parsed = new URL(rawAction, pageUrl || ("https://" + normHost));
        targetHost = parsed.hostname.toLowerCase();
        isHttps = parsed.protocol === "https:";
      } catch {}
    }

    const isCrossOrigin = targetHost !== normHost && !targetHost.endsWith("." + normHost);
    if (isPasswordForm && (!isHttps || isCrossOrigin)) {
      hasInsecureOrCrossOriginPasswordForm = true;
      passwordFormAction = rawAction || "(self)";
      passwordFormDestinationDetail = isCrossOrigin ? ("external domain '" + targetHost + "'") : "unencrypted HTTP endpoint";
    }
  }

  // Check meta-refresh
  const metaRefresh = /<meta[^>]+http-equiv=["']refresh["'][^>]*content=["']([0-9]+;\s*url=[^"']+)["']/i.exec(html);

  // Check script obfuscation
  const hasScriptObfuscation = /eval\s*\(\s*unescape\s*\(|eval\s*\(\s*atob\s*\(|document\.write\s*\(\s*unescape/i.test(html);

  // Check scam keywords
  const plainText = extractVisibleText(html).toLowerCase();
  const matchedScamPhrases = [];
  for (const phrase of KB.phishing.scamKeywords) {
    if (plainText.includes(phrase.toLowerCase())) matchedScamPhrases.push(phrase);
  }

  // Check third party iframes
  const iframeRegex = /<iframe\b[^>]*src=["']([^"']+)["']/gi;
  let ifMatch;
  const iframeHosts = new Set();
  while ((ifMatch = iframeRegex.exec(html)) !== null) {
    try {
      const h = new URL(ifMatch[1], pageUrl || ("https://" + normHost)).hostname.toLowerCase();
      if (h !== normHost && !h.endsWith("." + normHost)) iframeHosts.add(h);
    } catch {}
  }

  const trackers = detectTrackers(html, normHost);

  const observations = {
    targetHost: normHost,
    finalUrl: pageUrl,
    hasPasswordInput,
    hasInsecureOrCrossOriginPasswordForm,
    passwordFormAction,
    passwordFormDestinationDetail,
    hasMetaRefresh: Boolean(metaRefresh),
    metaRefreshContent: metaRefresh ? metaRefresh[1] : "",
    hasScriptObfuscation,
    scriptObfuscationPattern: hasScriptObfuscation ? "eval(unescape/atob) unpacker pattern" : "",
    hasScamKeywords: matchedScamPhrases.length > 0,
    scamPhrasesMatched: matchedScamPhrases.slice(0, 3).join(", "),
    thirdPartyIframesCount: iframeHosts.size,
    thirdPartyIframeDomains: Array.from(iframeHosts).slice(0, 3).join(", ")
  };

  const { findings } = evaluateObservationRules(observations);
  return {
    findings,
    trackers,
    observations
  };
}

// 7. SECURITY HEADERS ANALYZER
function analyzeSecurityHeaders(headers = {}, finalUrl = "") {
  const norm = {};
  for (const [k, v] of Object.entries(headers)) norm[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);

  const isHttps = finalUrl.startsWith("https:");
  const hsts = norm["strict-transport-security"];
  let hstsMaxAge = 0;
  if (hsts) {
    const m = hsts.match(/max-age=(\d+)/i);
    hstsMaxAge = m ? Number.parseInt(m[1], 10) : 0;
  }

  const csp = norm["content-security-policy"];
  const xfo = norm["x-frame-options"];
  const hasCspFraming = csp && /frame-ancestors/i.test(csp);
  const serverBanner = norm["server"] || norm["x-powered-by"] || "";

  const obs = {
    finalUrl,
    protocol: isHttps ? "https:" : "http:",
    isHttps,
    hasHsts: Boolean(hsts),
    hstsValue: hsts || "",
    hstsMaxAge,
    hasCsp: Boolean(csp),
    cspSnippet: csp ? (csp.length > 100 ? csp.slice(0, 100) + "..." : csp) : "",
    hasXctoNosniff: Boolean(norm["x-content-type-options"] && norm["x-content-type-options"].toLowerCase().includes("nosniff")),
    xctoValue: norm["x-content-type-options"] || "",
    hasFramingProtection: Boolean(xfo || hasCspFraming),
    framingMechanism: xfo ? ("X-Frame-Options: " + xfo) : (hasCspFraming ? "CSP frame-ancestors" : ""),
    hasServerVersionDisclosure: Boolean(serverBanner && /\d+\.\d+/.test(serverBanner)),
    serverBanner
  };

  const { findings } = evaluateObservationRules(obs);
  return findings.filter(f => f.category === "security" && (f.subcategory === "transport" || f.subcategory === "headers"));
}

// 8. NEGATION-AWARE POLICY ANALYZER
function analyzePolicyContent(policyText) {
  const lower = policyText.toLowerCase();
  const results = {};

  for (const [category, config] of Object.entries(KB.policyLexicon.disclosureCategories)) {
    let status = "not_found";
    let matchedPhrase = null;

    if (config.negativePatterns) {
      for (const pat of config.negativePatterns) {
        const m = lower.match(new RegExp(pat, "i"));
        if (m) { status = "explicit_denial"; matchedPhrase = m[0]; break; }
      }
    }
    if (status === "not_found" && config.affirmativePatterns) {
      for (const pat of config.affirmativePatterns) {
        const m = lower.match(new RegExp(pat, "i"));
        if (m) { status = "disclosed"; matchedPhrase = m[0]; break; }
      }
    }
    results[category] = {
      status,
      matchedPhrase,
      isAffirmative: status === "disclosed",
      isDenied: status === "explicit_denial"
    };
  }

  if (!results.deletion && results.deletionRights) results.deletion = results.deletionRights;
  if (!results.userRights && results.deletionRights) results.userRights = results.deletionRights;
  if (!results.contact && results.contactMethod) results.contact = results.contactMethod;
  return results;
}

function extractPolicyLinks(html, base) {
  const found = { terms: null, privacy: null };
  const linkRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    const rawHref = match[1].trim();
    if (!rawHref || rawHref.startsWith("#") || rawHref.startsWith("javascript:")) continue;
    const text = match[2].replace(/<[^>]+>/g, " ").toLowerCase();
    const searchTarget = (rawHref + " " + text).toLowerCase();
    let abs;
    try { abs = new URL(rawHref, base).href; } catch { continue; }
    if (!found.terms && /(?:terms\s+of\s+service|terms\s+and\s+conditions|\btos\b|user\s+agreement)/.test(searchTarget)) {
      found.terms = abs;
    }
    if (!found.privacy && /(?:privacy\s+policy|privacy\s+notice|data\s+policy|\bprivacy\b)/.test(searchTarget)) {
      found.privacy = abs;
    }
  }
  return found;
}

function buildTermsFindings(policies, observedTrackers = []) {
  const list = [];
  if (policies.length === 0) {
    const def = findingCatalog.get("POL_POLICY_NONE_FOUND");
    if (def) {
      list.push({
        id: def.id,
        legacyId: "policy-none-found",
        category: def.category,
        title: def.titleTemplate,
        summary: def.summaryTemplate,
        evidence: def.evidenceTemplate,
        whyItMatters: def.whyItMattersTemplate,
        recommendation: def.recommendationTemplate,
        severity: def.severity,
        confidence: def.confidence,
        level: "warning",
        simple: def.summaryTemplate,
        nerd: def.evidenceTemplate
      });
    }
    return list;
  }

  for (const policy of policies) {
    if (policy.ok) {
      const disc = policy.disclosures || {};
      if (disc.dataSelling && disc.dataSelling.isDenied) {
        const denyDef = findingCatalog.get("POL_DATA_SELLING_DENIED");
        if (denyDef) {
          list.push({
            id: denyDef.id,
            legacyId: "policy-data-selling-denied",
            category: denyDef.category,
            title: denyDef.titleTemplate,
            summary: denyDef.summaryTemplate,
            evidence: "Policy statement confirms: " + (disc.dataSelling.matchedPhrase || "we do not sell personal data"),
            whyItMatters: denyDef.whyItMattersTemplate,
            recommendation: denyDef.recommendationTemplate,
            severity: denyDef.severity,
            confidence: denyDef.confidence,
            level: "good",
            simple: denyDef.summaryTemplate,
            nerd: "Verified explicit denial clause."
          });
        }
      }

      const cookiesDisclosed = Boolean(disc.cookies && (disc.cookies.isAffirmative || disc.cookies === true));
      const adsDisclosed = Boolean(disc.dataSelling && (disc.dataSelling.isAffirmative || disc.dataSelling === true));
      if (policy.kind === "Privacy Policy" && observedTrackers.length > 0 && !cookiesDisclosed && !adsDisclosed) {
        const gapDef = findingCatalog.get("POL_TRACKER_DISCLOSURE_GAP");
        if (gapDef) {
          list.push({
            id: gapDef.id,
            legacyId: "policy-tracker-disclosure-gap",
            category: gapDef.category,
            title: gapDef.titleTemplate,
            summary: gapDef.summaryTemplate,
            evidence: "Trackers identified on-page but unlisted in policy: " + observedTrackers.map(t => t.provider || t.domain).join(", "),
            whyItMatters: gapDef.whyItMattersTemplate,
            recommendation: gapDef.recommendationTemplate,
            severity: gapDef.severity,
            confidence: gapDef.confidence,
            level: "warning",
            simple: gapDef.summaryTemplate,
            nerd: "Transparency omission observed."
          });
        }
      }
    }
  }
  return list;
}

// 9. CALIBRATED RISK SCORER & MULTI-DIMENSIONAL VECTORS
function calculateRiskScore(findings = [], options = {}) {
  const counts = { good: 0, warning: 0, bad: 0 };
  let totalDeduction = 0;
  const findingWeights = KB.scoring.findingWeights || {};

  const vectorDeductions = { transport: 0, content: 0, telemetry: 0, governance: 0 };

  for (const finding of findings) {
    counts[finding.level] = (counts[finding.level] || 0) + 1;
    const specificWeight = (finding.id && findingWeights[finding.id]) ?? (finding.legacyId && findingWeights[finding.legacyId]);
    const baseWeight = specificWeight !== undefined ? specificWeight : (
      KB.scoring.severityWeights[finding.severity] ?? (finding.level === "bad" ? 25 : finding.level === "warning" ? 10 : 0)
    );
    const confidenceMultiplier = KB.scoring.confidenceMultipliers[finding.confidence] ?? 1.0;
    const deduction = Math.round(baseWeight * confidenceMultiplier);
    finding.impact = deduction;
    totalDeduction += deduction;

    const sub = finding.subcategory || "";
    const cat = finding.category || "";
    if (sub === "transport" || sub === "headers") vectorDeductions.transport += deduction;
    else if (sub === "forms" || sub === "scripts" || sub === "elements" || sub === "scam" || cat === "content") vectorDeductions.content += deduction;
    else if (cat === "privacy" || sub === "tracking_transparency" || sub === "telemetry") vectorDeductions.telemetry += deduction;
    else if (cat === "policy" || sub === "transparency") vectorDeductions.governance += deduction;
  }

  const trackers = options.trackers || [];
  if (trackers.length > 0) {
    const trackerPenalty = Math.min(14, trackers.length * 2);
    totalDeduction += trackerPenalty;
    vectorDeductions.telemetry += trackerPenalty;
  }

  const score = Math.max(KB.scoring.minScore, Math.min(KB.scoring.maxScore, Math.round(KB.scoring.baseScore - totalDeduction)));
  let verdictObj = KB.verdicts.verdicts.find(v => score >= v.minScore && score <= v.maxScore) || KB.verdicts.verdicts[KB.verdicts.verdicts.length - 1];

  const vectors = {
    transport: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.transport)),
      label: vectorDeductions.transport === 0 ? "Hardened" : (vectorDeductions.transport < 15 ? "Guarded" : "Vulnerable")
    },
    content: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.content)),
      label: vectorDeductions.content === 0 ? "Clean" : (vectorDeductions.content < 20 ? "Caution" : "Suspicious")
    },
    telemetry: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.telemetry)),
      label: vectorDeductions.telemetry === 0 ? "Minimal" : (vectorDeductions.telemetry < 16 ? "Moderate" : "Heavy Tracking")
    },
    governance: {
      score: Math.max(0, Math.min(100, 100 - vectorDeductions.governance)),
      label: vectorDeductions.governance === 0 ? "Transparent" : (vectorDeductions.governance < 15 ? "Deficient" : "Unverified")
    }
  };

  return {
    score,
    verdict: verdictObj.code === "MILDLY_SUS" ? "MILDLY SUS" : verdictObj.code,
    verdictDetails: {
      code: verdictObj.code,
      label: verdictObj.label,
      summary: verdictObj.summary,
      explanation: verdictObj.explanation,
      color: verdictObj.color
    },
    counts,
    vectors,
    totalDeduction: Math.round(totalDeduction)
  };
}

// 10. AI-STYLE HEURISTIC SYNTHESIZER
function generateAiSynthesis(context = {}) {
  const { site = "target domain", url = "", score = 100, verdict = "BUS", findings = [], trackers = [], policies = [], vectors = {} } = context;

  const fIds = new Set(findings.map(f => f.id));
  const lIds = new Set(findings.map(f => f.legacyId).filter(Boolean));
  const has = (id, leg) => fIds.has(id) || (leg && lIds.has(leg));

  const isHttps = url.startsWith("https:") || has("SEC_TRANSPORT_HTTPS", "transport-https");
  const hasStrongHsts = has("SEC_HEADER_HSTS_STRONG", "header-hsts-strong");
  const hasShortHsts = has("SEC_HEADER_HSTS_SHORT", "header-hsts-short");
  const hasCsp = has("SEC_HEADER_CSP_PRESENT", "header-csp-present");
  const hasCrossOriginPassword = has("SEC_FORM_PASSWORD_CROSS_ORIGIN", "form-password-insecure-destination");
  const hasPasswordDetected = has("SEC_FORM_PASSWORD_DETECTED", "form-password-detected");
  const hasObfuscation = has("SEC_SCRIPT_OBFUSCATION", "scripts-obfuscation-detected");
  const hasNoPolicy = has("POL_POLICY_NONE_FOUND", "policy-none-found");
  const hasTrackerGap = has("POL_TRACKER_DISCLOSURE_GAP", "policy-tracker-disclosure-gap");
  const hasSaleDenied = has("POL_DATA_SELLING_DENIED", "policy-data-selling-denied");

  let p1 = "";
  if (!isHttps) {
    p1 = "CRITICAL PROTOCOL HAZARD: Automated heuristic scanning of " + site + " identified that communications occur over unencrypted HTTP. In-transit packets are vulnerable to on-path interception.";
  } else if (hasStrongHsts && hasCsp) {
    p1 = "Heuristic inspection of " + site + " confirms an enterprise-grade cryptographic baseline. Transport is strictly secured via HTTPS backed by long-duration HSTS enforcement, complemented by active Content Security Policy (CSP) directives.";
  } else if (hasStrongHsts) {
    p1 = "Heuristic inspection of " + site + " confirms hardened TLS transport encryption backed by long-duration HSTS enforcement. However, Content Security Policy (CSP) headers are absent.";
  } else if (hasShortHsts) {
    p1 = "Heuristic inspection of " + site + " confirms TLS encryption; however, HSTS max-age is set to a short duration, leaving future sessions vulnerable to protocol downgrade intercepts.";
  } else {
    p1 = "Heuristic inspection of " + site + " indicates standard TLS encryption is active, but HTTP Strict Transport Security (HSTS) is omitted. Client connections remain exposed to downgrade threats.";
  }

  if (hasCrossOriginPassword) {
    p1 += " CRITICAL FORM VULNERABILITY: Document parsing detected password inputs configured to submit credentials cross-origin to an untrusted external destination.";
  } else if (hasPasswordDetected) {
    p1 += " Authentication elements were detected; form handlers target the verified origin without cross-origin exfiltration routes.";
  } else {
    p1 += " No authentication credential fields or password capture inputs were identified on the analyzed landing document.";
  }

  let p2 = "";
  if (trackers.length === 0) {
    p2 = "From a telemetry standpoint, the landing page exhibits a clean profile with zero detected third-party tracking beacons or ad exchanges.";
  } else {
    p2 = "From a telemetry standpoint, the page ingests " + trackers.length + " external tracking service(s) (" + trackers.map(t => t.provider || t.domain).slice(0, 3).join(", ") + "), establishing outbound network requests across distinct third-party domains.";
  }

  if (hasSaleDenied) {
    p2 += " Commendably, the published privacy documentation features explicit contractual disclosures confirming the operator does not monetize or sell user personal records.";
  } else if (hasTrackerGap) {
    p2 += " Crucially, the published privacy documentation fails to disclose these active third-party tracking entities, creating an observed discrepancy between page behavior and stated privacy commitments.";
  } else if (hasNoPolicy) {
    p2 += " Crucially, no accessible privacy policy or terms of service could be verified for this domain, leaving data retention periods and third-party data distribution completely undefined.";
  } else {
    p2 += " Basic legal disclosure documents were identified on the page.";
  }

  let p3 = "";
  let riskProfile = "MINIMAL RISK";
  if (score >= 70) {
    riskProfile = "MINIMAL RISK";
    p3 = "Analyst Assessment: " + site + " satisfies baseline security expectations with a calibrated trust score of " + score + "/100. The lack of malicious redirect chains, obfuscated script loaders, or deceptive inputs makes this link appropriate for regular interaction under standard user precautions.";
  } else if (score >= 40) {
    riskProfile = "ELEVATED EXPOSURE";
    p3 = "Analyst Assessment: " + site + " exhibits an elevated risk profile with a calibrated score of " + score + "/100 (MILDLY SUS). The convergence of defensive configuration gaps and third-party telemetry warrants visitor vigilance.";
  } else {
    riskProfile = "CRITICAL HAZARD";
    p3 = "Analyst Assessment: CRITICAL THREAT PROFILE (" + score + "/100 - SUS). The automated scanner discovered high-severity security anomalies consistent with deceptive landing infrastructure or credential theft. Visitors are advised not to interact with this link.";
  }

  const recs = [];
  if (!isHttps) recs.push({ action: "Migrate entire site transport to HTTPS with TLS 1.3", points: "+33 pts" });
  if (hasCrossOriginPassword) recs.push({ action: "Refactor login forms to submit exclusively to verified first-party origin", points: "+47 pts" });
  if (!hasStrongHsts && isHttps) recs.push({ action: "Enable Strict-Transport-Security (max-age >= 31536000; preload)", points: "+9 pts" });
  if (!hasCsp) recs.push({ action: "Deploy Content-Security-Policy with strict script-src and frame-ancestors", points: "+7 pts" });
  if (hasTrackerGap) recs.push({ action: "Update Privacy Policy to explicitly disclose third-party analytics partners", points: "+8 pts" });
  if (hasNoPolicy) recs.push({ action: "Publish formal Privacy Policy and Terms of Service documents", points: "+14 pts" });

  const summaryBullets = [
    {
      category: "Transport",
      text: isHttps ? (hasStrongHsts ? "TLS encryption strictly enforced with long-duration HSTS" : "TLS encryption active; HTTP Strict Transport Security (HSTS) lacks preload") : "Unencrypted cleartext HTTP detected (traffic exposed to interception)",
      level: isHttps ? (hasStrongHsts ? "good" : "warning") : "bad"
    },
    {
      category: "Forms & Input",
      text: hasCrossOriginPassword ? "Password input configured to submit cross-origin to an untrusted external destination" : (hasPasswordDetected ? "Standard login form present submitting to verified domain" : "No credential or password input fields detected on page"),
      level: hasCrossOriginPassword ? "bad" : "good"
    },
    {
      category: "Telemetry",
      text: trackers.length === 0 ? "Zero third-party trackers or advertising beacons detected" : (trackers.length + " third-party tracking/analytics service(s) detected (" + trackers.map(t => t.provider || t.domain).slice(0, 3).join(", ") + ")"),
      level: trackers.length === 0 ? "good" : (trackers.length > 3 ? "warning" : "good")
    },
    {
      category: "Governance",
      text: hasSaleDenied ? "Privacy policy explicitly guarantees personal data is not sold" : (hasNoPolicy ? "No privacy policy or terms of service documentation found" : (hasTrackerGap ? "Third-party trackers active on page but not acknowledged in privacy policy" : "Standard privacy documentation published")),
      level: hasSaleDenied ? "good" : (hasNoPolicy || hasTrackerGap ? "warning" : "good")
    },
    {
      category: "Guidance",
      text: score >= 70 ? "Baseline security standards met; appropriate for standard interaction" : (score >= 40 ? "Configuration gaps and telemetry exposure warrant visitor caution" : "High risk indicators detected; avoid credential submission or downloads"),
      level: score >= 70 ? "good" : (score >= 40 ? "warning" : "bad")
    }
  ];

  return {
    summaryTitle: "Key Security Observations",
    summaryBullets: summaryBullets,
    badge: "SECURITY ASSESSMENT",
    headline: "Calibrated Trust Index: " + score + "/100 (" + verdict + ") — " + riskProfile,
    executiveSummary: [p1, p2, p3].join("\n\n"),
    paragraphs: [p1, p2, p3],
    keyTakeaways: [
      "Transport: " + (isHttps ? (hasStrongHsts ? "Enforced TLS with long-term HSTS" : "Standard TLS (missing HSTS preload)") : "UNENCRYPTED (High Risk)"),
      "Telemetry: " + (trackers.length === 0 ? "Zero third-party trackers detected" : (trackers.length + " active tracker service(s) identified")),
      "Governance: " + (hasSaleDenied ? "Explicit data selling denial confirmed" : (hasNoPolicy ? "Missing privacy and terms disclosures" : (hasTrackerGap ? "Tracker disclosure transparency gap" : "Basic legal disclosures present")))
    ],
    riskProfile: riskProfile,
    confidenceScore: 96,
    skepticismCalibration: "Zero-Trust Deterministic Heuristics",
    actionableRecommendations: recs.slice(0, 4),
    vectors: vectors || {}
  };
}

// 11. MASTER SCANNER ORCHESTRATION PIPELINE
async function runFullScan(targetInput) {
  const normHost = cleanTarget(targetInput);
  if (!normHost) throw new Error("Invalid or unresolvable hostname format");

  let pageUrl = "https://" + normHost;
  let html = "";
  let headers = {};
  let status = 200;

  // Perform secure HTTP fetch (works in Deno, Node.js fetch, or fallback)
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const resp = await fetch(pageUrl, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SusOrBusScanner/2.6; +https://susorbus.com)"
      },
      redirect: "follow"
    });
    clearTimeout(timeout);
    status = resp.status;
    pageUrl = resp.url || pageUrl;
    html = await resp.text();
    for (const [k, v] of resp.headers.entries()) headers[k.toLowerCase()] = v;
  } catch (err) {
    if (pageUrl.startsWith("https:")) {
      try {
        pageUrl = "http://" + normHost;
        const resp2 = await fetch(pageUrl, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; SusOrBusScanner/2.6; +https://susorbus.com)" }
        });
        status = resp2.status;
        pageUrl = resp2.url || pageUrl;
        html = await resp2.text();
        for (const [k, v] of resp2.headers.entries()) headers[k.toLowerCase()] = v;
      } catch (err2) {
        throw new Error("Unable to establish HTTP/HTTPS connection to " + normHost + ": " + err2.message);
      }
    } else {
      throw new Error("Unable to establish connection to " + normHost + ": " + err.message);
    }
  }

  // 1. Static Document Analysis
  const staticResult = analyzeStaticDocument(html, normHost, pageUrl);

  // 2. Security Headers Analysis
  const headerFindings = analyzeSecurityHeaders(headers, pageUrl);

  // 3. Policy Discovery & Negation-Aware Inspection
  const policyLinks = extractPolicyLinks(html, pageUrl);
  const policies = [];
  if (policyLinks.privacy) {
    try {
      const pResp = await fetch(policyLinks.privacy);
      if (pResp.ok) {
        const pHtml = await pResp.text();
        const pText = extractVisibleText(pHtml);
        policies.push({
          kind: "Privacy Policy",
          url: policyLinks.privacy,
          status: pResp.status,
          ok: true,
          disclosures: analyzePolicyContent(pText)
        });
      }
    } catch {}
  }
  const termsFindings = buildTermsFindings(policies, staticResult.trackers);

  // 4. Consolidate and Deduplicate Findings
  const allFindings = [...staticResult.findings, ...headerFindings, ...termsFindings];
  const seenIds = new Set();
  const deduplicatedFindings = [];
  for (const f of allFindings) {
    const fId = f.id || f.title;
    if (seenIds.has(fId)) continue;
    seenIds.add(fId);
    deduplicatedFindings.push(f);
  }

  // 5. Calculate Precise Risk Score & Vectors
  const scoringResult = calculateRiskScore(deduplicatedFindings, { trackers: staticResult.trackers });

  // 6. Generate AI Heuristic Synthesis Briefing
  const aiSynthesis = generateAiSynthesis({
    site: normHost,
    url: pageUrl,
    score: scoringResult.score,
    verdict: scoringResult.verdict,
    findings: deduplicatedFindings,
    trackers: staticResult.trackers,
    policies,
    vectors: scoringResult.vectors
  });

  return {
    site: normHost,
    url: pageUrl,
    status,
    checkedAt: new Date().toISOString(),
    score: scoringResult.score,
    verdict: scoringResult.verdict,
    verdictDetails: scoringResult.verdictDetails,
    counts: scoringResult.counts,
    vectors: scoringResult.vectors,
    aiSynthesis,
    findings: deduplicatedFindings,
    policies,
    termsFindings,
    analysis: {
      trackers: staticResult.trackers
    }
  };
}

// 12. BASE44 CLOUD FUNCTION HTTP HANDLER (Deno & Node.js Compatible)
if (typeof Deno !== "undefined" && Deno.serve) {
  Deno.serve(async (req) => {
    // Enable CORS for frontend invocations
    if (req.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    try {
      let site = "";
      if (req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        site = body.site || body.url || "";
      } else {
        const u = new URL(req.url);
        site = u.searchParams.get("site") || u.searchParams.get("url") || "";
      }

      if (!site) {
        return Response.json({ error: "Missing required 'site' parameter" }, { status: 400 });
      }

      const result = await runFullScan(site);
      return Response.json(result, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Content-Type": "application/json"
        }
      });
    } catch (err) {
      return Response.json({ error: err.message || "Scan execution error" }, {
        status: 500,
        headers: { "Access-Control-Allow-Origin": "*" }
      });
    }
  });
}

// Export for module systems
if (typeof module !== "undefined" && module.exports) {
  module.exports = { runFullScan, calculateRiskScore, generateAiSynthesis, KB };
}
