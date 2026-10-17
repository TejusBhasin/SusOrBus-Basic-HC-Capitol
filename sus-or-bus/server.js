const fs = require("fs");
const http = require("http");
const path = require("path");

const SOURCE_LIMIT = 20000; // characters of HTML sent to the frontend

// ---------- helpers ----------

function cleanTarget(raw) {
    const host = (raw || "")
        .trim()
        .replace(/^https?:\/\//i, "") // strip protocol if user pasted a full link
        .replace(/\/.*$/, "")         // keep only the hostname, drop any path
        .toLowerCase();
    if (!/^[a-z0-9.-]+$/.test(host)) return "";
    return host;
}

function isBlockedHost(host) {
    return host === "localhost"
        || host === "0.0.0.0"
        || /^127\./.test(host)
        || /^10\./.test(host)
        || /^192\.168\./.test(host)
        || /^172\.(1[6-9]|2\d|3[01])\./.test(host)
        || host.includes(":")
        || host.includes("@");
}

async function fetchPage(url) {
    const r = await fetch(url, {
        redirect: "follow",
        signal: AbortSignal.timeout(10000),
        headers: {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        }
    });
    const html = await r.text();
    return { r, html };
}

// ---------- analysis ----------

function analyze(html, host, finalUrl) {
    const low = html.toLowerCase();
    const findings = [];

    if (finalUrl.startsWith("https:")) {
        findings.push({ level: "good", category: "security", title: "HTTPS Transport",
            simple: "The connection to this page is encrypted, keeping your information private from snoops.",
            nerd: "The final response URL after any redirects is " + finalUrl + ", served over TLS." });
    } else {
        findings.push({ level: "bad", category: "security", title: "Unencrypted Connection",
            simple: "This page loads over a plain, unencrypted connection. Anything you type could be seen by others.",
            nerd: "The final URL " + finalUrl + " uses HTTP, so traffic travels unencrypted and can be read or modified anywhere along the network path." });
    }

    if (/<input[^>]+type=["']password["']/i.test(html)) {
        findings.push({ level: "bad", category: "security", title: "Password Field Detected",
            simple: "This page asks for a password. Fake login forms are a classic phishing trick, so double-check the address before typing anything.",
            nerd: "An <input type=\"password\"> element was present in the HTML. Phishing pages commonly clone real login forms to harvest credentials." });
    } else {
        findings.push({ level: "good", category: "security", title: "No Credential Fields",
            simple: "This page doesn't ask for a password, so it can't steal one from you here.",
            nerd: "No password input elements were found in the fetched HTML." });
    }

    const scamWords = ["urgent", "winner", "congratulations", "verify your account", "bitcoin", "free money", "click here to claim"];
    const hits = scamWords.filter(w => low.includes(w));
    if (hits.length > 0) {
        findings.push({ level: "bad", category: "content", title: "Scam Language Detected",
            simple: "The page uses phrases commonly found in scams: " + hits.join(", ") + ".",
            nerd: "Case-insensitive substring matches against a keyword list: " + hits.join(", ") + "." });
    } else {
        findings.push({ level: "good", category: "content", title: "No Scam Keywords",
            simple: "We didn't find the usual pressure tactics and scam phrases on this page.",
            nerd: "None of the tracked scam keywords matched the page text." });
    }

    if (low.includes("<form")) {
        findings.push({ level: "warning", category: "content", title: "Form Collects Your Data",
            simple: "This page has a form that collects information from you. Only submit it if you trust the site.",
            nerd: "A <form> element was present, meaning the page can send visitor-entered data to a server." });
    }

    if (low.includes("<iframe")) {
        findings.push({ level: "warning", category: "code", title: "Embedded External Content",
            simple: "This page shows content from another site inside a frame, which can sometimes hide something malicious.",
            nerd: "An <iframe> element was present, embedding a third-party document in the page." });
    }

    const scriptCount = (low.match(/<script[\s>]/g) || []).length;
    if (scriptCount === 0) {
        findings.push({ level: "good", category: "code", title: "Minimal Client-Side Code",
            simple: "There's almost no code running on this page, which means little room for sneaky behavior.",
            nerd: "Zero <script> elements were found in the HTML." });
    } else if (scriptCount > 15) {
        findings.push({ level: "warning", category: "code", title: "Heavy Scripting",
            simple: "This page runs a lot of code. That's not automatically bad, but it gives more room for tracking or sneaky behavior.",
            nerd: scriptCount + " <script> elements were found in the HTML." });
    }

    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const freeTld = /\.(tk|ml|ga|cf|gq)$/.test(host);
    const hyphens = (host.match(/-/g) || []).length;
    if (isIp) {
        findings.push({ level: "bad", category: "reputation", title: "IP Address as URL",
            simple: "This link is a raw IP address instead of a normal domain name, which is a common trick in phishing.",
            nerd: "The host " + host + " is a bare IPv4 address. Legitimate services almost always use domain names." });
    } else if (freeTld || hyphens >= 2 || host.replace(/\./g, "").length > 30) {
        findings.push({ level: "warning", category: "reputation", title: "Unusual Domain Pattern",
            simple: "The web address itself looks odd — the kind of pattern scammers often generate.",
            nerd: "Heuristic match: free-registered TLD (" + freeTld + "), " + hyphens + " hyphens, or an over-long domain name for host " + host + "." });
    } else {
        findings.push({ level: "good", category: "reputation", title: "Normal Domain Pattern",
            simple: "The web address looks like a normal, human-chosen domain name.",
            nerd: "Host " + host + " is not a raw IP, uses no abuse-prone free TLD, and has a reasonable length and hyphen count." });
    }

    return findings;
}

// ---------- terms & privacy ----------

function extractPolicyLinks(html, base) {
    const found = { terms: null, privacy: null };
    const re = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = re.exec(html))) {
        const text = m[2].replace(/<[^>]+>/g, " ").toLowerCase();
        const hay = (m[1] + " " + text).toLowerCase();
        let abs;
        try { abs = new URL(m[1], base).href; } catch { continue; }
        if (!found.terms && /terms|conditions|\btos\b/.test(hay)) found.terms = abs;
        if (!found.privacy && /privacy|data[ -]?policy/.test(hay)) found.privacy = abs;
        if (found.terms && found.privacy) break;
    }
    return found;
}

async function checkPolicy(url) {
    try {
        const { r, html } = await fetchPage(url);
        return { url, ok: r.ok && html.length > 400, status: r.status, size: html.length };
    } catch (err) {
        return { url, ok: false, error: err.message };
    }
}

function buildTermsFindings(policies) {
    if (policies.length === 0) {
        return [{ level: "warning", category: "content", title: "No Terms or Privacy Link Found",
            simple: "We couldn't find links to a Terms of Service or Privacy Policy on this page. Legitimate sites usually show these somewhere.",
            nerd: "No <a> elements whose href or link text matched the terms/privacy heuristics were present in the HTML." }];
    }
    return policies.map(p => p.ok
        ? { level: "good", category: "content", title: p.kind + " Available",
            simple: "The page links to a " + p.kind + " and the link works, so you can read how they handle your data.",
            nerd: "Found and fetched " + p.url + " (HTTP " + p.status + ", " + p.size + " bytes of content)." }
        : { level: "warning", category: "content", title: p.kind + " Link Not Loading",
            simple: "The page links to a " + p.kind + " but we couldn't load it properly, which is odd.",
            nerd: "Request to " + p.url + " failed or returned unusable content (" + (p.error || "HTTP " + p.status) + ")." });
}

// ---------- server ----------

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");

    if (url.pathname === "/") {
        const htmlPath = path.join(__dirname, "index.html");
        res.setHeader("Content-Type", "text/html");
        res.end(fs.readFileSync(htmlPath));
        return;
    }

    if (url.pathname === "/check") {
        res.setHeader("Content-Type", "application/json");
        const target = cleanTarget(url.searchParams.get("site"));
        if (!target || isBlockedHost(target)) {
            res.end(JSON.stringify({ error: "That doesn't look like a checkable website address." }));
            return;
        }
        try {
            const { r, html } = await fetchPage("https://" + target);

            const findings = analyze(html, target, r.url);
            const links = extractPolicyLinks(html, r.url);
            const policies = [];
            if (links.terms) policies.push({ kind: "Terms of Service", ...(await checkPolicy(links.terms)) });
            if (links.privacy) policies.push({ kind: "Privacy Policy", ...(await checkPolicy(links.privacy)) });
            const termsFindings = buildTermsFindings(policies);

            const counts = { good: 0, warning: 0, bad: 0 };
            for (const f of findings.concat(termsFindings)) counts[f.level]++;
            const score = Math.max(0, 100 - counts.bad * 30 - counts.warning * 10);
            const verdict = score >= 70 ? "BUS" : score >= 40 ? "MILDLY SUS" : "SUS";

            res.end(JSON.stringify({
                site: target,
                url: r.url,
                status: r.status,
                checkedAt: new Date().toISOString(),
                score,
                verdict,
                counts,
                findings,
                policies,
                termsFindings,
                source: html.slice(0, SOURCE_LIMIT)
            }));
        } catch (err) {
            res.end(JSON.stringify({ error: "Could not check " + target + " (" + err.message + ")" }));
        }
        return;
    }

    if (url.pathname === "/preview") {
        const target = cleanTarget(url.searchParams.get("site"));
        if (!target || isBlockedHost(target)) {
            res.statusCode = 400;
            res.end("Blocked or invalid host");
            return;
        }
        try {
            const { html } = await fetchPage("https://" + target);
            res.setHeader("Content-Type", "text/html; charset=utf-8");
            res.end(html);
        } catch (err) {
            res.end("Preview failed: " + err.message);
        }
        return;
    }

    res.statusCode = 404;
    res.end("Not found");
});

server.listen(3000, "127.0.0.1", () => {
    console.log("Server successfully running at http://127.0.0.1:3000");
});
