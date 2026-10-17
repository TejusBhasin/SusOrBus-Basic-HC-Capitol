const fs = require("fs");
const http = require("http");
const path = require("path");

function analyze(html) {
    const low = html.toLowerCase();
    const findings = [];
    const scamWords = ["urgent", "winner", "congratulations", "verify your account", "bitcoin", "free money", "click here to claim"];
    const hits = scamWords.filter(w => low.includes(w));
    findings.push({ level: "good", text: "Connection is encrypted (HTTPS)" });
    if (low.includes('type="password"')) {
        findings.push({ level: "bad", text: "Password field detected — phishing pages often fake login forms" });
    } else {
        findings.push({ level: "good", text: "No password fields asking for your credentials" });
    }
    if (low.includes("<form")) {
        findings.push({ level: "warning", text: "Contains a form that collects data from visitors" });
    }
    if (hits.length > 0) {
        findings.push({ level: "bad", text: "Scam keywords found: " + hits.join(", ") });
    } else {
        findings.push({ level: "good", text: "No scam keywords detected" });
    }
    if (low.includes("<iframe")) {
        findings.push({ level: "warning", text: "Embeds external content via iframe (can hide malicious pages)" });
    }
    const bad = findings.filter(f => f.level === "bad").length;
    const warn = findings.filter(f => f.level === "warning").length;
    const score = Math.max(0, 100 - bad * 30 - warn * 10);
    const verdict = score >= 70 ? "BUS" : score >= 40 ? "MILDLY SUS" : "SUS";
    return { score, verdict, findings };
}

const server = http.createServer(async (req, res) => {
    const site = req.url.slice(1);

    if (req.url === "/") {
        const htmlPath = path.join(__dirname, "index.html");
        res.end(fs.readFileSync(htmlPath));
        return;
    }

    if (req.url.startsWith("/check")) {
        const target = (new URL(req.url, "http://x").searchParams.get("site") || "").replace(/^https?:\/\//, "");
        res.setHeader("Content-Type", "application/json");
        try {
            const r = await fetch("https://" + target);
            const html = await r.text();
            res.end(JSON.stringify({ site: target, ...analyze(html) }));
        } catch (err) {
            res.end(JSON.stringify({ error: "Could not check " + target + " (" + err.message + ")" }));
        }
        return;
    }

    try {
        const r = await fetch("https://" + site);
        const html = await r.text();
        res.end(html);
    } catch (err) {
        res.end("Could not fetch " + site + " (" + err.message + ")");
    }
});

server.listen(3000, "127.0.0.1", () => {
    console.log("Server successfully running at http://127.0.0.1:3000");
});
