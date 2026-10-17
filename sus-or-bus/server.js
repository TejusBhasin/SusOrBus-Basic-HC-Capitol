
const fs = require("fs");
const http = require("http");
const path = require("path");

// 1. Add this built-in module
const server = http.createServer(async (req, res) => {
    const site = req.url.slice(1);

    if (req.url === "/") {
        // 2. Use path.join and __dirname to target the file accurately
        const htmlPath = path.join(__dirname, "index.html");

        res.end(fs.readFileSync(htmlPath));
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
