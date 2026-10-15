# Log Lens

A rule-based log analyser that runs entirely in the browser. It uses no AI and needs no API keys, and nothing leaves your machine.

## What it does
- **Formats:** NDJSON/JSON, pretty-printed JSON blocks, WSO2/Synapse (`TID: [...] [ts] LEVEL {logger} - msg`), log4j/logback-style text, syslog (RFC 3164/5424) and Apache/Nginx access logs. Lines that match no format are kept as "unknown". Multi-line entries such as stack traces are grouped together.
- **JSON format check:** checks every line, shows the `JSON.parse` error for each failing line, and gives a verdict (fully NDJSON / mixed / pretty-printed / plain text) with the % of valid lines.
- **Message analysis:** finds embedded JSON (including escaped `\"` JSON), `KEY = value` pairs (LogMediator style), HTTP header lines and `http.wire` byte lines. Wire lines are reassembled per channel and direction into full HTTP messages, and chunked bodies are decoded.
- **Cross-entry analysis:** HTTP exchanges, downstream API calls, deduplicated payloads, correlation IDs, statistics and repeated message signatures.
- **Issues:** exceptions (with root cause), ERROR/FATAL/WARN lines, HTTP 4xx/5xx, failure values inside payloads, `success:false`, and the case where the call returns HTTP 200 but the body says the request was rejected.
- **Security/PII:** phone numbers (MSISDN), emails, Luhn-checked card numbers, auth headers, JWTs and PIN/MPIN/password fields. All values are shown masked.
- **"What happened":** a plain-English summary built from templates. Results can be exported as JSON or as a Markdown report.

## Run
```bash
npm install      # if NODE_ENV=production is set: npm install --include=dev
npm run dev      # open the printed URL (http://localhost:5173)
npm run build    # production build into dist/
node tests/run.mjs   # engine tests against the bundled samples
```

`dist/` is a fully static site. You can host it anywhere (any static host, S3, nginx, GitHub Pages) or serve it locally with `npm run preview`. It uses relative asset paths (`base: './'`), so it also works from a sub-folder.

## Layout
- `src/lib/util.js`: shared helpers
- `src/lib/parse.js`: line parsing, entry grouping, JSON format check
- `src/lib/extract.js`: KEY=value, embedded JSON, header and wire lines, HTTP stream and chunked decoding
- `src/lib/analyze.js`: HTTP exchanges, API calls, payloads, IDs, stats, issues, security, story
- `src/lib/report.js`: JSON and Markdown export
- `src/lib/worker.js`: runs the analysis in a Web Worker so the page doesn't freeze
- `src/components/`: UI tabs and the JSON tree view
- `src/samples.js`: sample logs
