import { analyze } from '../src/lib/analyze.js';
import { toMarkdown } from '../src/lib/report.js';
import { SAMPLE_INBOUND, SAMPLE_OUTBOUND, SAMPLE_JAVA } from '../src/samples.js';

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; console.log('  ✓', msg); } else { fail++; console.log('  ✗', msg); } };

console.log('\n[a] inbound WhatsApp wire sample');
const a = analyze(SAMPLE_INBOUND);
const req = a.http.messages.find((m) => m.start.kind === 'request');
ok(req && req.start.method === 'POST' && req.start.url === '/WABA/menu', 'wire request start line reassembled (POST /WABA/menu)');
ok(req?.chunked && req.complete, 'chunked body decoded with final 0 chunk');
ok(req?.bodyJson?.entry?.[0]?.changes?.[0]?.value?.messages?.[0]?.text?.body === 'hi', 'wire body JSON parsed, text = hi');
ok(a.http.exchanges.some((x) => x.method === 'POST' && x.status === 200), 'exchange POST → 200 paired');
ok(a.payloads.some((p) => p.value?.request?.context?.session?.id === 'S-55102'), 'EVENT_LOG_REQUEST nested object recovered');
ok(a.payloads.some((p) => p.value?.txnId === 'TX-20261014-0001'), 'escaped \\" JSON recovered');
ok(a.formatCheck.validJsonLines === 0 && a.formatCheck.verdictCode === 'text', 'format verdict: plain text');
ok(a.ids.some((i) => i.value.startsWith('7d3f9e2a')), 'correlation id found');
ok(/WhatsApp message 'hi' from 9230… hit POST \/WABA\/menu/.test(a.story.text), `story: ${a.story.text}`);
ok(a.security.findings.some((f) => f.type.startsWith('Phone')), 'MSISDN flagged');

console.log('\n[b] outbound Infobip NDJSON sample');
const b = analyze(SAMPLE_OUTBOUND);
ok(b.formatCheck.nonEmptyLines === 11 && b.formatCheck.validJsonLines === 10, `10/11 valid JSON lines (got ${b.formatCheck.validJsonLines}/${b.formatCheck.nonEmptyLines})`);
ok(b.formatCheck.verdictCode === 'mixed', 'verdict mixed');
ok(b.formatCheck.lineResults.find((l) => !l.valid)?.error, 'invalid line has JSON.parse error');
const rej = b.issues.find((i) => /REJECTED/i.test(JSON.stringify(i.fields || '')) && /HTTP OK/.test(i.category));
ok(!!rej, 'business rejection behind HTTP 200 detected');
ok(!JSON.stringify(b.issues).includes('HTTP 420') && !b.http.exchanges.some((x) => x.status === 420), 'no false HTTP 420');
ok(b.http.exchanges.some((x) => x.status === 200 && x.method === 'POST'), 'header-line exchange POST → 200');
ok(/JAZZCASH_WHATSAPP_VALIDATE_PIN_FLOW.*200 OK.*REJECTED – Free trial exceeded/.test(b.story.text), `story: ${b.story.text}`);
ok(b.security.findings.some((f) => /Authorization/.test(f.type)), 'Authorization header flagged');
ok(b.security.findings.some((f) => /PIN/.test(f.type) && !f.masked.includes('4821')), 'MPIN flagged & masked');

console.log('\n[c] Java stack trace sample');
const c = analyze(SAMPLE_JAVA);
const exc = c.entries.find((e) => /IllegalStateException/.test(e.raw));
ok(exc && exc.lineEnd - exc.lineStart >= 7, 'stack trace grouped into one entry');
ok(c.issues.some((i) => i.category === 'Exception' && /SocketTimeout/.test(i.explanation)), 'exception with root cause');
ok(c.issues.some((i) => /502/.test(i.title)), 'access log 502 flagged');
ok(c.security.findings.some((f) => /Card/.test(f.type)), 'card number (luhn) flagged');
ok(c.security.findings.some((f) => /Email/.test(f.type)), 'email flagged');
ok(c.entries.some((e) => e.format === 'unknown'), 'unknown line kept');
ok(c.stats.levels.ERROR === 3, `3 ERROR entries (2 app + access 502) (got ${c.stats.levels.ERROR})`);

console.log('\n[d] misc');
const pretty = analyze('{\n  "level": "error",\n  "message": "boom",\n  "success": false\n}\n');
ok(pretty.entries.length === 1 && pretty.formatCheck.verdictCode === 'pretty', 'pretty-printed JSON grouped');
const nd = analyze('{"time":"2026-01-01T00:00:00Z","severity":"INFO","msg":"a"}\n{"time":"2026-01-01T00:00:02Z","severity":"error","msg":"b","result":{"success":false}}');
ok(nd.formatCheck.verdictCode === 'ndjson' && nd.stats.perSecond > 0, 'ndjson verdict + rate');
ok(nd.issues.some((i) => /success is false|Payload/.test(JSON.stringify(i))), 'success:false caught');
const md = toMarkdown(b);
ok(md.includes('# Log Lens report') && md.includes('REJECTED'), 'markdown report');
const big = analyze(SAMPLE_OUTBOUND.split('\n').slice(0, 10).join('\n').concat('\n').repeat(3000));
ok(big.entries.length === 30000, `30k lines analysed in ${big.elapsedMs} ms`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
