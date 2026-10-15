// Cross-entry analysis: HTTP exchanges, API calls, payloads, IDs, stats, issues, security, story.
import { parseText } from './parse.js';
import { extractEntry, parseHttpStream, RE_START_REQ, RE_START_RES } from './extract.js';
import {
  tryJSON, walk, preview, normalizeSig, humanize, shortComp, maskValue, luhn, countBy, canonical, fmtDuration, LEVELS,
} from './util.js';

const FAIL_WORDS = /\b(reject\w*|fail\w*|error\w*|denied|deny|invalid\w*|exceed\w*|expired?|timeout|timed[ _-]?out|unauthori[sz]ed|forbidden|declined?|insufficient|blocked|refused|not[ _]found|unavailable|suspended|locked|aborted|cancell?ed|violation|mismatch|unsupported|throttl\w*|limit[ _]reached|disabled)\b/i;
const FAIL_WORDS_SPLIT = /(reject|fail|error|denied|invalid|exceed|expired|timeout|unauthori[sz]ed|forbidden|declin|insufficient|blocked|refused|notfound|unavailable|suspended|locked|aborted|throttl)/i;
const STATUS_KEYS = /^(status|state|result|outcome|error|errors|code|errorcode|error_code|reason|description|errordescription|error_description|statusdescription|statusmessage|message|resultcode|responsecode|responsedescription|groupname|name|fault|faultstring|errormessage|detail|title)$/i;
const OK_VALUES = /^(ok|success|successful|succeeded|accepted|delivered|pending|sent|approved|completed|true|0|00|000|200|201|202|204|none|null|no error|n\/a)$/i;
const ID_KEYS = /^(x-)?(correlation[-_]?id|request[-_]?id|req[-_]?id|transaction[-_]?id|txn[-_]?id|trace[-_]?id|traceid|span[-_]?id|message[-_]?id|messageid|activityid|activity[-_]?id|session[-_]?id|conversation[-_]?id|bulk[-_]?id|bulkid|reference[-_]?id|ref[-_]?id|order[-_]?id|wamid|activity_id|x-b3-traceid)$/i;
const SECRET_KEYS = /^(pin|mpin|m_pin|otp|password|passwd|pwd|pass|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|token|authorization|auth|cvv|cvc|private[_-]?key|session[_-]?token|x-api-key)$/i;
const PHONE_KEYS = /(msisdn|phone|mobile|from|to|wa_id|cell|contact|destination|sender|recipient)/i;

export function analyze(text, opts = {}) {
  const t0 = Date.now();
  const { entries, formatCheck } = parseText(text, opts);
  for (const e of entries) e.ex = extractEntry(e);

  const http = buildHttp(entries);
  const apiCalls = buildApiCalls(entries, http);
  const payloads = buildPayloads(entries, http);
  const ids = buildIds(entries, payloads);
  const stats = buildStats(entries);
  const issues = buildIssues(entries, http, apiCalls, payloads);
  const security = buildSecurity(entries, http);
  const story = buildStory({ entries, http, apiCalls, payloads, issues, stats, formatCheck, ids });

  return {
    generatedAt: new Date().toISOString(),
    elapsedMs: Date.now() - t0,
    formatCheck, entries, stats, http, apiCalls, payloads, ids, issues, security, story,
  };
}

// ───────────────────────── HTTP ─────────────────────────
function buildHttp(entries) {
  const streams = new Map(); // key channel|dir -> { buf, entries, firstTs, lastTs }
  const hdrMsgs = new Map(); // key channel|dir -> current message
  const headerMessages = [];
  for (const e of entries) {
    const w = e.ex.wire;
    if (w) {
      const k = `${w.channel}|${w.dir}`;
      let s = streams.get(k);
      if (!s) { s = { channel: w.channel, dir: w.dir, buf: '', entryIds: [], firstTs: e.tsMs, lastTs: e.tsMs, offsets: [] }; streams.set(k, s); }
      s.offsets.push({ off: s.buf.length, id: e.id, ts: e.tsMs });
      s.buf += w.data; s.entryIds.push(e.id); s.lastTs = e.tsMs ?? s.lastTs;
      continue;
    }
    const h = e.ex.header;
    if (h) {
      const k = `${h.channel}|${h.dir}`;
      if (h.start) {
        const m = { channel: h.channel, dir: h.dir, start: { kind: h.start.method ? 'request' : 'response', ...h.start }, headers: [], entryIds: [e.id], ts: e.tsMs, source: 'headers' };
        hdrMsgs.set(k, m); headerMessages.push(m);
      } else {
        let m = hdrMsgs.get(k);
        if (!m) { m = { channel: h.channel, dir: h.dir, start: {}, headers: [], entryIds: [], ts: e.tsMs, source: 'headers' }; hdrMsgs.set(k, m); headerMessages.push(m); }
        m.headers.push({ name: h.name, value: h.value }); m.entryIds.push(e.id);
      }
    }
  }

  const messages = [];
  for (const s of streams.values()) {
    for (const m of parseHttpStream(s.buf)) {
      const at = [...s.offsets].reverse().find((o) => o.off <= (m.offset ?? 0)) || s.offsets[0];
      const ids = s.offsets.filter((o) => o.off >= (at?.off ?? 0)).map((o) => o.id);
      messages.push({ ...m, channel: s.channel, dir: s.dir, ts: at?.ts ?? null, entryIds: ids.length ? ids : s.entryIds, source: 'wire' });
    }
  }
  // header-only messages are useful only if no wire message covers that channel
  const wireChannels = new Set(messages.map((m) => m.channel));
  for (const m of headerMessages) if (!wireChannels.has(m.channel) && (m.start.kind || m.headers.length)) messages.push({ ...m, body: '', bodyJson: undefined });

  // exchanges: pair request & response on same channel. Direction semantics differ by side:
  // Listener (server): >> = request in, << = response out. Outgoing (client): >> = request out, << = response in.
  messages.sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0));
  const exchanges = [];
  const open = new Map();
  for (const m of messages) {
    const side = /listener|incoming/i.test(m.channel) ? 'inbound' : /outgoing|sender/i.test(m.channel) ? 'outbound' : 'unknown';
    if (m.start.kind === 'request') {
      const x = { channel: m.channel, side, method: m.start.method, url: m.start.url, host: hdr(m, 'host'), request: m, response: null, status: null, startTs: m.ts, endTs: null, source: m.source };
      exchanges.push(x); open.set(m.channel, x);
    } else if (m.start.kind === 'response') {
      let x = open.get(m.channel);
      if (!x || x.response) { x = { channel: m.channel, side, method: null, url: null, host: null, request: null, response: null, startTs: null, source: m.source }; exchanges.push(x); }
      x.response = m; x.status = m.start.status; x.reason = m.start.reason; x.endTs = m.ts;
      open.delete(m.channel);
    } else if (m.body) {
      exchanges.push({ channel: m.channel, side, method: null, url: null, request: m.dir === '>>' ? m : null, response: m.dir === '<<' ? m : null, status: null, startTs: m.ts, source: m.source, partial: true });
    }
  }
  // access logs and structured fields with method/status
  for (const e of entries) {
    if (e.access) {
      exchanges.push({ channel: e.access.client, side: 'inbound', method: e.access.method, url: e.access.url, status: e.access.status, startTs: e.tsMs, endTs: null, request: null, response: null, source: 'access-log', entryIds: [e.id], durationMs: e.access.responseTime && !Number.isNaN(+e.access.responseTime) ? +e.access.responseTime * (String(e.access.responseTime).includes('.') ? 1000 : 1) : null });
    } else if (e.fields && typeof e.fields === 'object') {
      const f = flat(e.fields);
      const st = num(f.status ?? f.statusCode ?? f.status_code ?? f['http.status_code'] ?? f['http.response.status_code'] ?? f.response_status);
      const method = f.method ?? f['http.method'] ?? f['http.request.method'] ?? f.request_method;
      const url = f.url ?? f.path ?? f['http.url'] ?? f['url.path'] ?? f.uri ?? f.request_uri ?? f.endpoint;
      if (st && st >= 100 && st < 600 && (method || url)) {
        const d = num(f.duration ?? f.durationMs ?? f.duration_ms ?? f.latency ?? f.elapsed ?? f.response_time ?? f.responseTime);
        exchanges.push({ channel: e.component || 'json', side: 'unknown', method: method || null, url: url || null, status: st, startTs: e.tsMs, durationMs: d ?? null, source: 'json-fields', entryIds: [e.id] });
      }
    }
  }
  for (const x of exchanges) {
    if (x.durationMs == null && x.startTs != null && x.endTs != null) x.durationMs = x.endTs - x.startTs;
    x.entryIds = x.entryIds || [...(x.request?.entryIds || []), ...(x.response?.entryIds || [])];
    x.requestBody = x.request?.bodyJson ?? (x.request?.body || null);
    x.responseBody = x.response?.bodyJson ?? (x.response?.body || null);
  }
  return { messages, exchanges, streams: [...streams.values()].map((s) => ({ channel: s.channel, dir: s.dir, bytes: s.buf.length, lines: s.entryIds.length })) };
}

function hdr(m, name) { return m?.headers?.find((h) => h.name.toLowerCase() === name)?.value ?? null; }
function num(v) { const n = typeof v === 'number' ? v : typeof v === 'string' && /^\d+(\.\d+)?$/.test(v) ? +v : null; return n; }
function flat(obj, pre = '', out = {}, d = 0) {
  if (d > 4 || !obj || typeof obj !== 'object') return out;
  for (const [k, v] of Object.entries(obj)) {
    const p = pre ? `${pre}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flat(v, p, out, d + 1);
    else { out[p] = v; if (!(k in out)) out[k] = v; }
  }
  return out;
}

// ───────────────────────── API calls (LogMediator style) ─────────────────────────
function kvMap(e) {
  const m = {};
  for (const p of e.ex.kv || []) m[p.key.toUpperCase()] = p;
  return m;
}
function buildApiCalls(entries, http) {
  const calls = [];
  for (const e of entries) {
    const kv = kvMap(e);
    const name = kv.API_NAME || kv.APINAME || kv.SERVICE_NAME || kv.API || kv.OPERATION || kv.FLOW_NAME || kv.SEQUENCE || kv.PROXY_NAME;
    const url = kv.URL || kv.ENDPOINT || kv.API_URL || kv.REQUEST_URL || kv.TARGET_URL || kv.URI || kv.ENDPOINT_URL;
    const resp = kv.RESPONSE_BODY || kv.RESPONSE || kv.RESPONSE_PAYLOAD || kv.RES_BODY;
    const req = kv.REQUEST_BODY || kv.REQUEST || kv.REQUEST_PAYLOAD || kv.REQ_BODY || kv.PAYLOAD;
    const st = kv.HTTP_STATUS || kv.HTTP_SC || kv.STATUS_CODE || kv.RESPONSE_CODE || kv.HTTP_STATUS_CODE;
    if (!name && !url && !resp) continue;
    calls.push({
      entryId: e.id, ts: e.tsMs, apiName: name?.value || null, url: url?.value || null,
      method: (kv.METHOD || kv.HTTP_METHOD)?.value || null,
      httpStatus: st ? num(st.value) : null,
      requestBody: req ? (req.json ?? req.value) : null,
      responseBody: resp ? (resp.json ?? resp.value) : null,
      event: (kv.EVENT || kv.EVENT_NAME || kv.LOG_TYPE || kv.TYPE)?.value || null,
      source: 'log-mediator',
    });
  }
  // outbound wire exchanges are API calls too
  for (const x of http.exchanges) {
    if (x.side !== 'outbound') continue;
    calls.push({ entryId: x.entryIds[0], ts: x.startTs, apiName: null, url: x.host && x.url && !/^https?:/.test(x.url) ? `https://${x.host}${x.url}` : x.url, method: x.method, httpStatus: x.status, requestBody: x.requestBody, responseBody: x.responseBody, source: 'wire', durationMs: x.durationMs });
  }
  // merge wire-only calls into a named call with same URL/body
  for (const c of calls) {
    if (c.source !== 'wire') continue;
    const twin = calls.find((o) => o.source === 'log-mediator' && ((o.url && c.url && sameUrl(o.url, c.url)) || (o.responseBody && c.responseBody && canonical(o.responseBody) === canonical(c.responseBody))));
    if (twin) { twin.httpStatus = twin.httpStatus ?? c.httpStatus; twin.method = twin.method || c.method; twin.durationMs = c.durationMs; twin.responseBody = twin.responseBody ?? c.responseBody; c.merged = true; }
  }
  // merge LogMediator lines for the same API (request line + response line)
  for (let i = 0; i < calls.length; i++) {
    const c = calls[i];
    if (c.merged || c.source !== 'log-mediator' || !c.apiName) continue;
    const later = calls.slice(i + 1).find((o) => !o.merged && o.source === 'log-mediator' && o.apiName === c.apiName && !(c.responseBody && o.responseBody));
    if (later && !c.responseBody) {
      for (const k of ['url', 'method', 'httpStatus', 'requestBody', 'responseBody', 'durationMs', 'event']) if (later[k] == null) later[k] = c[k];
      later.entryId = later.entryId ?? c.entryId; later.ts = c.ts ?? later.ts; c.merged = true;
    }
  }
  const out = calls.filter((c) => !c.merged);
  for (const c of out) { c.outcome = judge(c.responseBody, c.httpStatus); c.vendor = vendorOf(c.url, c.apiName); }
  return out;
}
function sameUrl(a, b) {
  const p = (u) => String(u).replace(/^https?:\/\/[^/]+/, '').split('?')[0];
  return p(a) === p(b) || String(a).includes(p(b)) || String(b).includes(p(a));
}
function vendorOf(url, name) {
  const s = `${url || ''} ${name || ''}`.toLowerCase();
  for (const [k, v] of [['infobip', 'Infobip'], ['twilio', 'Twilio'], ['graph.facebook', 'Meta WhatsApp Cloud API'], ['whatsapp', 'WhatsApp'], ['stripe', 'Stripe'], ['paypal', 'PayPal'], ['amazonaws', 'AWS'], ['googleapis', 'Google'], ['sendgrid', 'SendGrid'], ['jazzcash', 'JazzCash']]) if (s.includes(k)) return v;
  try { return url && /^https?:/.test(url) ? new URL(url).hostname : null; } catch { return null; }
}

/** Decide whether a payload means failure. Returns { failed, reasons:[{path,value}], status } */
export function judge(body, httpStatus) {
  const reasons = [];
  let obj = body;
  if (typeof obj === 'string') obj = tryJSON(obj) ?? obj;
  if (obj && typeof obj === 'object') {
    walk(obj, (k, v, path) => {
      if (v == null || typeof v === 'object') return;
      const key = String(k).replace(/[^a-z_]/gi, '');
      if (/^success(ful)?$|^ok$/i.test(key) && (v === false || v === 'false')) reasons.push({ path, value: v, why: 'success is false' });
      else if (/^(haserrors?|iserror|failed)$/i.test(key) && (v === true || v === 'true')) reasons.push({ path, value: v, why: `${k} is true` });
      else if (STATUS_KEYS.test(key) && typeof v === 'string' && !OK_VALUES.test(v.trim()) && (FAIL_WORDS.test(v) || FAIL_WORDS_SPLIT.test(v.replace(/[_\s-]/g, '')))) reasons.push({ path, value: v });
      else if (/^(error|errors|fault|errormessage|error_message|errordescription|error_description)$/i.test(key) && typeof v === 'string' && v.trim() && !OK_VALUES.test(v.trim())) reasons.push({ path, value: v });
    });
  } else if (typeof obj === 'string' && obj.length < 400 && FAIL_WORDS.test(obj)) reasons.push({ path: '(body)', value: obj });
  const uniq = [];
  const seen = new Set();
  for (const r of reasons) { const k = `${r.path}=${r.value}`; if (!seen.has(k)) { seen.add(k); uniq.push(r); } }
  const httpFail = httpStatus != null && httpStatus >= 400;
  return { failed: httpFail || uniq.length > 0, httpFail, businessFail: uniq.length > 0, reasons: uniq.slice(0, 8), description: describeReasons(uniq) };
}
function describeReasons(rs) {
  if (!rs.length) return null;
  const pref = rs.find((r) => /name$|^status$|groupname/i.test(r.path.split('.').pop())) || rs[0];
  const desc = rs.find((r) => /description|message|reason|detail/i.test(r.path.split('.').pop()) && r !== pref);
  const a = String(pref.value);
  return desc ? `${a} – ${desc.value}` : a;
}

// ───────────────────────── Payloads ─────────────────────────
function buildPayloads(entries, http) {
  const map = new Map();
  const add = (value, source, entryId, label) => {
    if (value == null || typeof value !== 'object') return;
    const k = canonical(value);
    if (k.length < 3) return;
    const ex = map.get(k);
    if (ex) { ex.count++; if (!ex.entryIds.includes(entryId)) ex.entryIds.push(entryId); return; }
    map.set(k, { id: map.size, value, source, label, entryIds: [entryId], count: 1, size: k.length });
  };
  for (const e of entries) {
    for (const p of e.ex.kv || []) if (p.json !== undefined) add(p.json, 'key=value', e.id, p.key);
    for (const j of e.ex.json || []) add(j, 'embedded JSON', e.id, e.component ? shortComp(e.component) : 'message');
  }
  for (const m of http.messages) {
    if (m.bodyJson !== undefined) add(m.bodyJson, 'HTTP body (wire)', m.entryIds[0], `${m.start.kind === 'request' ? `${m.start.method} ${m.start.url}` : `HTTP ${m.start.status ?? ''}`} @ ${m.channel}`);
  }
  const out = [...map.values()];
  for (const p of out) p.outcome = judge(p.value, null);
  return out;
}

// ───────────────────────── IDs ─────────────────────────
function buildIds(entries, payloads) {
  const m = new Map();
  const add = (key, val, id) => {
    if (val == null || typeof val === 'object') return;
    const v = String(val);
    if (v.length < 4 || v.length > 120) return;
    const k = v;
    let r = m.get(k);
    if (!r) { r = { value: v, keys: new Set(), entryIds: new Set() }; m.set(k, r); }
    r.keys.add(key); r.entryIds.add(id);
  };
  for (const e of entries) {
    if (e.fields) walk(e.fields, (k, v) => { if (ID_KEYS.test(k)) add(k, v, e.id); });
    for (const p of e.ex.kv || []) {
      if (ID_KEYS.test(p.key)) add(p.key, p.value, e.id);
      if (p.json) walk(p.json, (k, v) => { if (ID_KEYS.test(k)) add(k, v, e.id); });
    }
    for (const j of e.ex.json || []) walk(j, (k, v) => { if (ID_KEYS.test(k)) add(k, v, e.id); });
    const h = e.ex.header;
    if (h?.name && ID_KEYS.test(h.name)) add(h.name, h.value, e.id);
    const tm = e.raw.match(/\b(?:correlation[_-]?id|request[_-]?id|trace[_-]?id|txn[_-]?id)\s*[:=]\s*"?([\w\-.:]{4,})/i);
    if (tm) add('inline', tm[1], e.id);
  }
  void payloads;
  // find other entries that mention the id value anywhere
  const list = [...m.values()];
  if (list.length && list.length < 300) {
    for (const r of list) for (const e of entries) if (!r.entryIds.has(e.id) && e.raw.includes(r.value)) r.entryIds.add(e.id);
  }
  return list.map((r) => ({ value: r.value, keys: [...r.keys], entryIds: [...r.entryIds].sort((a, b) => a - b), links: r.entryIds.size }))
    .sort((a, b) => b.links - a.links);
}

// ───────────────────────── Stats ─────────────────────────
function buildStats(entries) {
  const times = entries.map((e) => e.tsMs).filter((x) => x != null);
  const min = times.length ? Math.min(...times) : null;
  const max = times.length ? Math.max(...times) : null;
  const spanMs = min != null ? max - min : null;
  const levels = Object.fromEntries([...LEVELS, 'UNKNOWN'].map((l) => [l, 0]));
  for (const e of entries) levels[e.level] = (levels[e.level] || 0) + 1;
  const sigs = countBy(entries.filter((e) => !e.ex.wire), (e) => normalizeSig(e.message.split('\n')[0] || e.raw.split('\n')[0]));
  const sigExample = new Map();
  for (const e of entries) { const s = normalizeSig(e.message.split('\n')[0] || e.raw.split('\n')[0]); if (!sigExample.has(s)) sigExample.set(s, e); }
  return {
    entries: entries.length, levels,
    components: countBy(entries, (e) => e.component || null).slice(0, 50),
    threads: countBy(entries, (e) => e.thread || null).slice(0, 30),
    formats: countBy(entries, (e) => e.format),
    timeRange: { start: min, end: max, spanMs, spanText: fmtDuration(spanMs) },
    perSecond: spanMs ? +(entries.length / Math.max(spanMs / 1000, 0.001)).toFixed(2) : null,
    timestamped: times.length,
    topSignatures: sigs.filter(([, n]) => n > 1).slice(0, 15).map(([sig, count]) => ({ sig, count, example: preview(sigExample.get(sig)?.message || '', 200), level: sigExample.get(sig)?.level })),
  };
}

// ───────────────────────── Issues ─────────────────────────
function buildIssues(entries, http, apiCalls, payloads) {
  const issues = new Map();
  const add = (key, o, entry) => {
    let i = issues.get(key);
    if (!i) { i = { key, ...o, count: 0, evidence: [], entryIds: [] }; issues.set(key, i); }
    i.count++;
    if (entry) {
      if (!i.entryIds.includes(entry.id)) i.entryIds.push(entry.id);
      if (i.evidence.length < 5) i.evidence.push({ line: entry.lineStart, text: preview(entry.raw, 400) });
    }
  };
  const byId = (id) => entries[id];

  for (const e of entries) {
    const first = e.message.split('\n')[0];
    const exm = (e.raw.match(/\b((?:[a-z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable|Fault))\b(?::\s*([^\n]{0,200}))?/) || e.raw.match(/\b([A-Z][\w]*(?:Exception|Error))\b(?::\s*([^\n]{0,200}))?/));
    const hasStack = /\n\s+at\s+[\w$.<>]+\(/.test(e.raw) || /Traceback \(most recent call last\)/.test(e.raw);
    if (exm && (hasStack || e.level === 'ERROR' || e.level === 'FATAL' || e.level === 'WARN')) {
      const name = exm[1].split('.').pop();
      const root = [...e.raw.matchAll(/Caused by:\s*([\w.$]+)(?::\s*([^\n]{0,200}))?/g)].pop();
      add(`exc:${exm[1]}`, {
        severity: e.level === 'FATAL' ? 'critical' : 'high', category: 'Exception',
        title: `${name}${exm[2] ? `: ${preview(exm[2], 90)}` : ''}`,
        explanation: `The application threw ${exm[1]}${hasStack ? ' (with a stack trace)' : ''}${root ? `. Root cause: ${root[1].split('.').pop()}${root[2] ? ` – ${preview(root[2], 120)}` : ''}` : ''}. ${excHint(exm[1] + ' ' + (exm[2] || '') + ' ' + (root?.[1] || ''))}`.trim(),
        where: frameOf(e.raw),
      }, e);
      continue;
    }
    if (e.level === 'FATAL' || e.level === 'ERROR') {
      add(`lvl:${e.level}:${normalizeSig(first).slice(0, 120)}`, {
        severity: e.level === 'FATAL' ? 'critical' : 'high', category: `${e.level} log`,
        title: `${e.level}: ${preview(first, 100)}`,
        explanation: `A log line at ${e.level} level was written${e.component ? ` by ${shortComp(e.component)}` : ''}. ${e.level === 'FATAL' ? 'FATAL usually means the process or a critical part of it stopped.' : 'Something failed and the code logged it as an error.'}`,
      }, e);
    } else if (e.level === 'WARN') {
      add(`lvl:WARN:${normalizeSig(first).slice(0, 120)}`, {
        severity: 'low', category: 'Warning', title: `Warning: ${preview(first, 100)}`,
        explanation: `A warning was logged${e.component ? ` by ${shortComp(e.component)}` : ''}. Warnings are not failures by themselves but often explain what goes wrong next.`,
      }, e);
    }
    if (e.access && e.access.status >= 400) {
      add(`access:${e.access.status}:${(e.access.url || '').split('?')[0]}`, {
        severity: e.access.status >= 500 ? 'high' : 'medium', category: 'HTTP error',
        title: `HTTP ${e.access.status} on ${e.access.method || ''} ${preview((e.access.url || '').split('?')[0], 70)}`,
        explanation: httpExplain(e.access.status),
      }, e);
    }
  }

  for (const x of http.exchanges) {
    if (x.source === 'access-log') continue;
    const ent = byId(x.response?.entryIds?.[0] ?? x.entryIds[0]);
    if (x.status >= 400) {
      add(`http:${x.status}:${x.method}:${(x.url || '').split('?')[0]}`, {
        severity: x.status >= 500 ? 'high' : 'medium', category: 'HTTP error',
        title: `HTTP ${x.status}${x.reason ? ` ${x.reason}` : ''}${x.url ? ` from ${x.method || ''} ${preview(x.url.split('?')[0], 60)}` : ''}`,
        explanation: `${x.side === 'outbound' ? 'A downstream service' : 'The server'} answered with status ${x.status}. ${httpExplain(x.status)}`,
      }, ent);
    }
  }

  const reported = new Set();
  for (const c of apiCalls) {
    const ent = byId(c.entryId);
    const o = c.outcome;
    if (o.businessFail) {
      const desc = o.description;
      const http200 = c.httpStatus != null && c.httpStatus < 400;
      const who = c.apiName || c.vendor || c.url || 'A downstream API';
      add(`biz:${who}:${desc}`, {
        severity: 'high', category: http200 ? 'Business rejection (HTTP OK)' : 'Business failure',
        title: `${who} → ${humanize(String(o.reasons[0].value))}`,
        explanation: `${http200 ? `The HTTP call succeeded (${c.httpStatus}) but the response body says it failed` : c.httpStatus ? `The call returned HTTP ${c.httpStatus} and the body says it failed` : 'The response body says the call failed'}: ${desc}. ${bizHint(desc)}${http200 ? ' Monitoring that only checks HTTP status codes will miss this.' : ''}`.trim(),
        fields: o.reasons,
      }, ent);
      if (c.responseBody && typeof c.responseBody === 'object') reported.add(canonical(c.responseBody));
    }
  }
  for (const p of payloads) {
    if (!p.outcome.businessFail || reported.has(canonical(p.value))) continue;
    // ignore failure-ish words in payloads that are clearly configuration lists
    const ent = byId(p.entryIds[0]);
    const desc = p.outcome.description;
    add(`payload:${desc}`, {
      severity: 'medium', category: 'Failure in payload',
      title: `Payload says: ${preview(humanize(String(p.outcome.reasons[0].value)), 90)}`,
      explanation: `A JSON payload (${p.label}) contains a field that signals failure: ${p.outcome.reasons.map((r) => `${r.path} = ${preview(String(r.value), 60)}`).join('; ')}. ${bizHint(desc)}`.trim(),
      fields: p.outcome.reasons,
    }, ent);
  }

  for (const e of entries) {
    if (!e.fields || typeof e.fields !== 'object') continue;
    const f = { ...e.fields };
    for (const k of ['message', 'msg', 'level', 'severity', 'log', 'text', '@m', '@mt']) delete f[k];
    const o = judge(f, null);
    if (!o.businessFail) continue;
    add(`fields:${o.description}`, {
      severity: 'medium', category: 'Failure in log fields',
      title: `Log fields say: ${preview(humanize(String(o.reasons[0].value)), 90)}`,
      explanation: `Structured fields on this entry signal failure: ${o.reasons.map((r) => `${r.path} = ${preview(String(r.value), 60)}${r.why ? ` (${r.why})` : ''}`).join('; ')}. ${bizHint(o.description)}`.trim(),
      fields: o.reasons,
    }, e);
  }

  for (const s of http.messages) {
    if (s.source === 'wire' && s.chunked && !s.complete) {
      add(`wire-incomplete:${s.channel}`, { severity: 'low', category: 'Truncated', title: `Incomplete chunked body on ${s.channel}`, explanation: 'The wire log for this HTTP message ends before the final 0-size chunk, so the body may be cut off (log truncated or connection closed early).' }, byId(s.entryIds[0]));
    }
  }

  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...issues.values()].sort((a, b) => rank[a.severity] - rank[b.severity] || b.count - a.count);
}

function frameOf(raw) {
  const m = raw.match(/\n\s+at\s+([\w$.<>]+)\(([^)]*)\)/);
  return m ? `${m[1]} (${m[2]})` : null;
}
function excHint(s) {
  const h = [
    [/NullPointer|NoneType|undefined is not|Cannot read propert/i, 'Code used a value that was null/undefined — usually missing input data or an unset field.'],
    [/Timeout|SocketTimeout|timed out/i, 'A call took too long — the downstream service is slow or unreachable.'],
    [/ConnectException|Connection refused|UnknownHost|ECONNREFUSED|ENOTFOUND/i, 'Could not connect to a service — it is down, the host/port is wrong, or a firewall blocks it.'],
    [/SSL|Certificate|PKIX|handshake/i, 'TLS/certificate problem — the certificate is untrusted, expired, or the trust store is missing it.'],
    [/SQL|JDBC|Hibernate|Database|deadlock|ConstraintViolation/i, 'Database problem — query, connection or constraint failure.'],
    [/OutOfMemory|heap space|GC overhead/i, 'The JVM/process ran out of memory.'],
    [/NumberFormat|Parse|JsonProcessing|JSONException|Unexpected token|Malformed/i, 'Data could not be parsed — input is not in the expected format.'],
    [/IllegalArgument|IllegalState|Validation/i, 'Invalid argument or state — input data did not meet expectations.'],
    [/ClassNotFound|NoSuchMethod|NoClassDefFound/i, 'Deployment/classpath problem — a class or library version is missing or mismatched.'],
    [/AccessDenied|Unauthori|Forbidden|Authentication/i, 'Authentication/authorization failed.'],
    [/IndexOutOfBounds|ArrayIndex/i, 'Code read past the end of a list or array.'],
  ];
  for (const [re, t] of h) if (re.test(s)) return t;
  return '';
}
function httpExplain(s) {
  const t = { 400: 'Bad request — the caller sent invalid data.', 401: 'Unauthorized — missing or invalid credentials/token.', 403: 'Forbidden — credentials are valid but not allowed to do this.', 404: 'Not found — wrong URL or the resource does not exist.', 405: 'Method not allowed.', 408: 'Request timeout.', 409: 'Conflict — the resource state does not allow this.', 413: 'Payload too large.', 415: 'Unsupported media type — check Content-Type.', 422: 'Unprocessable — the data is well-formed but failed validation.', 429: 'Too many requests — rate limit hit.', 500: 'Internal server error on the called service.', 502: 'Bad gateway — a proxy got a bad answer from upstream.', 503: 'Service unavailable — overloaded or down.', 504: 'Gateway timeout — upstream did not answer in time.' };
  return t[s] || (s >= 500 ? 'Server-side failure.' : 'Client-side error — the request was rejected.');
}
function bizHint(d) {
  const s = String(d || '').toLowerCase();
  if (/free.?trial|trial/.test(s)) return 'The provider account is on a free trial whose limit is used up — upgrade/top up the account or whitelist the destination.';
  if (/insufficient|balance|credit|fund/.test(s)) return 'Not enough balance/credit on the account.';
  if (/expired/.test(s)) return 'Something (token, session, OTP, subscription) has expired.';
  if (/invalid.*pin|pin.*invalid|wrong.*pin|mpin/.test(s)) return 'The user entered a wrong PIN/MPIN.';
  if (/unauthori|auth|credential|token/.test(s)) return 'Authentication problem — check API key/token.';
  if (/destination|number|msisdn|recipient/.test(s)) return 'There is a problem with the destination/recipient number.';
  if (/limit|exceed|throttl|quota/.test(s)) return 'A limit or quota was exceeded.';
  if (/timeout/.test(s)) return 'The operation timed out.';
  if (/not.?found/.test(s)) return 'The requested item was not found.';
  return '';
}

// ───────────────────────── Security / PII ─────────────────────────
function buildSecurity(entries, http) {
  const findings = new Map();
  const add = (type, value, e, where, sev) => {
    const k = `${type}|${value}`;
    let f = findings.get(k);
    if (!f) { f = { type, severity: sev, masked: maskValue(value), where, lines: [], count: 0 }; findings.set(k, f); }
    f.count++;
    if (f.lines.length < 10 && !f.lines.includes(e.lineStart)) f.lines.push(e.lineStart);
  };
  const scanObj = (obj, e, src) => walk(obj, (k, v) => {
    if (v == null || typeof v === 'object') return;
    const s = String(v);
    if (SECRET_KEYS.test(k) && s && s.length < 600) add(/pin|otp/i.test(k) ? 'PIN / OTP field' : /password|passwd|pwd|pass$/i.test(k) ? 'Password field' : 'Secret / token field', s, e, `${src} → ${k}`, 'high');
    else if (PHONE_KEYS.test(k) && /^\+?\d{10,15}$/.test(s)) add('Phone number (MSISDN)', s, e, `${src} → ${k}`, 'medium');
  });
  for (const e of entries) {
    const text = e.ex.wire ? e.ex.wire.data : e.raw;
    if (e.fields) scanObj(e.fields, e, 'JSON field');
    for (const p of e.ex.kv || []) {
      if (SECRET_KEYS.test(p.key)) add('Secret / token field', p.value, e, `key=value → ${p.key}`, 'high');
      if (p.json) scanObj(p.json, e, p.key);
    }
    for (const j of e.ex.json || []) scanObj(j, e, 'embedded JSON');
    const h = e.ex.header;
    if (h?.name && /^(authorization|proxy-authorization|x-api-key|api-key|cookie|set-cookie|x-auth-token)$/i.test(h.name)) add('Authorization header / credential', h.value, e, `header ${h.name}`, 'high');
    // free text scans
    for (const m of text.matchAll(/\b(?:Authorization|X-Api-Key|api[_-]?key)\s*[:=]\s*"?((?:Bearer|Basic|App|Token)\s+[\w\-.~+/=]{8,}|[\w\-.~+/=]{16,})/gi)) add('Authorization header / credential', m[1], e, 'text', 'high');
    for (const m of text.matchAll(/\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g)) add('JWT token', m[0], e, 'text', 'high');
    for (const m of text.matchAll(/["']?\b(m?pin|otp|password|passwd|pwd)\b["']?\s*[:=]\s*["']?([^\s"',&}]{1,64})/gi)) add(/pin|otp/i.test(m[1]) ? 'PIN / OTP field' : 'Password field', m[2], e, `text → ${m[1]}`, 'high');
    for (const m of text.matchAll(/[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}/gi)) if (!/\.(png|jpg|gif|svg|js|css)$/i.test(m[0]) && !/^[\w-]+@\d/.test(m[0])) add('Email address', m[0], e, 'text', 'medium');
    for (const m of text.matchAll(/(?<![\w.\-:/])\+?(?:92|91|1|44|971|966|20|234|254|27|62|63|880|86|49|33)\d{9,12}(?![\w.])/g)) {
      const d = m[0].replace('+', '');
      if (d.length >= 11 && d.length <= 15 && !/^1\d{12}$/.test(d)) add('Phone number (MSISDN)', m[0], e, 'text', 'medium');
    }
    for (const m of text.matchAll(/(?<![\w])(?:\d[ -]?){13,19}(?![\w])/g)) {
      const d = m[0].replace(/\D/g, '');
      if (d.length >= 13 && d.length <= 19 && /^[3-6]/.test(d) && luhn(d) && !/^(\d)\1+$/.test(d)) add('Card number (Luhn-valid)', d, e, 'text', 'critical');
    }
  }
  for (const m of http.messages) for (const h of m.headers || []) {
    if (/^(authorization|proxy-authorization|x-api-key|api-key|cookie|x-auth-token)$/i.test(h.name)) {
      const e = entries[m.entryIds[0]];
      if (e) add('Authorization header / credential', h.value, e, `wire header ${h.name}`, 'high');
    }
  }
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  const list = [...findings.values()].sort((a, b) => rank[a.severity] - rank[b.severity] || b.count - a.count);
  return { findings: list, byType: countBy(list, (f) => f.type) };
}

// ───────────────────────── Story ─────────────────────────
function firstMatch(obj, re) {
  let out;
  walk(obj, (k, v) => { if (out === undefined && re.test(k) && v != null && typeof v !== 'object') out = v; });
  return out;
}
function buildStory({ entries, http, apiCalls, payloads, issues, stats, formatCheck, ids }) {
  const sentences = [];
  const bullets = [];

  // inbound
  const inbound = http.exchanges.filter((x) => x.side === 'inbound' && x.method);
  const inMsg = payloads.map((p) => p.value).find((v) => firstMatch(v, /^(body|text)$/) !== undefined && (firstMatch(v, /^(from|wa_id|sender)$/) !== undefined || JSON.stringify(v).includes('messages')));
  if (inMsg) {
    const txt = firstMatch(inMsg, /^body$/) ?? firstMatch(inMsg, /^text$/);
    const from = firstMatch(inMsg, /^(from|wa_id|sender)$/);
    const isWa = /whatsapp|wa_id|messaging_product|WABA/i.test(JSON.stringify(inMsg) + (inbound[0]?.url || ''));
    const x = inbound[0];
    sentences.push(`An inbound ${isWa ? 'WhatsApp ' : ''}message '${preview(String(txt), 60)}'${from ? ` from ${String(from).slice(0, 4)}…` : ''}${x ? ` hit ${x.method} ${x.url.split('?')[0]}` : ''}`);
  } else if (inbound.length) {
    const x = inbound[0];
    sentences.push(`The server received ${inbound.length === 1 ? 'a request' : `${inbound.length} requests`}, starting with ${x.method} ${x.url?.split('?')[0]}${x.status ? ` (answered ${x.status})` : ''}`);
  }

  const named = apiCalls.filter((c) => c.apiName || c.url);
  if (named.length) {
    const parts = named.slice(0, 4).map((c) => {
      const who = [c.vendor && !(c.apiName || '').toLowerCase().includes(c.vendor.toLowerCase()) ? c.vendor : null, c.apiName || (c.url ? c.url.split('?')[0] : '')].filter(Boolean).join(' ');
      let r = who;
      if (c.outcome.businessFail && (c.httpStatus == null || c.httpStatus < 400)) r += `, which answered ${c.httpStatus ? `${c.httpStatus} OK` : 'normally'} but the body says ${humanizeDesc(c.outcome.description)}`;
      else if (c.outcome.failed) r += `, which failed${c.httpStatus ? ` with HTTP ${c.httpStatus}` : ''}${c.outcome.description ? ` (${humanizeDesc(c.outcome.description)})` : ''}`;
      else if (c.httpStatus) r += `, which answered ${c.httpStatus}`;
      if (c.durationMs != null) r += ` in ${fmtDuration(c.durationMs)}`;
      return r;
    });
    sentences.push(`${sentences.length ? 'the app then called' : 'The app called'} ${parts.join('; then ')}${named.length > 4 ? ` (+${named.length - 4} more calls)` : ''}`);
  }

  let story = '';
  if (sentences.length) story = `${sentences.join('; ')}.`;
  story = story.replace(/^./, (c) => c.toUpperCase());

  const top = issues.filter((i) => i.severity === 'critical' || i.severity === 'high');
  if (top.length) {
    const t = top[0];
    if (!story.includes(humanizeDesc(t.fields?.[0]?.value ?? '').slice(0, 20)) || !story) story += `${story ? ' ' : ''}The main problem: ${t.title}${t.count > 1 ? ` (seen ${t.count}×)` : ''}.`;
    if (top.length > 1) story += ` ${top.length - 1} more serious issue${top.length > 2 ? 's were' : ' was'} found.`;
  } else if (!issues.length) {
    story += `${story ? ' ' : ''}No errors, exceptions or failure responses were detected.`;
  } else story += `${story ? ' ' : ''}Only minor issues (warnings) were found.`;

  if (!sentences.length) {
    const lv = stats.levels;
    story = `${stats.entries} log entries${stats.timeRange.spanMs != null ? ` over ${stats.timeRange.spanText}` : ''} (${lv.ERROR + lv.FATAL} errors, ${lv.WARN} warnings). ${story}`;
  }

  bullets.push(`Format: ${formatCheck.verdict} (${formatCheck.validJsonLines}/${formatCheck.nonEmptyLines} lines valid JSON).`);
  bullets.push(`${stats.entries} entries${stats.timeRange.spanMs != null ? ` spanning ${stats.timeRange.spanText}` : ''}; ${stats.levels.ERROR + stats.levels.FATAL} error-level, ${stats.levels.WARN} warnings.`);
  if (http.exchanges.length) bullets.push(`${http.exchanges.length} HTTP exchange(s) reconstructed${http.streams.length ? ` from ${http.streams.length} wire stream(s)` : ''}.`);
  if (apiCalls.length) bullets.push(`${apiCalls.length} downstream API call(s); ${apiCalls.filter((c) => c.outcome.failed).length} failed.`);
  if (payloads.length) bullets.push(`${payloads.length} unique JSON payload(s) recovered from messages.`);
  if (ids.length) bullets.push(`${ids.length} correlation/request ID(s) found${ids[0].links > 1 ? `; the busiest links ${ids[0].links} entries` : ''}.`);
  void entries;
  return { text: story.trim(), bullets };
}
function humanizeDesc(d) {
  if (!d) return '';
  const [a, ...rest] = String(d).split(' – ');
  const head = /^[A-Z0-9_]+$/.test(a) ? a.split('_')[0] : a;
  const tail = rest.length ? rest.join(' – ') : /^[A-Z0-9_]+$/.test(a) ? humanize(a.split('_').slice(1).join('_')) : '';
  return tail ? `${head} – ${tail}` : head;
}

export { RE_START_REQ, RE_START_RES };
