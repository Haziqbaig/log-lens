// Layout Check — rule-based schema inference + per-line compliance checking for NDJSON logs.
// No AI, no network. Works on raw text, one physical line at a time.

export const CLIENT_LAYOUT_SAMPLE = [
  '{"@timestamp":"2026-02-27 11:18:00,244","level":"INFO","component":"org.wso2.micro.integrator.initializer.StartupFinalizer","message":"WSO2 Micro Integrator started in 5.35 seconds"}',
  '{"@timestamp":"2026-02-27 11:26:01,868","level":"INFO","component":"org.apache.synapse.mediators.builtin.LogMediator","message":{"api":"MY_API","REQUEST_LOGGING":{"LOG_LEVEL":"INFO","LOG_TYPE":"EVENT_LOG_REQUEST","CORRELATION_ID":"e151a049-4484-4fc9-b35f-a5a47ed5d54f","TRAN_ID":"123455565432","MSISDN":"92324999999","API_NAME":"My_API","INTERFACE":"MI_INCOMING","STAGE":"MI","TIMESTAMP":"2026-02-27 11:26:01","CHANNEL":"App","SERVER_IP":"localhost","REQUEST_PAYLOAD":{"Transaction_Id":"123455565432","Msisdn":"923249999999","Message":"test message"}}}}',
].join('\n');

const STD_LEVELS = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'];

export const PATTERNS = {
  uuid: { label: 'UUID', re: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i },
  'ts-ms': { label: 'yyyy-MM-dd HH:mm:ss,SSS', re: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}$/ },
  'ts-ms-dot': { label: 'yyyy-MM-dd HH:mm:ss.SSS', re: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/ },
  ts: { label: 'yyyy-MM-dd HH:mm:ss', re: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/ },
  iso: { label: 'ISO-8601 (yyyy-MM-ddTHH:mm:ss…)', re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})?$/ },
  msisdn: { label: '92XXXXXXXXXX (12 digits)', re: /^92\d{10}$/ },
  digits: { label: 'digits only', re: /^\d+$/ },
  level: { label: STD_LEVELS.join('|'), re: new RegExp(`^(${STD_LEVELS.join('|')})$`) },
};
const VALUE_ORDER = ['uuid', 'ts-ms', 'ts-ms-dot', 'ts', 'iso', 'msisdn', 'digits'];

function hintPattern(key) {
  if (/correlation/i.test(key)) return 'uuid';
  if (/msisdn/i.test(key)) return 'msisdn';
  if (/^(tran_?id|transaction_?id|txn_?id)$/i.test(key)) return 'digits';
  if (/^(log_?level|level)$/i.test(key)) return 'level';
  return null;
}

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const tryParse = (s) => { try { return { ok: true, v: JSON.parse(s) }; } catch (e) { return { ok: false, err: e.message }; } };

function valuePattern(key, values) {
  const h = hintPattern(key);
  if (h) return h;
  const strs = values.filter((v) => typeof v === 'string' || typeof v === 'number').map(String);
  if (!strs.length || strs.length !== values.length) return null;
  return VALUE_ORDER.find((p) => strs.every((s) => PATTERNS[p].re.test(s))) || null;
}

// ── inference ────────────────────────────────────────────────────────────────
function newNode() { return { types: new Set(), count: 0, objCount: 0, values: [], keys: {} }; }
function feed(node, v) {
  node.count++; node.types.add(typeOf(v));
  if (isObj(v)) { node.objCount++; for (const [k, x] of Object.entries(v)) feed(node.keys[k] ??= newNode(), x); }
  else if (node.values.length < 200) node.values.push(v);
}
function finalize(node, key) {
  const out = { type: [...node.types].sort(), pattern: null, keys: null };
  if (node.objCount) {
    out.keys = {};
    for (const [k, c] of Object.entries(node.keys)) out.keys[k] = { ...finalize(c, k), required: c.count === node.objCount };
  }
  if (node.values.length && !out.type.includes('object')) out.pattern = valuePattern(key, node.values);
  return out;
}

/** Learn a schema from reference NDJSON lines. Lines that don't parse are ignored (reported in .skipped). */
export function inferLayout(sampleText) {
  const lines = String(sampleText || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const root = newNode();
  const skipped = [];
  lines.forEach((l, i) => { const p = tryParse(l); if (p.ok && isObj(p.v)) feed(root, p.v); else skipped.push(i + 1); });
  if (!root.objCount) return { ok: false, error: 'No valid JSON object lines found in the sample.', skipped };
  const tree = finalize(root, '');
  const top = tree.keys;
  const tsKey = Object.keys(top).find((k) => /timestamp|^time$|^ts$/i.test(k)) || null;
  const levelKey = Object.keys(top).find((k) => /^(level|severity|loglevel)$/i.test(k)) || null;
  const levels = new Set(STD_LEVELS);
  if (levelKey) for (const v of root.keys[levelKey].values) if (typeof v === 'string') levels.add(v);
  return {
    ok: true, lines: root.objCount, skipped,
    top, tsKey, levelKey, levels: [...levels],
    timestampPattern: tsKey ? top[tsKey].pattern : null,
    messageKey: top.message ? 'message' : null,
  };
}

export const DEFAULT_SCHEMA = inferLayout(CLIENT_LAYOUT_SAMPLE);

/** Flatten the schema into readable rows: path, type, pattern, required. */
export function schemaRows(schema) {
  const rows = [];
  const rec = (keys, prefix, parentRequired) => {
    for (const [k, n] of Object.entries(keys || {})) {
      const path = prefix ? `${prefix}.${k}` : k;
      let pattern = n.pattern ? PATTERNS[n.pattern].label : '';
      if (k === schema.levelKey) pattern = schema.levels.join('|');
      rows.push({ path, type: n.type.join(' | '), pattern, required: n.required && parentRequired, conditional: !parentRequired && n.required });
      if (n.keys) rec(n.keys, path, n.required && parentRequired && !n.type.includes('string'));
    }
  };
  rec(schema.top, '', true);
  return rows;
}

// ── JSON repair helpers ──────────────────────────────────────────────────────
const VALID_ESC = new Set(['"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u']);

/** Escape a raw string body: unescaped quotes, invalid backslashes, control chars. Returns {text, quoteCols, escCols}. */
function escapeBody(body, offset) {
  let out = ''; const quoteCols = []; const escCols = [];
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\') {
      const n = body[i + 1];
      if (n === 'u' && /^[0-9a-fA-F]{4}$/.test(body.slice(i + 2, i + 6))) { out += body.slice(i, i + 6); i += 5; continue; }
      if (n !== undefined && VALID_ESC.has(n) && n !== 'u') { out += c + n; i++; continue; }
      out += '\\\\'; escCols.push(offset + i + 1); continue;
    }
    if (c === '"') { out += '\\"'; quoteCols.push(offset + i + 1); continue; }
    const code = c.charCodeAt(0);
    if (code < 0x20) { out += c === '\n' ? '\\n' : c === '\r' ? '\\r' : c === '\t' ? '\\t' : `\\u${code.toString(16).padStart(4, '0')}`; continue; }
    out += c;
  }
  return { text: out, quoteCols, escCols };
}

function isEscaped(s, i) { let n = 0; while (i - 1 - n >= 0 && s[i - 1 - n] === '\\') n++; return n % 2 === 1; }

function matchClose(s, start) {
  let depth = 0, inStr = false;
  for (let j = start; j < s.length; j++) {
    const c = s[j];
    if (inStr) { if (c === '\\') j++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') { depth--; if (depth === 0) return j; if (depth < 0) return -1; }
  }
  return -1;
}

/**
 * Re-tokenise a top-level JSON object where string values may contain raw (unescaped) quotes.
 * A string value ends at the first quote followed by `,"<known top key>":` or by the final `}`.
 */
export function repairObjectLine(line, knownKeys) {
  const s = line;
  let i = 0, out = '';
  const quoteCols = [], escCols = [];
  const ws = () => { while (i < s.length && /\s/.test(s[i])) i++; };
  ws(); if (s[i] !== '{') return null; out += '{'; i++;
  const seen = new Set();
  for (let guard = 0; guard < 200; guard++) {
    ws();
    if (s[i] === '}') { out += '}'; i++; break; }
    if (s[i] !== '"') return null;
    let j = i + 1; while (j < s.length && !(s[j] === '"' && !isEscaped(s, j))) j++;
    if (j >= s.length) return null;
    const key = s.slice(i + 1, j); seen.add(key);
    out += s.slice(i, j + 1); i = j + 1; ws();
    if (s[i] !== ':') return null; out += ':'; i++; ws();
    if (s[i] === '"') {
      const start = i + 1; let end = -1, lastEnd = -1;
      for (let k = start; k < s.length; k++) {
        if (s[k] !== '"' || isEscaped(s, k)) continue;
        const rest = s.slice(k + 1);
        const m = /^\s*,\s*"([^"\\]+)"\s*:/.exec(rest);
        if (m && knownKeys.has(m[1]) && !seen.has(m[1])) { end = k; break; }
        if (/^\s*}\s*$/.test(rest)) lastEnd = k;
      }
      if (end < 0) end = lastEnd;
      if (end < 0) return null;
      const b = escapeBody(s.slice(start, end), start);
      quoteCols.push(...b.quoteCols); escCols.push(...b.escCols);
      out += `"${b.text}"`; i = end + 1;
    } else if (s[i] === '{' || s[i] === '[') {
      const e = matchClose(s, i); if (e < 0) return null;
      out += s.slice(i, e + 1); i = e + 1;
    } else {
      const m = /^[^,}]+/.exec(s.slice(i)); if (!m) return null;
      out += m[0].trim(); i += m[0].length;
    }
    ws();
    if (s[i] === ',') { out += ','; i++; continue; }
    if (s[i] === '}') { out += '}'; i++; break; }
    return null;
  }
  if (s.slice(i).trim()) return null;
  const p = tryParse(out);
  if (!p.ok || (!quoteCols.length && !escCols.length)) return null;
  return { fixed: out, value: p.v, quoteCols, escCols };
}

/** Is the scanner inside a string at the end of `s`? */
function endsInString(s) {
  let inStr = false;
  for (let j = 0; j < s.length; j++) { const c = s[j]; if (inStr) { if (c === '\\') j++; else if (c === '"') inStr = false; } else if (c === '"') inStr = true; }
  return inStr;
}
function braceDepth(s) {
  let d = 0, inStr = false;
  for (let j = 0; j < s.length; j++) { const c = s[j]; if (inStr) { if (c === '\\') j++; else if (c === '"') inStr = false; continue; } if (c === '"') inStr = true; else if (c === '{' || c === '[') d++; else if (c === '}' || c === ']') d--; }
  return { depth: d, inStr };
}

// ── checking ────────────────────────────────────────────────────────────────
export const VIOLATION_INFO = {
  'unescaped-quotes': { sev: 'fail', label: 'Unescaped double quotes inside a string' },
  'invalid-escape': { sev: 'fail', label: 'Invalid backslash escape in a string' },
  'raw-newline': { sev: 'fail', label: 'Raw newline splits one entry over several lines' },
  'raw-newline-cont': { sev: 'fail', label: 'Continuation of an entry split by a raw newline' },
  truncated: { sev: 'fail', label: 'Truncated JSON object' },
  'trailing-junk': { sev: 'fail', label: 'Trailing text after the JSON object' },
  fragment: { sev: 'fail', label: 'Line starts mid-JSON (orphan fragment)' },
  'not-json': { sev: 'fail', label: 'Not JSON (plain text)' },
  'invalid-json': { sev: 'fail', label: 'Invalid JSON (other)' },
  'not-object': { sev: 'fail', label: 'JSON value is not an object' },
  'missing-key': { sev: 'fail', label: 'Required key missing' },
  'key-case': { sev: 'fail', label: 'Key case differs from layout' },
  'wrong-type': { sev: 'fail', label: 'Value has the wrong type' },
  'bad-timestamp': { sev: 'fail', label: 'Bad @timestamp format' },
  'unknown-level': { sev: 'fail', label: 'Unknown level' },
  'extra-key': { sev: 'warn', label: 'Extra key not in layout' },
  'pattern-mismatch': { sev: 'warn', label: 'Value breaks its pattern' },
  'msisdn-mismatch': { sev: 'warn', label: 'MSISDN differs inside the payload' },
  'tranid-mismatch': { sev: 'warn', label: 'TRAN_ID differs from Transaction_Id' },
};
const V = (code, msg, extra = {}) => ({ code, severity: VIOLATION_INFO[code].sev, label: VIOLATION_INFO[code].label, msg, ...extra });

function compareNode(actual, node, path, out) {
  const keys = node.keys || {};
  const actualKeys = Object.keys(actual);
  const used = new Set();
  for (const [k, n] of Object.entries(keys)) {
    let key = k;
    if (!(k in actual)) {
      const alt = actualKeys.find((a) => a.toLowerCase() === k.toLowerCase() && !(a in keys));
      if (alt) { out.push(V('key-case', `${path}.${alt} should be "${k}" (key names are case-sensitive)`, { path: `${path}.${k}`, found: alt })); key = alt; }
      else { if (n.required) out.push(V('missing-key', `${path}.${k} is missing`, { path: `${path}.${k}`, key: k })); continue; }
    }
    used.add(key);
    checkValue(actual[key], n, `${path}.${k}`, k, out);
  }
  for (const a of actualKeys) if (!used.has(a) && !(a in keys)) out.push(V('extra-key', `${path}.${a} is not in the layout`, { path: `${path}.${a}`, key: a }));
}
function checkValue(v, n, path, key, out) {
  const t = typeOf(v);
  if (!n.type.includes(t)) { out.push(V('wrong-type', `${path} is ${t}, expected ${n.type.join(' or ')}`, { path })); return; }
  if (t === 'object' && n.keys) { compareNode(v, n, path, out); return; }
  if (n.pattern && (t === 'string' || t === 'number') && !PATTERNS[n.pattern].re.test(String(v))) {
    const s = String(v);
    const extra = n.pattern === 'msisdn' && /^\d+$/.test(s) ? ` (${s.length} digits)` : '';
    out.push(V('pattern-mismatch', `${path} = "${s.slice(0, 60)}"${extra} does not match ${PATTERNS[n.pattern].label}`, { path, key }));
  }
}

function collect(v, re, path = 'message', acc = []) {
  if (!isObj(v)) return acc;
  for (const [k, x] of Object.entries(v)) {
    const p = `${path}.${k}`;
    if (isObj(x)) collect(x, re, p, acc);
    else if ((typeof x === 'string' || typeof x === 'number') && re.test(k)) acc.push({ path: p, value: String(x) });
  }
  return acc;
}
function consistency(msg, out) {
  for (const [re, code, name] of [[/msisdn/i, 'msisdn-mismatch', 'MSISDN'], [/^(tran_?id|transaction_?id|txn_?id)$/i, 'tranid-mismatch', 'Transaction id']]) {
    const vals = collect(msg, re);
    const distinct = [...new Set(vals.map((x) => x.value))];
    if (distinct.length > 1) out.push(V(code, `${name} values disagree: ${vals.map((x) => `${x.path} = ${x.value} (${x.value.length} chars)`).join(' vs ')}`, { values: vals }));
  }
}

/** Validate one parsed entry against the schema. */
export function checkObject(obj, schema) {
  const out = [];
  if (!isObj(obj)) return [V('not-object', `top-level JSON is ${typeOf(obj)}, expected an object`)];
  const top = schema.top || {};
  const keys = Object.keys(obj);
  const used = new Set();
  for (const [k, n] of Object.entries(top)) {
    let key = k;
    if (!(k in obj)) {
      const alt = keys.find((a) => a.toLowerCase() === k.toLowerCase() && !(a in top));
      if (alt) { out.push(V('key-case', `top-level "${alt}" should be "${k}"`, { path: k, found: alt })); key = alt; }
      else { if (n.required) out.push(V('missing-key', `top-level "${k}" is missing`, { path: k, key: k })); continue; }
    }
    used.add(key);
    const v = obj[key];
    const t = typeOf(v);
    if (!n.type.includes(t)) { out.push(V('wrong-type', `"${k}" is ${t}, expected ${n.type.join(' or ')}`, { path: k })); continue; }
    if (k === schema.tsKey && schema.timestampPattern && !PATTERNS[schema.timestampPattern].re.test(String(v))) out.push(V('bad-timestamp', `"${k}" = "${String(v).slice(0, 40)}" — expected ${PATTERNS[schema.timestampPattern].label}`, { path: k }));
    else if (k === schema.levelKey && !schema.levels.includes(String(v))) out.push(V('unknown-level', `level "${v}" is not one of ${schema.levels.join(', ')}`, { path: k }));
    else if (t === 'object' && n.keys) { compareNode(v, n, k, out); if (k === schema.messageKey) consistency(v, out); }
    else if (k !== schema.tsKey && k !== schema.levelKey) checkValue(v, n, k, k, out);
  }
  for (const a of keys) if (!used.has(a) && !(a in top)) out.push(V('extra-key', `top-level "${a}" is not in the layout`, { path: a, key: a }));
  return out;
}

const statusOf = (vs) => (vs.some((v) => v.severity === 'fail') ? 'fail' : vs.length ? 'warn' : 'pass');

function compShort(c) {
  const s = String(c || '');
  if (/wire/i.test(s)) return 'wire';
  if (/headers/i.test(s)) return 'headers';
  if (/LogMediator|mediator/i.test(s)) return 'mediator';
  return s.split('.').pop() || 'unknown';
}

/** Check every physical line of `text` against `schema`. */
export function checkLayout(text, schema = DEFAULT_SCHEMA, opts = {}) {
  const t0 = Date.now();
  const maxJoin = opts.maxJoin ?? 60;
  const raw = String(text || '').split('\n').map((l) => l.replace(/\r$/, ''));
  const known = new Set([...Object.keys(schema.top || {}), '@timestamp', 'level', 'component', 'message', 'logger', 'thread']);
  const firstKeys = [...known].map((k) => k.replace(/[.*+?^${}()|[\]\\@]/g, '\\$&')).join('|');
  const startRe = new RegExp(`^\\s*\\{\\s*"(${firstKeys})"\\s*:`);
  const lines = [];
  const entries = [];
  const claimed = new Map();

  const addEntry = (e) => { entries.push(e); return e; };

  for (let i = 0; i < raw.length; i++) {
    const text = raw[i];
    const ln = i + 1;
    if (!text.trim()) continue;
    if (claimed.has(ln)) {
      const start = claimed.get(ln);
      lines.push({ line: ln, text, status: 'fail', role: 'cont', entryStart: start, violations: [V('raw-newline-cont', `continuation of the entry that starts on line ${start} (raw newline)`)], fix: null });
      continue;
    }
    const trimmed = text.trim();
    const res = { line: ln, text, role: 'single', violations: [], fix: null, jsonOk: false, entryLines: [ln, ln] };
    let obj;
    const p = tryParse(trimmed);
    if (p.ok) { res.jsonOk = true; obj = p.v; }
    else if (!trimmed.startsWith('{')) {
      const v = /^\s*["}\]]|^\s*"[^"]+"\s*:|[}\]]\s*$/.test(trimmed)
        ? V('fragment', 'line starts mid-JSON — the beginning of this entry is on an earlier line', { col: 1 })
        : V('not-json', `plain text, not JSON: ${p.err}`, { col: 1 });
      res.violations.push(v);
    } else {
      // trailing junk
      const e = matchClose(trimmed, 0);
      const pre = e > 0 && e < trimmed.length - 1 ? tryParse(trimmed.slice(0, e + 1)) : null;
      const rep = repairObjectLine(trimmed, known);
      if (pre?.ok) {
        const col = text.indexOf(trimmed) + e + 2;
        res.violations.push(V('trailing-junk', `unexpected text after the closing } at column ${col}: "${trimmed.slice(e + 1, e + 41)}"`, { col }));
        res.fix = trimmed.slice(0, e + 1); obj = pre.v;
      } else if (rep) {
        const lead = text.indexOf(trimmed);
        if (rep.quoteCols.length) res.violations.push(V('unescaped-quotes', `${rep.quoteCols.length} unescaped " inside a string value — first at column ${rep.quoteCols[0] + lead}`, { col: rep.quoteCols[0] + lead, cols: rep.quoteCols.map((c) => c + lead) }));
        if (rep.escCols.length) res.violations.push(V('invalid-escape', `invalid backslash escape at column ${rep.escCols[0] + lead}`, { col: rep.escCols[0] + lead }));
        res.fix = rep.fixed; obj = rep.value;
      } else {
        // raw newline: join with following lines until it parses
        let joined = null;
        let acc = trimmed, accSpace = trimmed, accNl = trimmed;
        for (let k = 1; k <= maxJoin && i + k < raw.length; k++) {
          const nx = raw[i + k];
          if (startRe.test(nx)) break;
          const sep = endsInString(acc) ? '\\n' : ' ';
          acc += sep + nx.trim(); accSpace += ` ${nx.trim()}`; accNl += `\\n${nx}`;
          for (const cand of [acc, accNl, accSpace]) {
            const q = tryParse(cand);
            if (q.ok && isObj(q.v)) { joined = { k, fixed: cand, value: q.v, quotes: null }; break; }
            const r = repairObjectLine(cand, known);
            if (r) { joined = { k, fixed: r.fixed, value: r.value, quotes: r }; break; }
          }
          if (joined) break;
        }
        if (joined) {
          const end = ln + joined.k;
          for (let x = ln + 1; x <= end; x++) claimed.set(x, ln);
          res.role = 'start'; res.entryLines = [ln, end];
          res.violations.push(V('raw-newline', `entry continues on line${joined.k > 1 ? 's' : ''} ${ln + 1}${joined.k > 1 ? `–${end}` : ''} — a raw newline was written instead of \\n; fixed by joining`, { col: text.length + 1 }));
          if (joined.quotes?.quoteCols.length) res.violations.push(V('unescaped-quotes', `${joined.quotes.quoteCols.length} unescaped " inside a string value in the joined entry`));
          res.fix = joined.fixed; obj = joined.value;
        } else {
          const { depth, inStr } = braceDepth(trimmed);
          if (depth > 0 || inStr) {
            res.violations.push(V('truncated', `object is cut off (${inStr ? 'unterminated string, ' : ''}${depth} unclosed bracket${depth === 1 ? '' : 's'}) and could not be completed by joining the next lines`, { col: text.length }));
          } else {
            const m = /position (\d+)/.exec(p.err);
            res.violations.push(V('invalid-json', p.err, m ? { col: Number(m[1]) + 1 + text.indexOf(trimmed) } : {}));
          }
        }
      }
    }
    if (obj !== undefined) {
      res.obj = obj;
      res.violations.push(...checkObject(obj, schema));
      res.level = isObj(obj) ? obj[schema.levelKey || 'level'] : undefined;
      res.component = isObj(obj) ? obj.component : undefined;
      res.messageType = isObj(obj) ? typeOf(obj[schema.messageKey || 'message']) : undefined;
    } else {
      res.level = (/"level"\s*:\s*"([A-Z]+)"/.exec(trimmed) || [])[1];
      res.component = (/"component"\s*:\s*"([^"]+)"/.exec(trimmed) || [])[1];
    }
    res.isRequestLog = res.messageType === 'object' || /LogMediator/.test(res.component || '') || /REQUEST_LOGGING|RESPONSE_LOGGING|LOG_TYPE/.test(trimmed);
    res.status = statusOf(res.violations);
    // keep the suggested fix only if it really parses
    if (res.fix && !tryParse(res.fix).ok) res.fix = null;
    lines.push(res);
    addEntry(res);
  }
  // Re-sort (continuation lines were pushed in order already) and drop heavy obj from output
  for (const l of lines) delete l.obj;
  const summary = summarize(lines, entries);
  return { schemaInfo: { tsKey: schema.tsKey, levels: schema.levels, timestampPattern: schema.timestampPattern }, lines, summary, elapsedMs: Date.now() - t0 };
}

function summarize(lines, entries) {
  const total = lines.length;
  const by = { pass: 0, warn: 0, fail: 0 };
  for (const l of lines) by[l.status]++;
  const jsonOk = lines.filter((l) => l.jsonOk).length;
  const counts = {};
  const examples = {};
  const missingKeys = {};
  const quoteCtx = { levels: new Set(), comps: new Set() };
  for (const e of entries) {
    for (const v of e.violations) {
      counts[v.code] = (counts[v.code] || 0) + 1;
      (examples[v.code] ??= []).length < 5 && examples[v.code].push(e.line);
      if (v.code === 'missing-key') missingKeys[v.key] = (missingKeys[v.key] || 0) + 1;
      if (v.code === 'unescaped-quotes') { if (e.level) quoteCtx.levels.add(e.level); quoteCtx.comps.add(compShort(e.component)); }
    }
  }
  const contLines = lines.filter((l) => l.role === 'cont').length;
  const req = entries.filter((e) => e.isRequestLog);
  const reqMatch = req.filter((e) => e.jsonOk && e.messageType === 'object' && e.status !== 'fail').length;
  const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
  const top = Object.entries(counts).map(([code, n]) => ({ code, label: VIOLATION_INFO[code].label, severity: VIOLATION_INFO[code].sev, count: n, lines: examples[code] }))
    .sort((a, b) => (a.severity === b.severity ? b.count - a.count : a.severity === 'fail' ? -1 : 1));

  const causes = [];
  for (const t of top.filter((x) => x.severity === 'fail').slice(0, 4)) {
    if (t.code === 'unescaped-quotes') causes.push(`unescaped quotes in ${[...quoteCtx.levels].join('/') || ''} ${[...quoteCtx.comps].join('/')} messages`.replace(/\s+/g, ' '));
    else if (t.code === 'missing-key') causes.push(`missing ${Object.entries(missingKeys).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k]) => k).join('/')}`);
    else if (t.code === 'raw-newline') causes.push('raw newlines splitting entries across lines');
    else if (t.code === 'key-case') causes.push('key case differences (e.g. API vs api)');
    else if (t.code !== 'raw-newline-cont') causes.push(t.label.toLowerCase());
  }
  const warnOnly = top.filter((x) => x.severity === 'warn').map((x) => x.label.toLowerCase());
  let verdict = `${pct(jsonOk, total)}% of lines are valid JSON; ${req.length ? `${pct(reqMatch, req.length)}% of request-log lines match the client layout` : 'no request-log lines found'}`;
  if (causes.length) verdict += `; main causes: ${causes.slice(0, 3).join(', ')}.`;
  else if (warnOnly.length) verdict += `; no blocking violations, only warnings: ${warnOnly.slice(0, 2).join(', ')}.`;
  else verdict += '; every line matches the layout.';

  return {
    totalLines: total, entries: entries.length, continuationLines: contLines,
    pass: by.pass, warn: by.warn, fail: by.fail,
    passPct: pct(by.pass, total), compliancePct: pct(by.pass + by.warn, total), validJsonPct: pct(jsonOk, total), validJsonLines: jsonOk,
    requestLogEntries: req.length, requestLogMatch: reqMatch, requestLogMatchPct: pct(reqMatch, req.length),
    fixable: entries.filter((e) => !e.jsonOk && e.fix).length,
    counts, top, verdict,
  };
}

/** Build NDJSON from valid + auto-fixed entries. Returns {text, included, omitted:[line numbers]}. */
export function fixedNDJSON(result) {
  const out = []; const omitted = []; let fixed = 0;
  for (const l of result.lines) {
    if (l.role === 'cont') continue;
    if (l.jsonOk) out.push(l.text.trim());
    else if (l.fix) { out.push(l.fix); fixed++; }
    else omitted.push(l.entryLines?.[0] === l.entryLines?.[1] ? l.line : `${l.entryLines[0]}-${l.entryLines[1]}`);
  }
  return { text: out.length ? `${out.join('\n')}\n` : '', included: out.length, fixed, omitted };
}
