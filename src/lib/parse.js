// Line → entry parsing and the JSON format check. Pure JS.
import { tryJSON, jsonError, normLevel, tsToMs, matchBracket } from './util.js';

const TS = String.raw`\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:\s?Z|\s?[+-]\d{2}:?\d{2})?`;
const LVL = String.raw`(?:FATAL|ERROR|ERR|WARN(?:ING)?|INFO|DEBUG|TRACE|SEVERE|CRITICAL|NOTICE|VERBOSE)`;

const RE_WSO2 = new RegExp(String.raw`^TID:\s*\[[^\]]*\]\s*(?:\[[^\]]*\]\s*)?\[(${TS})\]\s+(${LVL})\s+\{([^}]+)\}\s+-\s+([\s\S]*?)(?:\s+\{[\w.$]+\}\s*)?$`, 'i');
const RE_TS_FIRST = new RegExp(String.raw`^\[?(${TS})\]?\s+\[?(${LVL})\]?\s+(?:\[([^\]]+)\]\s+)?(?:\{?([\w.$\-]+(?:\.[\w$\-]+)*)\}?\s+(?:-|:)\s+)?([\s\S]*)$`, 'i');
const RE_LVL_FIRST = new RegExp(String.raw`^\[?(${LVL})\]?\s+\[?(${TS})\]?\s+(?:\[([^\]]+)\]\s+)?(?:\{?([\w.$\-]+)\}?\s+(?:-|:)\s+)?([\s\S]*)$`, 'i');
const RE_TS_ONLY = new RegExp(String.raw`^\[?(${TS})\]?\s+([\s\S]*)$`);
const RE_SYSLOG = /^(?:<(\d+)>)?([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-./]+)(?:\[(\d+)\])?:\s*([\s\S]*)$/;
const RE_SYSLOG5424 = /^<(\d+)>\d\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:-|\[.*?\])\s*([\s\S]*)$/;
const RE_ACCESS = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(?:(\S+) (\S+)(?: (\S+))?|-)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?(?:\s+(\S+))?/;
const RE_LEVEL_WORD = new RegExp(String.raw`\b(${LVL})\b`);
const RE_CONT = /^(\s+|at\s|Caused by:|Suppressed:|\.\.\. \d+ (more|common)|[}\]],?\s*$)/;

const K = {
  ts: ['@timestamp', 'timestamp', 'time', 'ts', 'date', 'datetime', 'eventTime', '@t', 'asctime'],
  level: ['level', 'severity', 'lvl', 'loglevel', 'log.level', 'levelname', 'log_level', '@l', 'severityText'],
  msg: ['message', 'msg', 'text', 'log', 'event', '@m', '@mt', 'body'],
  comp: ['component', 'logger', 'logger_name', 'loggerName', 'log.logger', 'class', 'source', 'module', 'service', 'service.name', 'name', 'category'],
  thread: ['thread', 'thread_name', 'threadName'],
};

function pick(obj, keys) {
  for (const k of keys) {
    if (obj[k] != null && obj[k] !== '') return { key: k, value: obj[k] };
    if (k.includes('.')) {
      const v = k.split('.').reduce((o, p) => (o && typeof o === 'object' ? o[p] : undefined), obj);
      if (v != null && v !== '' && typeof v !== 'object') return { key: k, value: v };
    }
  }
  return null;
}

export function fromJSONObject(obj) {
  const e = { fields: obj };
  const ts = pick(obj, K.ts); const lv = pick(obj, K.level); const m = pick(obj, K.msg);
  const c = pick(obj, K.comp); const t = pick(obj, K.thread);
  e.ts = ts ? String(ts.value) : null;
  e.level = lv ? normLevel(lv.value, true) : null;
  e.message = m ? (typeof m.value === 'string' ? m.value : JSON.stringify(m.value)) : '';
  e.component = c && typeof c.value !== 'object' ? String(c.value) : null;
  e.thread = t ? String(t.value) : null;
  // A JSON envelope may wrap a classic text log line — parse that too for extra metadata.
  if (e.message) {
    const inner = parsePlainHeader(e.message);
    if (inner && inner.format !== 'unknown') {
      e.ts = e.ts || inner.ts; e.level = e.level || inner.level;
      e.component = e.component || inner.component; e.thread = e.thread || inner.thread;
      if (inner.format === 'wso2' || inner.format === 'plain') e.message = inner.message;
    }
  }
  if (!e.level && e.message) e.level = guessLevel(e.message);
  return e;
}

function guessLevel(s) {
  const m = s.slice(0, 200).match(RE_LEVEL_WORD);
  return m ? normLevel(m[1]) : null;
}

/** Try to recognise a header (first) line of a text log entry. Returns null if not a header. */
export function parsePlainHeader(line) {
  let m = line.match(RE_WSO2);
  if (m) return { format: 'wso2', ts: m[1], level: normLevel(m[2]), component: m[3].trim(), message: m[4] };
  m = line.match(RE_TS_FIRST);
  if (m) return { format: 'plain', ts: m[1], level: normLevel(m[2]), thread: m[3] || null, component: m[4] || null, message: m[5] };
  m = line.match(RE_LVL_FIRST);
  if (m) return { format: 'plain', ts: m[2], level: normLevel(m[1]), thread: m[3] || null, component: m[4] || null, message: m[5] };
  m = line.match(RE_ACCESS);
  if (m) {
    const status = +m[7];
    return {
      format: 'access', ts: m[3], level: status >= 500 ? 'ERROR' : status >= 400 ? 'WARN' : 'INFO', component: 'access-log',
      message: line, access: { client: m[1], user: m[2], method: m[4] || null, url: m[5] || null, protocol: m[6] || null, status, bytes: m[8], referer: m[9] || null, agent: m[10] || null, responseTime: m[11] || null },
    };
  }
  m = line.match(RE_SYSLOG5424);
  if (m) return { format: 'syslog', ts: m[2], level: sysLevel(+m[1]), component: m[4], thread: m[5] !== '-' ? m[5] : null, host: m[3], message: m[7] };
  m = line.match(RE_SYSLOG);
  if (m) {
    const year = new Date().getUTCFullYear();
    return { format: 'syslog', ts: `${m[2]} ${year}`, level: m[1] ? sysLevel(+m[1]) : guessLevel(m[6]) || 'INFO', component: m[4], thread: m[5] || null, host: m[3], message: m[6] };
  }
  m = line.match(RE_TS_ONLY);
  if (m) return { format: 'plain', ts: m[1], level: guessLevel(m[2]), message: m[2] };
  return null;
}

function sysLevel(pri) {
  return ['FATAL', 'FATAL', 'FATAL', 'ERROR', 'WARN', 'INFO', 'INFO', 'DEBUG'][pri & 7];
}

/**
 * Split text into lines, run per-line JSON check, and group into entries.
 * Returns { lines, formatCheck, entries }.
 */
export function parseText(text, opts = {}) {
  const maxLineDetails = opts.maxLineDetails ?? 20000;
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  if (lines.length && lines[lines.length - 1] === '') lines.pop();

  // --- per-line JSON check
  const lineResults = [];
  let nonEmpty = 0, valid = 0, validObjects = 0;
  const errorKinds = new Map();
  for (let i = 0; i < lines.length; i++) {
    const s = lines[i].trim();
    if (!s) continue;
    nonEmpty++;
    let ok = false, err = null, kind = 'text';
    if (s[0] === '{' || s[0] === '[' || s[0] === '"') {
      err = jsonError(s); ok = err == null;
      if (ok) { kind = s[0] === '{' ? 'object' : s[0] === '[' ? 'array' : 'scalar'; if (kind === 'object') validObjects++; }
      else kind = 'broken-json';
    } else {
      err = jsonError(s);
      if (err == null) { ok = true; kind = 'scalar'; } // bare numbers etc.
    }
    if (ok) valid++;
    else {
      const k = kind === 'broken-json' ? 'Starts like JSON but is invalid' : 'Plain text (not JSON)';
      errorKinds.set(k, (errorKinds.get(k) || 0) + 1);
    }
    if (lineResults.length < maxLineDetails) lineResults.push({ line: i + 1, valid: ok, kind, error: err, text: s.length > 300 ? `${s.slice(0, 300)}…` : s });
  }

  // --- grouping into entries
  const entries = [];
  let cur = null;
  const prettyBlocks = [];
  const push = (e) => { e.id = entries.length; entries.push(e); cur = e; };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const s = raw.trim();
    if (!s) { if (cur) cur.rawLines.push(raw); continue; }

    if (s[0] === '{' || s[0] === '[') {
      const obj = tryJSON(s);
      if (obj !== undefined && typeof obj === 'object' && obj) {
        const base = Array.isArray(obj) ? { fields: null, message: s, level: null } : fromJSONObject(obj);
        push({ ...base, format: 'json', lineStart: i + 1, lineEnd: i + 1, rawLines: [raw] });
        if (Array.isArray(obj)) cur.fields = { items: obj };
        continue;
      }
      // pretty-printed JSON block spanning several lines?
      const window = lines.slice(i, i + 3000).join('\n');
      const startIdx = window.indexOf(s[0]);
      const end = matchBracket(window, startIdx, true);
      if (end > 0) {
        const block = window.slice(startIdx, end + 1);
        const v = tryJSON(block);
        if (v !== undefined) {
          const n = block.split('\n').length;
          if (n > 1) {
            const base = Array.isArray(v) ? { fields: { items: v }, message: '' } : fromJSONObject(v);
            push({ ...base, format: 'json-multiline', lineStart: i + 1, lineEnd: i + n, rawLines: lines.slice(i, i + n) });
            prettyBlocks.push({ lineStart: i + 1, lineEnd: i + n });
            i += n - 1;
            continue;
          }
        }
      }
    }

    const h = RE_CONT.test(raw) && cur ? null : parsePlainHeader(s);
    if (h) {
      push({ ...h, fields: null, lineStart: i + 1, lineEnd: i + 1, rawLines: [raw] });
      continue;
    }
    if (cur && (RE_CONT.test(raw) || /^[\w.$]+(Exception|Error)\b/.test(s) || ((cur.format === 'plain' || cur.format === 'wso2') && /^["{}[\]]/.test(s)))) {
      // continuation of a multi-line text entry (stack trace, wrapped message, pretty payload)
      if (cur.format === 'json') { // JSON lines don't continue — start an unknown entry instead
        push({ format: 'unknown', ts: null, level: guessLevel(s), component: null, message: s, fields: null, lineStart: i + 1, lineEnd: i + 1, rawLines: [raw] });
        continue;
      }
      cur.rawLines.push(raw); cur.lineEnd = i + 1;
      continue;
    }
    push({ format: 'unknown', ts: null, level: guessLevel(s), component: null, message: s, fields: null, lineStart: i + 1, lineEnd: i + 1, rawLines: [raw] });
  }

  for (const e of entries) {
    e.raw = e.rawLines.join('\n').replace(/\n+$/, '');
    delete e.rawLines;
    if (e.lineEnd > e.lineStart && e.format !== 'json-multiline') {
      const rest = e.raw.split('\n').slice(1).join('\n');
      e.continuation = rest;
    }
    e.tsMs = tsToMs(e.ts);
    e.level = e.level || 'UNKNOWN';
    e.message = e.message ?? '';
  }

  const pct = nonEmpty ? (valid / nonEmpty) * 100 : 0;
  let verdict, verdictCode;
  if (!nonEmpty) { verdict = 'Empty input'; verdictCode = 'empty'; }
  else if (valid === nonEmpty) { verdict = validObjects === nonEmpty ? 'Fully NDJSON — every line is a valid JSON object' : 'Every line is valid JSON'; verdictCode = 'ndjson'; }
  else if (valid === 0 && prettyBlocks.length) { verdict = 'Pretty-printed (multi-line) JSON — valid JSON, but not one object per line'; verdictCode = 'pretty'; }
  else if (valid === 0) { verdict = 'Plain text — the logs are NOT in JSON format'; verdictCode = 'text'; }
  else { verdict = `Mixed — ${pct.toFixed(1)}% of lines are valid JSON, the rest are not`; verdictCode = 'mixed'; }

  const formats = {};
  for (const e of entries) formats[e.format] = (formats[e.format] || 0) + 1;

  return {
    lines,
    entries,
    formatCheck: {
      totalLines: lines.length, nonEmptyLines: nonEmpty, validJsonLines: valid, validJsonObjects: validObjects,
      invalidLines: nonEmpty - valid, validPct: +pct.toFixed(2), verdict, verdictCode,
      prettyBlocks, errorKinds: [...errorKinds.entries()], lineResults, truncated: nonEmpty > lineResults.length, entryFormats: formats,
    },
  };
}
