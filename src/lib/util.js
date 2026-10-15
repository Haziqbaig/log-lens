// Shared helpers for the Log Lens engine. Pure JS, no dependencies, no network.

export const LEVELS = ['FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'];

const LEVEL_ALIASES = {
  WARNING: 'WARN', SEVERE: 'ERROR', ERR: 'ERROR', CRITICAL: 'FATAL', CRIT: 'FATAL', EMERG: 'FATAL',
  EMERGENCY: 'FATAL', ALERT: 'FATAL', PANIC: 'FATAL', NOTICE: 'INFO', INFORMATION: 'INFO', VERBOSE: 'TRACE',
  FINE: 'DEBUG', FINER: 'TRACE', FINEST: 'TRACE', CONFIG: 'DEBUG', DBG: 'DEBUG', TRC: 'TRACE', INF: 'INFO',
  WRN: 'WARN', FTL: 'FATAL', E: 'ERROR', W: 'WARN', I: 'INFO', D: 'DEBUG', V: 'TRACE',
};

export function tryJSON(s) {
  try { return JSON.parse(s); } catch { return undefined; }
}

export function jsonError(s) {
  try { JSON.parse(s); return null; } catch (e) { return String(e.message || e); }
}

export function normLevel(v, allowShort = false) {
  if (v == null || v === '') return null;
  if (typeof v === 'number') {
    if (v >= 60) return 'FATAL';
    if (v >= 50) return 'ERROR';
    if (v >= 40) return 'WARN';
    if (v >= 30) return 'INFO';
    if (v >= 20) return 'DEBUG';
    return 'TRACE';
  }
  const u = String(v).trim().toUpperCase();
  if (LEVELS.includes(u)) return u;
  if (u.length === 1 && !allowShort) return null;
  return LEVEL_ALIASES[u] || null;
}

export function tsToMs(ts) {
  if (ts == null || ts === '') return null;
  if (typeof ts === 'number') return ts > 1e12 ? ts : ts * 1000;
  const s = String(ts).trim();
  let m = s.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,](\d{1,9}))?\s?(Z|[+-]\d{2}:?\d{2})?$/);
  if (m) {
    const frac = (m[3] || '0').padEnd(3, '0').slice(0, 3);
    let tz = 'Z';
    if (m[4] && m[4] !== 'Z') tz = m[4].length === 5 ? `${m[4].slice(0, 3)}:${m[4].slice(3)}` : m[4];
    const v = Date.parse(`${m[1]}T${m[2]}.${frac}${tz}`);
    return Number.isNaN(v) ? null : v;
  }
  m = s.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})(?:\s([+-]\d{4}))?/);
  if (m) {
    const v = Date.parse(`${m[2]} ${m[1]} ${m[3]} ${m[4]} GMT${m[5] || '+0000'}`);
    return Number.isNaN(v) ? null : v;
  }
  if (/^\d{10}(\.\d+)?$/.test(s)) return Math.round(parseFloat(s) * 1000);
  if (/^\d{13}$/.test(s)) return parseInt(s, 10);
  const v = Date.parse(s);
  return Number.isNaN(v) ? null : v;
}

export function fmtTime(ms, withDate = false) {
  if (ms == null) return '';
  const d = new Date(ms);
  const iso = d.toISOString();
  return withDate ? iso.replace('T', ' ').replace('Z', '') : iso.slice(11, 23);
}

export function fmtDuration(ms) {
  if (ms == null || Number.isNaN(ms)) return '—';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 1)} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${Math.round(s % 60)}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

/** Find matching close bracket for the bracket at `start`. Returns index or -1. */
export function matchBracket(text, start, trackStrings = true) {
  let depth = 0;
  let inStr = false;
  let esc = false;
  const limit = Math.min(text.length, start + 2_000_000);
  for (let j = start; j < limit; j++) {
    const c = text[j];
    if (trackStrings) {
      if (inStr) {
        if (esc) esc = false;
        else if (c === '\\') esc = true;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') { inStr = true; continue; }
    }
    if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') {
      depth--;
      if (depth === 0) return j;
      if (depth < 0) return -1;
    }
  }
  return -1;
}

function isMeaningful(v) {
  if (Array.isArray(v)) return v.length > 0 && v.some((x) => x && typeof x === 'object');
  return !!v && typeof v === 'object' && Object.keys(v).length > 0;
}

/** Extract every JSON object/array embedded in free text. */
export function findJSON(text, max = 25) {
  const out = [];
  if (!text || typeof text !== 'string') return out;
  let i = 0;
  while (i < text.length && out.length < max) {
    const ch = text[i];
    if (ch === '{' || ch === '[') {
      let found = null;
      for (const track of [true, false]) {
        const end = matchBracket(text, i, track);
        if (end <= i) continue;
        const cand = text.slice(i, end + 1);
        let v = tryJSON(cand);
        if (v === undefined && cand.includes('\\"')) v = tryJSON(cand.replace(/\\\\/g, '\u0000').replace(/\\"/g, '"').replace(/\u0000/g, '\\'));
        if (v !== undefined && isMeaningful(v)) { found = { value: v, start: i, end }; break; }
      }
      if (found) { out.push(found); i = found.end + 1; continue; }
    }
    i++;
  }
  return out;
}

/** Depth-first walk over JSON. cb(key, value, path, parentPath) */
export function walk(value, cb, path = '', depth = 0) {
  if (depth > 14 || value == null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((v, i) => {
      const p = `${path}[${i}]`;
      cb(String(i), v, p, path);
      walk(v, cb, p, depth + 1);
    });
  } else {
    for (const [k, v] of Object.entries(value)) {
      const p = path ? `${path}.${k}` : k;
      cb(k, v, p, path);
      walk(v, cb, p, depth + 1);
    }
  }
}

export function preview(v, n = 160) {
  let s = typeof v === 'string' ? v : JSON.stringify(v);
  if (s == null) s = String(v);
  s = s.replace(/\s+/g, ' ').trim();
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

/** Turn a message into a "signature" so repeated messages with different ids/numbers group together. */
export function normalizeSig(s) {
  return String(s)
    .replace(UUID_RE, '<id>')
    .replace(/\b\d{4}-\d{2}-\d{2}[ T][\d:.,]+\b/g, '<time>')
    .replace(/\b[0-9a-f]{16,}\b/gi, '<hex>')
    .replace(/\d+/g, '<n>')
    .replace(/\s+/g, ' ')
    .slice(0, 220);
}

/** REJECTED_FREE_TRIAL_EXCEEDED -> "Rejected free trial exceeded" ; invalidPinCount -> "Invalid pin count" */
export function humanize(s) {
  const t = String(s)
    .replace(/([a-z\d])([A-Z])/g, '$1 $2')
    .replace(/[_\-.]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  return t ? t[0].toUpperCase() + t.slice(1) : t;
}

export function shortComp(c) {
  if (!c) return '';
  const parts = String(c).split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : String(c);
}

export function maskValue(v) {
  const s = String(v);
  if (s.length <= 4) return '*'.repeat(s.length);
  if (/^\+?\d[\d\s-]{6,}$/.test(s)) return s.slice(0, 4) + '*'.repeat(Math.max(0, s.length - 6)) + s.slice(-2);
  if (s.includes('@')) {
    const [u, d] = s.split('@');
    return `${u.slice(0, 2)}***@${d}`;
  }
  return s.slice(0, 3) + '*'.repeat(Math.min(12, s.length - 5)) + s.slice(-2);
}

export function luhn(num) {
  const d = num.replace(/\D/g, '');
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function countBy(arr, fn) {
  const m = new Map();
  for (const x of arr) {
    const k = fn(x);
    if (k == null) continue;
    m.set(k, (m.get(k) || 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
}
