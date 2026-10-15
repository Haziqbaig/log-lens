// Per-entry message analysis: embedded JSON, KEY = value pairs, HTTP header lines, http.wire lines.
import { findJSON, tryJSON, matchBracket } from './util.js';

// '<channel> >> "<bytes>"'  — channel e.g. "HTTP-Listener I/O dispatcher-21" or "http-outgoing-420"
const RE_WIRE = /^(?:.*?\s-\s)?((?:HTTP-(?:Listener|Sender)\s+I\/O\s+dispatcher-\d+)|(?:http-(?:outgoing|incoming)-\d+)|(?:[\w\-]+(?:\s[\w\-/]+){0,4}?))\s(<<|>>)\s"([\s\S]*)"\s*(?:\{[\w.$]+\})?\s*$/;
// '<channel> << Header-Name: value'  or  '<channel> << HTTP/1.1 200 OK'
const RE_HDR = /^(?:.*?\s-\s)?((?:HTTP-(?:Listener|Sender)\s+I\/O\s+dispatcher-\d+)|(?:http-(?:outgoing|incoming)-\d+))\s(<<|>>)\s(.+?)\s*(?:\{[\w.$]+\})?\s*$/;
export const RE_START_REQ = /^([A-Z]{3,7}) (\S+) (HTTP\/\d(?:\.\d)?)$/;
export const RE_START_RES = /^(HTTP\/\d(?:\.\d)?) (\d{3})(?: (.*))?$/;

export function decodeWire(s) {
  return s
    .replace(/\[\\r\]/g, '\r')
    .replace(/\[\\n\]/g, '\n')
    .replace(/\[\\t\]/g, '\t')
    .replace(/\[0x([0-9a-f]{1,2})\]/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** Parse KEY = value, KEY = value (Synapse LogMediator style). Values may be JSON with commas. */
export function parseKV(text) {
  if (!text || !/[\w.\-]\s?=\s?\S/.test(text)) return null;
  const out = [];
  const keyRe = /([A-Za-z_][\w.\-]{0,60})\s?=\s?/y;
  let i = 0;
  const n = text.length;
  // skip leading prose until first KEY =
  const first = text.search(/(^|[\s,;:])[A-Za-z_][\w.\-]{0,60}\s?=\s?/);
  if (first < 0) return null;
  i = first;
  while (i < n) {
    while (i < n && /[\s,;]/.test(text[i])) i++;
    keyRe.lastIndex = i;
    const m = keyRe.exec(text);
    if (!m) break;
    const key = m[1];
    i = keyRe.lastIndex;
    let val;
    if (text[i] === '{' || text[i] === '[') {
      const end = matchBracket(text, i, true);
      const end2 = end > 0 ? end : matchBracket(text, i, false);
      if (end2 > 0) { val = text.slice(i, end2 + 1); i = end2 + 1; }
    }
    if (val === undefined) {
      const rest = text.slice(i);
      const nx = rest.search(/,\s*[A-Za-z_][\w.\-]{0,60}\s?=\s?/);
      if (nx < 0) { val = rest; i = n; } else { val = rest.slice(0, nx); i += nx + 1; }
    }
    val = val.trim();
    let json;
    if (/^[[{]/.test(val)) {
      json = tryJSON(val);
      if (json === undefined && val.includes('\\"')) json = tryJSON(val.replace(/\\"/g, '"'));
    }
    out.push({ key, value: val, json });
  }
  if (!out.length) return null;
  // Avoid false positives: need ≥2 pairs or an UPPER_CASE key or a JSON value.
  if (out.length < 2 && !/^[A-Z][A-Z0-9_.]+$/.test(out[0].key) && out[0].json === undefined) return null;
  return out;
}

export function extractEntry(e) {
  const msg = e.message || '';
  const ex = {};
  const firstLine = msg.split('\n')[0];
  const isWireComp = /wire/i.test(e.component || '') || /http\.wire/.test(e.raw);

  const w = firstLine.match(RE_WIRE);
  if (w && (isWireComp || /dispatcher-\d+|http-(outgoing|incoming)-\d+/.test(w[1]))) {
    ex.wire = { channel: w[1].trim(), dir: w[2], data: decodeWire(w[3]) };
    return ex; // wire bytes are reassembled later; don't treat them as messages
  }
  const h = firstLine.match(RE_HDR);
  if (h) {
    const line = h[3];
    let m;
    if ((m = line.match(RE_START_REQ))) ex.header = { channel: h[1], dir: h[2], start: { method: m[1], url: m[2], protocol: m[3] } };
    else if ((m = line.match(RE_START_RES))) ex.header = { channel: h[1], dir: h[2], start: { protocol: m[1], status: +m[2], reason: m[3] || '' } };
    else if ((m = line.match(/^([A-Za-z0-9\-_]+):\s?(.*)$/))) ex.header = { channel: h[1], dir: h[2], name: m[1], value: m[2] };
    if (ex.header) return ex;
  }

  const full = e.continuation && e.format !== 'json-multiline' ? `${msg}\n${e.continuation}` : msg;
  const kv = parseKV(full.length > 200000 ? full.slice(0, 200000) : full);
  if (kv) ex.kv = kv;
  const covered = new Set((kv || []).filter((p) => p.json !== undefined).map((p) => p.value));
  const js = findJSON(full.length > 500000 ? full.slice(0, 500000) : full, 15)
    .filter((j) => !covered.has(full.slice(j.start, j.end + 1)));
  if (js.length) ex.json = js.map((j) => j.value);
  return ex;
}

/** Parse a raw HTTP byte stream (one channel+direction) into messages. */
export function parseHttpStream(buf) {
  const msgs = [];
  let pos = 0;
  const startRe = /(?:^|\n)((?:[A-Z]{3,7} \S+ HTTP\/\d(?:\.\d)?)|(?:HTTP\/\d(?:\.\d)? \d{3}[^\r\n]*))\r?\n/g;
  const starts = [];
  let m;
  while ((m = startRe.exec(buf))) starts.push({ idx: m.index + (buf[m.index] === '\n' ? 1 : 0), line: m[1] });
  if (!starts.length) {
    if (buf.trim()) msgs.push({ start: null, headers: [], body: buf, partial: true });
    return msgs;
  }
  for (let k = 0; k < starts.length; k++) {
    const s = starts[k];
    const stop = k + 1 < starts.length ? starts[k + 1].idx : buf.length;
    pos = s.idx;
    const seg = buf.slice(pos, stop);
    const sep = seg.search(/\r?\n\r?\n/);
    const head = sep >= 0 ? seg.slice(0, sep) : seg;
    let rest = sep >= 0 ? seg.slice(sep).replace(/^\r?\n\r?\n/, '') : '';
    const hl = head.split(/\r?\n/);
    const startLine = hl.shift();
    const headers = hl.filter(Boolean).map((l) => { const i = l.indexOf(':'); return { name: l.slice(0, i).trim(), value: l.slice(i + 1).trim() }; });
    const get = (n) => headers.find((x) => x.name.toLowerCase() === n)?.value;
    let body = rest, chunked = false, complete = true;
    if (/chunked/i.test(get('transfer-encoding') || '')) {
      chunked = true;
      const d = decodeChunked(rest); body = d.body; complete = d.complete;
    } else if (get('content-length')) {
      const cl = parseInt(get('content-length'), 10);
      body = rest.slice(0, cl); complete = rest.length >= cl;
    }
    let mm; const start = {};
    if ((mm = startLine.match(RE_START_REQ))) Object.assign(start, { kind: 'request', method: mm[1], url: mm[2], protocol: mm[3] });
    else if ((mm = startLine.match(RE_START_RES))) Object.assign(start, { kind: 'response', protocol: mm[1], status: +mm[2], reason: mm[3] || '' });
    const bodyJson = body.trim() ? tryJSON(body.trim()) : undefined;
    msgs.push({ startLine, start, headers, body, bodyJson, chunked, complete, offset: pos });
  }
  return msgs;
}

export function decodeChunked(s) {
  let i = 0, body = '', complete = false, chunks = 0;
  while (i < s.length) {
    const nl = s.indexOf('\n', i);
    if (nl < 0) break;
    const sizeLine = s.slice(i, nl).replace(/\r$/, '').split(';')[0].trim();
    if (!/^[0-9a-fA-F]+$/.test(sizeLine)) { body += s.slice(i); break; }
    const size = parseInt(sizeLine, 16);
    i = nl + 1;
    if (size === 0) { complete = true; break; }
    // sizes are bytes; logs show chars — use UTF-8 aware slicing
    const { text, consumed } = sliceBytes(s, i, size);
    body += text; chunks++;
    i += consumed;
    if (s[i] === '\r') i++;
    if (s[i] === '\n') i++;
  }
  return { body, complete, chunks };
}

function sliceBytes(s, from, nBytes) {
  let bytes = 0, j = from;
  while (j < s.length && bytes < nBytes) {
    const c = s.codePointAt(j);
    bytes += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    j += c > 0xffff ? 2 : 1;
  }
  return { text: s.slice(from, j), consumed: j - from };
}
