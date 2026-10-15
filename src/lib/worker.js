import { analyze } from './analyze.js';
self.onmessage = (ev) => {
  try { self.postMessage({ ok: true, result: analyze(ev.data.text) }); }
  catch (e) { self.postMessage({ ok: false, error: String(e?.stack || e) }); }
};
