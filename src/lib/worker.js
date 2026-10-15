import { analyze } from './analyze.js';
self.onmessage = (ev) => {
  try { self.postMessage({ ok: true, result: analyze(ev.data.text, { schema: ev.data.schema, schemaSource: ev.data.schemaSource }) }); }
  catch (e) { self.postMessage({ ok: false, error: String(e?.stack || e) }); }
};
