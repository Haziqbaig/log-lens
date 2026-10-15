import { useCallback, useEffect, useRef, useState } from 'react';
import { SAMPLES } from './samples.js';
import { toExportJSON, toMarkdown } from './lib/report.js';
import { analyze } from './lib/analyze.js';
import { LayoutTab } from './components/LayoutTab.jsx';
import { inferLayout, fixedNDJSON, DEFAULT_SCHEMA, CLIENT_LAYOUT_SAMPLE } from './lib/layout.js';
import { Summary, Issues, FormatCheck, HttpTab, Payloads, Entries, Security } from './components/Tabs.jsx';

const TABS = [
  ['summary', 'Summary'], ['issues', 'Issues'], ['format', 'JSON Format Check'], ['layout', 'Layout Check'], ['http', 'HTTP & API calls'],
  ['payloads', 'Payloads'], ['entries', 'Timeline / Entries'], ['security', 'Security'],
];

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a'); a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function App() {
  const [text, setText] = useState('');
  const [fileName, setFileName] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('summary');
  const [drag, setDrag] = useState(false);
  const [sample, setSample] = useState(SAMPLES[0].id);
  const [layoutText, setLayoutText] = useState(CLIENT_LAYOUT_SAMPLE);
  const [schema, setSchema] = useState(DEFAULT_SCHEMA);
  const [schemaSource, setSchemaSource] = useState('client default');
  const [schemaError, setSchemaError] = useState('');
  const worker = useRef(null);
  const bigText = useRef(null); // large files are not pushed into the textarea

  useEffect(() => () => worker.current?.terminate(), []);

  const run = useCallback((input, sch = schema, src0 = schemaSource, keepTab = false) => {
    const src = input ?? bigText.current ?? text;
    if (!src.trim()) { setError('Paste some logs, drop a file or load a sample first.'); return; }
    setBusy(true); setError('');
    const done = (res) => { setResult(res); if (!keepTab) setTab('summary'); setBusy(false); };
    const opts = { schema: sch, schemaSource: src0 };
    try {
      worker.current?.terminate();
      const w = new Worker(new URL('./lib/worker.js', import.meta.url), { type: 'module' });
      worker.current = w;
      w.onmessage = (ev) => { w.terminate(); if (ev.data.ok) done(ev.data.result); else { setError(ev.data.error); setBusy(false); } };
      w.onerror = (ev) => { w.terminate(); setError(`Worker failed (${ev.message}); running on main thread.`); setTimeout(() => done(analyze(src, opts)), 10); };
      w.postMessage({ text: src, ...opts });
    } catch {
      setTimeout(() => { try { done(analyze(src, opts)); } catch (e) { setError(String(e)); setBusy(false); } }, 10);
    }
  }, [text, schema, schemaSource]);

  const loadFile = async (file) => {
    if (!file) return;
    const t = await file.text();
    setFileName(`${file.name} · ${(file.size / 1024).toFixed(1)} KB`);
    if (t.length > 1_000_000) { bigText.current = t; setText(`${t.slice(0, 20000)}\n\n… [${(t.length / 1e6).toFixed(1)} MB loaded — preview only; the whole file will be analysed]`); }
    else { bigText.current = null; setText(t); }
    run(t);
  };

  const applySchema = (sch, label) => { setSchema(sch); setSchemaSource(label); setSchemaError(''); if (result) run(undefined, sch, label, true); };
  const useDefault = () => { setLayoutText(CLIENT_LAYOUT_SAMPLE); applySchema(DEFAULT_SCHEMA, 'client default'); };
  const learn = () => { const sch = inferLayout(layoutText); if (!sch.ok) { setSchemaError(sch.error); return; } applySchema(sch, `learned from ${sch.lines} line(s)${sch.skipped.length ? `, ${sch.skipped.length} skipped` : ''}`); };
  const resetLayout = () => { setLayoutText(CLIENT_LAYOUT_SAMPLE); setSchemaError(''); applySchema(DEFAULT_SCHEMA, 'client default'); };
  const downloadFixed = () => {
    const f = fixedNDJSON(result.layout);
    download('log-lens-fixed.ndjson', f.text, 'application/x-ndjson');
    if (f.omitted.length) alert(`${f.included} line(s) written (${f.fixed} auto-fixed).\n${f.omitted.length} entr${f.omitted.length === 1 ? 'y' : 'ies'} could not be fixed and were left out: lines ${f.omitted.slice(0, 60).join(', ')}${f.omitted.length > 60 ? '…' : ''}`);
  };

  const onDrop = (e) => { e.preventDefault(); setDrag(false); loadFile(e.dataTransfer.files?.[0]); };
  const loadSample = () => { const s = SAMPLES.find((x) => x.id === sample); bigText.current = null; setFileName(`sample: ${s.name}`); setText(s.text); run(s.text); };
  const clear = () => { bigText.current = null; setText(''); setFileName(''); setResult(null); setError(''); };

  const counts = result && { issues: result.issues.length, payloads: result.payloads.length, entries: result.entries.length, security: result.security.findings.length, layout: result.layout?.summary.fail, http: result.http.exchanges.length + result.apiCalls.length };

  return (
    <div className="app">
      <header className="top">
        <div className="brand"><span className="logo">◎</span> Log Lens <span className="muted small">rule-based log analyser · runs 100% in your browser</span></div>
        {result && <div className="exports">
          <button className="btn" onClick={() => download('log-lens-analysis.json', toExportJSON(result), 'application/json')}>Export JSON</button>
          <button className="btn" onClick={() => download('log-lens-report.md', toMarkdown(result), 'text/markdown')}>Export Markdown</button>
        </div>}
      </header>

      <section className={`input panel ${drag ? 'drag' : ''}`} onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={onDrop}>
        <textarea value={text} spellCheck={false} placeholder="Paste logs here (JSON / NDJSON, WSO2, log4j, syslog, Nginx/Apache…) or drop a .log / .txt / .json file" onChange={(e) => { bigText.current = null; setText(e.target.value); }} />
        <div className="actions">
          <button className="btn primary" disabled={busy} onClick={() => run()}>{busy ? 'Analysing…' : 'Analyze'}</button>
          <label className="btn">Upload file<input type="file" accept=".log,.txt,.json,.ndjson,.jsonl,text/*" hidden onChange={(e) => loadFile(e.target.files?.[0])} /></label>
          <select value={sample} onChange={(e) => setSample(e.target.value)}>{SAMPLES.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
          <button className="btn" onClick={loadSample}>Load sample</button>
          <button className="btn ghost" onClick={clear}>Clear</button>
          <span className="muted small">{fileName}{result ? ` · analysed in ${result.elapsedMs} ms` : ''}</span>
        </div>
        {error && <div className="error">{error}</div>}
      </section>

      {result && <>
        <nav className="tabs">{TABS.map(([id, label]) => <button key={id} className={`tab ${tab === id ? 'on' : ''}`} onClick={() => setTab(id)}>{label}{counts[id] != null && <span className="count">{counts[id]}</span>}</button>)}</nav>
        <main className="content">
          {tab === 'summary' && <Summary r={result} go={setTab} />}
          {tab === 'issues' && <Issues r={result} />}
          {tab === 'format' && <FormatCheck r={result} />}
          {tab === 'layout' && <LayoutTab r={result} layoutText={layoutText} setLayoutText={setLayoutText} schema={schema} schemaSource={schemaSource} schemaError={schemaError} onUseDefault={useDefault} onLearn={learn} onReset={resetLayout} onDownloadFixed={downloadFixed} />}
          {tab === 'http' && <HttpTab r={result} />}
          {tab === 'payloads' && <Payloads r={result} />}
          {tab === 'entries' && <Entries r={result} />}
          {tab === 'security' && <Security r={result} />}
        </main>
      </>}
      {!result && !busy && <p className="muted center">No AI, no API keys, nothing leaves your machine. Load a sample to see what it finds.</p>}
    </div>
  );
}
