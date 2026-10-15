import { useMemo, useState } from 'react';
import { CopyButton } from './JsonTree.jsx';
import { schemaRows, VIOLATION_INFO } from '../lib/layout.js';

function Highlight({ text, cols }) {
  if (!cols?.length) return <>{text.length > 4000 ? `${text.slice(0, 4000)}…` : text}</>;
  const set = new Set(cols.map((c) => c - 1));
  const parts = []; let buf = '';
  const lim = Math.min(text.length, 4000);
  for (let i = 0; i < lim; i++) {
    if (set.has(i)) { if (buf) parts.push(buf); buf = ''; parts.push(<mark key={i} className="badcol">{text[i]}</mark>); } else buf += text[i];
  }
  if (buf) parts.push(buf);
  if (cols.some((c) => c - 1 >= text.length)) parts.push(<mark key="eol" className="badcol">⏎</mark>);
  return <>{parts}{text.length > lim ? '…' : ''}</>;
}

export function LayoutTab({ r, layoutText, setLayoutText, schema, schemaSource, onUseDefault, onLearn, onReset, onDownloadFixed, schemaError }) {
  const L = r.layout;
  const [open, setOpen] = useState(false);
  const [only, setOnly] = useState('fail');
  const [code, setCode] = useState('all');
  const [limit, setLimit] = useState(300);
  const rows = useMemo(() => schemaRows(schema), [schema]);
  if (!L) return <p className="muted">Layout check not run.</p>;
  const s = L.summary;
  const list = L.lines.filter((l) => (only === 'all' || l.status === only) && (code === 'all' || l.violations.some((v) => v.code === code)));
  const cards = [
    { t: 'Compliance', v: `${s.compliancePct}%`, sub: `${s.pass} pass · ${s.warn} warn · ${s.fail} fail`, tone: s.fail ? 'bad' : s.warn ? 'warn' : 'good' },
    { t: 'Valid JSON lines', v: `${s.validJsonPct}%`, sub: `${s.validJsonLines}/${s.totalLines} physical lines`, tone: s.validJsonPct === 100 ? 'good' : 'bad' },
    { t: 'Request logs match', v: `${s.requestLogMatchPct}%`, sub: `${s.requestLogMatch}/${s.requestLogEntries} request-log entries`, tone: s.requestLogEntries && s.requestLogMatch === s.requestLogEntries ? 'good' : s.requestLogEntries ? 'bad' : 'neutral' },
    { t: 'Auto-fixable', v: s.fixable, sub: `${s.continuationLines} continuation line(s) joined`, tone: s.fixable ? 'warn' : 'neutral' },
  ];
  return <div>
    <section className="panel">
      <div className="row-between"><h3 className="click" onClick={() => setOpen(!open)}>{open ? '▾' : '▸'} Expected layout <span className="muted small">({schemaSource} · {rows.length} key paths)</span></h3></div>
      {open && <>
        <textarea value={layoutText} spellCheck={false} onChange={(e) => setLayoutText(e.target.value)} style={{ minHeight: 120 }} />
        <div className="actions">
          <button className="btn" onClick={onUseDefault}>Use client default</button>
          <button className="btn primary" onClick={onLearn}>Learn from pasted sample</button>
          <button className="btn ghost" onClick={onReset}>Reset</button>
          {schemaError && <span className="bad small">{schemaError}</span>}
        </div>
        <div className="scroll"><table className="tbl"><thead><tr><th>Key path</th><th>Type</th><th>Pattern</th><th>Required</th></tr></thead><tbody>
          {rows.map((x) => <tr key={x.path}><td className="mono">{x.path}</td><td className="small">{x.type}</td><td className="small">{x.pattern || '—'}</td><td>{x.required ? <span className="ok">yes</span> : x.conditional ? <span className="small muted">when message is an object</span> : <span className="muted">no</span>}</td></tr>)}
        </tbody></table></div>
      </>}
    </section>
    <section className={`panel verdict ${s.fail ? 'v-text' : s.warn ? 'v-mixed' : 'v-ndjson'}`}><h3>Verdict</h3><p>{s.verdict}</p></section>
    <div className="cards">{cards.map((c) => <div key={c.t} className={`card tone-${c.tone}`}><div className="card-t">{c.t}</div><div className="card-v">{c.v}</div><div className="card-s">{c.sub}</div></div>)}</div>
    {s.top.length > 0 && <section className="panel"><h3>Violation breakdown</h3><table className="tbl"><thead><tr><th>Violation</th><th>Severity</th><th>Count</th><th>Example lines</th></tr></thead><tbody>
      {s.top.map((t) => <tr key={t.code} className="click" onClick={() => { setCode(t.code); setOnly('all'); }}><td>{t.label}</td><td><span className={t.severity === 'fail' ? 'bad' : 'warn-t'}>{t.severity}</span></td><td className="num">{t.count}</td><td className="small">{t.lines.map((n) => `L${n}`).join(', ')}</td></tr>)}
    </tbody></table></section>}
    <div className="toolbar">
      {['fail', 'warn', 'pass', 'all'].map((x) => <button key={x} className={`chip ${only === x ? 'on' : ''}`} onClick={() => setOnly(x)}>{x} ({x === 'all' ? L.lines.length : s[x]})</button>)}
      <select value={code} onChange={(e) => setCode(e.target.value)}><option value="all">All violation types</option>{Object.keys(s.counts).map((c) => <option key={c} value={c}>{VIOLATION_INFO[c].label} ({s.counts[c]})</option>)}</select>
      <button className="btn" onClick={onDownloadFixed}>Download fixed NDJSON</button>
      <span className="muted small">{list.length} lines</span>
    </div>
    <div className="scroll tall"><table className="tbl"><thead><tr><th>Line</th><th>Status</th><th>Raw line · violations · suggested fix</th></tr></thead><tbody>
      {list.slice(0, limit).map((l) => <tr key={l.line}>
        <td className="num">{l.line}{l.entryLines && l.entryLines[1] > l.entryLines[0] ? `–${l.entryLines[1]}` : ''}</td>
        <td><span className={`lstat lstat-${l.status}`}>{l.status}</span></td>
        <td>
          <pre className="raw"><Highlight text={l.text} cols={l.violations.flatMap((v) => v.cols || (v.col ? [v.col] : []))} /></pre>
          <ul className="viol">{l.violations.map((v, k) => <li key={k} className={v.severity === 'fail' ? 'bad' : 'warn-t'}><b>{v.label}:</b> {v.msg}</li>)}</ul>
          {l.fix && <div className="fixbox"><div className="row-between"><span className="small ok">Suggested fix (parses ✓)</span><CopyButton value={l.fix} /></div><pre className="raw">{l.fix.length > 4000 ? `${l.fix.slice(0, 4000)}…` : l.fix}</pre></div>}
        </td>
      </tr>)}
    </tbody></table>
    {list.length > limit && <button className="btn" onClick={() => setLimit(limit + 500)}>Show more ({list.length - limit} left)</button>}</div>
  </div>;
}
