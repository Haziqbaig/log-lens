import { useMemo, useState } from 'react';
import JsonTree, { CopyButton } from './JsonTree.jsx';
import { fmtTime, fmtDuration, preview, shortComp, LEVELS } from '../lib/util.js';

const Sev = ({ s }) => <span className={`sev sev-${s}`}>{s}</span>;
const Lvl = ({ l }) => <span className={`lvl lvl-${l}`}>{l}</span>;
const Body = ({ v }) => v == null || v === '' ? <span className="muted">—</span> : typeof v === 'object'
  ? <div className="bodybox"><div className="row-end"><CopyButton value={v} /></div><JsonTree value={v} defaultOpen={2} /></div>
  : <pre className="raw">{preview(v, 4000)}</pre>;

export function Summary({ r, go }) {
  const f = r.formatCheck, s = r.stats;
  const serious = r.issues.filter((i) => i.severity === 'critical' || i.severity === 'high').length;
  const cards = [
    { t: 'JSON format', v: f.verdictCode === 'ndjson' ? 'Yes — NDJSON' : f.verdictCode === 'mixed' ? 'Mixed' : f.verdictCode === 'pretty' ? 'Pretty JSON' : 'No — plain text', sub: `${f.validJsonLines}/${f.nonEmptyLines} lines valid (${f.validPct}%)`, tone: f.verdictCode === 'ndjson' ? 'good' : f.verdictCode === 'mixed' ? 'warn' : 'bad', tab: 'format' },
    { t: 'Issues', v: r.issues.length, sub: `${serious} serious`, tone: serious ? 'bad' : r.issues.length ? 'warn' : 'good', tab: 'issues' },
    { t: 'Entries', v: s.entries, sub: `${s.levels.ERROR + s.levels.FATAL} errors · ${s.levels.WARN} warnings`, tone: 'neutral', tab: 'entries' },
    { t: 'HTTP / API', v: `${r.http.exchanges.length} / ${r.apiCalls.length}`, sub: `${r.apiCalls.filter((c) => c.outcome.failed).length} failed calls`, tone: r.apiCalls.some((c) => c.outcome.failed) ? 'bad' : 'neutral', tab: 'http' },
    { t: 'Time span', v: s.timeRange.spanText, sub: s.perSecond != null ? `${s.perSecond} entries/s` : 'no timestamps', tone: 'neutral', tab: 'entries' },
    { t: 'Sensitive data', v: r.security.findings.length, sub: r.security.byType.map(([k, n]) => `${n} ${k.split(' ')[0]}`).slice(0, 3).join(', ') || 'none', tone: r.security.findings.length ? 'warn' : 'good', tab: 'security' },
  ];
  return (
    <div>
      <div className="cards">{cards.map((c) => <button key={c.t} className={`card tone-${c.tone}`} onClick={() => go(c.tab)}><div className="card-t">{c.t}</div><div className="card-v">{c.v}</div><div className="card-s">{c.sub}</div></button>)}</div>
      <section className="panel story"><h3>What happened</h3><p>{r.story.text}</p><ul>{r.story.bullets.map((b) => <li key={b}>{b}</li>)}</ul></section>
      <section className="panel"><h3>Top issues</h3>{r.issues.length ? r.issues.slice(0, 5).map((i) => <IssueCard key={i.key} i={i} compact />) : <p className="muted">No issues detected.</p>}</section>
      {s.topSignatures.length > 0 && <section className="panel"><h3>Most repeated messages</h3><table className="tbl"><tbody>{s.topSignatures.slice(0, 8).map((x) => <tr key={x.sig}><td className="num">{x.count}×</td><td><Lvl l={x.level} /></td><td className="mono">{preview(x.example, 140)}</td></tr>)}</tbody></table></section>}
    </div>
  );
}

function IssueCard({ i, compact }) {
  const [open, setOpen] = useState(!compact);
  return (
    <div className={`issue sevb-${i.severity}`}>
      <div className="issue-h" onClick={() => setOpen(!open)}><Sev s={i.severity} /><span className="issue-t">{i.title}</span><span className="badge">{i.category}</span>{i.count > 1 && <span className="badge">×{i.count}</span>}</div>
      <p className="issue-x">{i.explanation}</p>
      {open && <>
        {i.where && <div className="muted small">at {i.where}</div>}
        {i.fields && <div className="fields">{i.fields.map((f) => <code key={f.path}>{f.path} = {String(f.value)}</code>)}</div>}
        {i.evidence.map((e, k) => <pre key={k} className="raw"><span className="ln">L{e.line}</span> {e.text}</pre>)}
      </>}
    </div>
  );
}

export function Issues({ r }) {
  const [sev, setSev] = useState('all');
  const list = r.issues.filter((i) => sev === 'all' || i.severity === sev);
  return <div>
    <div className="toolbar">{['all', 'critical', 'high', 'medium', 'low'].map((s) => <button key={s} className={`chip ${sev === s ? 'on' : ''}`} onClick={() => setSev(s)}>{s} ({s === 'all' ? r.issues.length : r.issues.filter((i) => i.severity === s).length})</button>)}</div>
    {list.length ? list.map((i) => <IssueCard key={i.key} i={i} />) : <p className="muted">Nothing here.</p>}
  </div>;
}

export function FormatCheck({ r }) {
  const f = r.formatCheck;
  const [only, setOnly] = useState('invalid');
  const rows = f.lineResults.filter((l) => only === 'all' || (only === 'invalid' ? !l.valid : l.valid));
  return <div>
    <section className={`panel verdict v-${f.verdictCode}`}>
      <h2>Are the logs coming in JSON format?</h2>
      <p className="big">{f.verdictCode === 'ndjson' ? 'YES' : f.verdictCode === 'mixed' ? 'PARTLY' : f.verdictCode === 'pretty' ? 'JSON, but multi-line' : 'NO'}</p>
      <p>{f.verdict}</p>
      <div className="bar"><div style={{ width: `${f.validPct}%` }} /></div>
      <p className="muted">{f.validJsonLines} valid JSON lines ({f.validJsonObjects} objects) · {f.invalidLines} not valid · {f.nonEmptyLines} non-empty of {f.totalLines} lines</p>
      {f.errorKinds.length > 0 && <p className="muted">{f.errorKinds.map(([k, n]) => `${k}: ${n}`).join(' · ')}</p>}
      {f.prettyBlocks.length > 0 && <p className="muted">{f.prettyBlocks.length} pretty-printed JSON block(s) found (valid JSON spread over several lines — not NDJSON).</p>}
    </section>
    <div className="toolbar">{['invalid', 'valid', 'all'].map((s) => <button key={s} className={`chip ${only === s ? 'on' : ''}`} onClick={() => setOnly(s)}>{s}</button>)}{f.truncated && <span className="muted small">showing first {f.lineResults.length} lines</span>}</div>
    <div className="scroll"><table className="tbl"><thead><tr><th>Line</th><th>JSON?</th><th>Error</th><th>Text</th></tr></thead><tbody>
      {rows.slice(0, 2000).map((l) => <tr key={l.line}><td className="num">{l.line}</td><td>{l.valid ? <span className="ok">✓ {l.kind}</span> : <span className="bad">✗</span>}</td><td className="small">{l.error || ''}</td><td className="mono">{preview(l.text, 140)}</td></tr>)}
    </tbody></table>{rows.length > 2000 && <p className="muted">…{rows.length - 2000} more</p>}</div>
  </div>;
}

export function HttpTab({ r }) {
  const [sel, setSel] = useState(null);
  return <div>
    <section className="panel"><h3>API calls ({r.apiCalls.length})</h3>
      {r.apiCalls.length ? <div className="scroll"><table className="tbl"><thead><tr><th>Time</th><th>API</th><th>URL</th><th>HTTP</th><th>Outcome</th></tr></thead><tbody>
        {r.apiCalls.map((c, k) => <tr key={k} className="click" onClick={() => setSel({ t: 'api', k })}><td className="mono">{fmtTime(c.ts)}</td><td>{c.apiName || c.vendor || '—'}</td><td className="mono">{preview(c.url || '', 70)}</td><td>{c.httpStatus ?? '—'}</td><td>{c.outcome.failed ? <span className="bad">✗ {preview(c.outcome.description || `HTTP ${c.httpStatus}`, 60)}</span> : <span className="ok">ok</span>}</td></tr>)}
      </tbody></table></div> : <p className="muted">No downstream API calls found.</p>}
      {sel?.t === 'api' && (() => { const c = r.apiCalls[sel.k]; return <div className="detail"><h4>{c.apiName || c.url}</h4><div className="grid2"><div><b>Request body</b><Body v={c.requestBody} /></div><div><b>Response body</b><Body v={c.responseBody} /></div></div></div>; })()}
    </section>
    <section className="panel"><h3>HTTP exchanges ({r.http.exchanges.length})</h3>
      {r.http.exchanges.length ? <div className="scroll"><table className="tbl"><thead><tr><th>Time</th><th>Side</th><th>Method</th><th>URL</th><th>Status</th><th>Duration</th><th>Channel</th><th>Source</th></tr></thead><tbody>
        {r.http.exchanges.map((x, k) => <tr key={k} className="click" onClick={() => setSel({ t: 'x', k })}><td className="mono">{fmtTime(x.startTs ?? x.endTs)}</td><td>{x.side}</td><td>{x.method || '—'}</td><td className="mono">{preview(x.url || '', 60)}</td><td className={x.status >= 400 ? 'bad' : ''}>{x.status ?? '—'} {x.reason || ''}</td><td>{fmtDuration(x.durationMs)}</td><td className="small">{x.channel}</td><td className="small">{x.source}</td></tr>)}
      </tbody></table></div> : <p className="muted">No HTTP traffic found.</p>}
      {sel?.t === 'x' && (() => { const x = r.http.exchanges[sel.k]; return <div className="detail grid2">
        {[['Request', x.request], ['Response', x.response]].map(([n, m]) => <div key={n}><b>{n}</b>{m ? <>
          <pre className="raw">{m.startLine || (m.start?.method ? `${m.start.method} ${m.start.url}` : m.start?.status ? `HTTP ${m.start.status} ${m.start.reason || ''}` : '')}{'\n'}{(m.headers || []).map((h) => `${h.name}: ${h.value}`).join('\n')}</pre>
          {m.chunked && <div className="muted small">chunked body {m.complete ? 'decoded (final 0 chunk seen)' : 'INCOMPLETE'}</div>}
          <Body v={m.bodyJson ?? m.body} /></> : <p className="muted">not in log</p>}</div>)}
      </div>; })()}
    </section>
    {r.http.streams.length > 0 && <section className="panel"><h3>Wire streams</h3><table className="tbl"><tbody>{r.http.streams.map((s) => <tr key={s.channel + s.dir}><td>{s.channel}</td><td>{s.dir}</td><td>{s.lines} lines</td><td>{s.bytes} chars</td></tr>)}</tbody></table></section>}
    {r.ids.length > 0 && <section className="panel"><h3>Correlation / request IDs</h3><table className="tbl"><thead><tr><th>ID</th><th>Keys</th><th>Linked entries</th></tr></thead><tbody>{r.ids.slice(0, 50).map((i) => <tr key={i.value}><td className="mono">{i.value}</td><td className="small">{i.keys.join(', ')}</td><td className="small">{i.links} ({i.entryIds.slice(0, 12).map((x) => `#${x}`).join(' ')}{i.entryIds.length > 12 ? '…' : ''})</td></tr>)}</tbody></table></section>}
  </div>;
}

export function Payloads({ r }) {
  return <div>{r.payloads.length ? r.payloads.map((p) => <details key={p.id} className="panel payload" open={p.id < 3}>
    <summary><span className="badge">{p.source}</span> <b>{p.label}</b> <span className="muted small">{p.size} chars · seen {p.count}× · entries {p.entryIds.map((x) => `#${x}`).join(' ')}</span>{p.outcome.businessFail && <span className="sev sev-high">failure: {preview(p.outcome.description, 50)}</span>}</summary>
    <div className="row-end"><CopyButton value={p.value} label="Copy JSON" /></div>
    <JsonTree value={p.value} />
  </details>) : <p className="muted">No JSON payloads found in messages.</p>}</div>;
}

export function Entries({ r }) {
  const [q, setQ] = useState('');
  const [lv, setLv] = useState('all');
  const [comp, setComp] = useState('all');
  const [hideWire, setHideWire] = useState(false);
  const [open, setOpen] = useState(null);
  const [limit, setLimit] = useState(500);
  const list = useMemo(() => {
    const ql = q.toLowerCase();
    return r.entries.filter((e) => (lv === 'all' || e.level === lv) && (comp === 'all' || e.component === comp) && (!hideWire || !e.ex.wire) && (!ql || e.raw.toLowerCase().includes(ql)));
  }, [r, q, lv, comp, hideWire]);
  return <div>
    <div className="toolbar">
      <input className="search" placeholder="Search entries…" value={q} onChange={(e) => setQ(e.target.value)} />
      <select value={lv} onChange={(e) => setLv(e.target.value)}><option value="all">All levels</option>{[...LEVELS, 'UNKNOWN'].filter((l) => r.stats.levels[l]).map((l) => <option key={l} value={l}>{l} ({r.stats.levels[l]})</option>)}</select>
      <select value={comp} onChange={(e) => setComp(e.target.value)}><option value="all">All components</option>{r.stats.components.map(([c, n]) => <option key={c} value={c}>{shortComp(c)} ({n})</option>)}</select>
      <label className="small"><input type="checkbox" checked={hideWire} onChange={(e) => setHideWire(e.target.checked)} /> hide wire lines</label>
      <span className="muted small">{list.length} / {r.entries.length}</span>
    </div>
    <div className="scroll tall"><table className="tbl entries"><thead><tr><th>#</th><th>Line</th><th>Time</th><th>Level</th><th>Component</th><th>Message</th></tr></thead><tbody>
      {list.slice(0, limit).map((e) => [
        <tr key={e.id} className="click" onClick={() => setOpen(open === e.id ? null : e.id)}><td className="num">{e.id}</td><td className="num">{e.lineStart}{e.lineEnd > e.lineStart ? `–${e.lineEnd}` : ''}</td><td className="mono">{fmtTime(e.tsMs)}</td><td><Lvl l={e.level} /></td><td className="small">{shortComp(e.component)}</td><td className="mono">{e.ex.wire ? `${e.ex.wire.channel} ${e.ex.wire.dir} ${preview(JSON.stringify(e.ex.wire.data), 120)}` : preview(e.message || e.raw, 160)}</td></tr>,
        open === e.id && <tr key={`${e.id}x`} className="expand"><td colSpan={6}>
          <div className="row-end"><CopyButton value={e.raw} label="Copy raw" /></div>
          <pre className="raw">{e.raw.length > 20000 ? `${e.raw.slice(0, 20000)}…` : e.raw}</pre>
          <div className="muted small">format: {e.format}{e.thread ? ` · thread: ${e.thread}` : ''}{e.ts ? ` · ts: ${e.ts}` : ''}</div>
          {e.fields && <><b>Parsed fields</b><JsonTree value={e.fields} defaultOpen={1} /></>}
          {e.ex.kv && <><b>Key = value pairs</b><JsonTree value={Object.fromEntries(e.ex.kv.map((p) => [p.key, p.json ?? p.value]))} defaultOpen={1} /></>}
          {e.ex.json && <><b>Embedded JSON</b>{e.ex.json.map((j, k) => <JsonTree key={k} value={j} defaultOpen={1} />)}</>}
          {e.ex.header && <><b>HTTP header line</b><JsonTree value={e.ex.header} /></>}
          {e.ex.wire && <><b>Wire bytes (decoded)</b><pre className="raw">{e.ex.wire.data}</pre></>}
        </td></tr>,
      ])}
    </tbody></table>
    {list.length > limit && <button className="btn" onClick={() => setLimit(limit + 1000)}>Show more ({list.length - limit} left)</button>}</div>
  </div>;
}

export function Security({ r }) {
  const f = r.security.findings;
  return <div>
    <section className="panel"><p>Values are masked. These should normally not be written to logs in clear text (PCI-DSS / GDPR / local data-protection rules).</p></section>
    {f.length ? <div className="scroll"><table className="tbl"><thead><tr><th>Severity</th><th>Type</th><th>Masked value</th><th>Where</th><th>Lines</th><th>Count</th></tr></thead><tbody>
      {f.map((x, k) => <tr key={k}><td><Sev s={x.severity} /></td><td>{x.type}</td><td className="mono">{x.masked}</td><td className="small">{x.where}</td><td className="small">{x.lines.join(', ')}</td><td className="num">{x.count}</td></tr>)}
    </tbody></table></div> : <p className="muted">No sensitive data found.</p>}
  </div>;
}
