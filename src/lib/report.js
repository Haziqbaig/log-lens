import { fmtTime, preview } from './util.js';

export function toExportJSON(r) {
  const { entries, ...rest } = r;
  return JSON.stringify({
    ...rest,
    formatCheck: { ...r.formatCheck, lineResults: r.formatCheck.lineResults.filter((l) => !l.valid).slice(0, 2000) },
    layout: r.layout ? { ...r.layout, lines: r.layout.lines.filter((l) => l.status !== 'pass').slice(0, 2000).map((l) => ({ line: l.line, status: l.status, role: l.role, violations: l.violations.map((v) => ({ code: v.code, severity: v.severity, msg: v.msg, col: v.col })), fix: l.fix })) } : null,
    entries: entries.map((e) => ({ id: e.id, lineStart: e.lineStart, lineEnd: e.lineEnd, ts: e.ts, level: e.level, component: e.component, thread: e.thread, format: e.format, message: preview(e.message, 2000) })),
  }, null, 2);
}

export function toMarkdown(r) {
  const f = r.formatCheck, s = r.stats;
  const o = [];
  o.push('# Log Lens report', '', `_Generated ${r.generatedAt}_`, '');
  o.push('## What happened', '', r.story.text, '', ...r.story.bullets.map((b) => `- ${b}`), '');
  o.push('## Are the logs JSON?', '', `**${f.verdict}**`, '', `- Valid JSON lines: ${f.validJsonLines} / ${f.nonEmptyLines} (${f.validPct}%)`, `- Invalid lines: ${f.invalidLines}`, '');
  const bad = f.lineResults.filter((l) => !l.valid).slice(0, 20);
  if (bad.length) { o.push('| Line | Error | Text |', '|---|---|---|'); for (const l of bad) o.push(`| ${l.line} | ${esc(l.error)} | \`${esc(preview(l.text, 80))}\` |`); o.push(''); }
  if (r.layout) {
    const L = r.layout.summary;
    o.push('## Layout check', '', `**${L.verdict}**`, '', `- Schema: ${r.layout.schemaSource || 'client default'}`, `- Lines: ${L.totalLines} · pass ${L.pass} · warn ${L.warn} · fail ${L.fail} (compliance ${L.compliancePct}%)`, `- Request-log entries matching layout: ${L.requestLogMatch} / ${L.requestLogEntries} (${L.requestLogMatchPct}%)`, '');
    if (L.top.length) { o.push('| Violation | Severity | Count | Example lines |', '|---|---|---|---|'); for (const t of L.top) o.push(`| ${t.label} | ${t.severity} | ${t.count} | ${t.lines.join(', ')} |`); o.push(''); }
    const bad = r.layout.lines.filter((l) => l.status === 'fail' && l.role !== 'cont').slice(0, 15);
    for (const l of bad) o.push(`- line ${l.line}: ${esc(l.violations.map((v) => v.msg).join('; '))}`);
    if (bad.length) o.push('');
  }
  o.push(`## Issues (${r.issues.length})`, '');
  for (const i of r.issues) {
    o.push(`### [${i.severity.toUpperCase()}] ${i.title}  ×${i.count}`, '', i.explanation, '');
    for (const ev of i.evidence.slice(0, 3)) o.push(`- line ${ev.line}: \`${esc(preview(ev.text, 200))}\``);
    o.push('');
  }
  o.push('## HTTP exchanges', '');
  if (r.http.exchanges.length) { o.push('| Method | URL | Status | Duration | Channel |', '|---|---|---|---|---|'); for (const x of r.http.exchanges) o.push(`| ${x.method || ''} | ${esc(x.url || '')} | ${x.status ?? ''} | ${x.durationMs != null ? `${x.durationMs} ms` : ''} | ${esc(x.channel)} |`); } else o.push('_none_');
  o.push('', '## API calls', '');
  for (const c of r.apiCalls) o.push(`- **${c.apiName || c.url || '?'}** ${c.httpStatus ? `HTTP ${c.httpStatus}` : ''} → ${c.outcome.failed ? `FAILED (${c.outcome.description || 'http'})` : 'ok'}`);
  o.push('', '## Stats', '', `- Entries: ${s.entries}`, `- Time range: ${fmtTime(s.timeRange.start, true)} → ${fmtTime(s.timeRange.end, true)} (${s.timeRange.spanText})`, `- Entries/sec: ${s.perSecond ?? '—'}`, `- Levels: ${Object.entries(s.levels).filter(([, n]) => n).map(([k, n]) => `${k} ${n}`).join(', ')}`, '');
  o.push('## Security / PII', '');
  if (r.security.findings.length) { o.push('| Type | Masked value | Where | Count |', '|---|---|---|---|'); for (const x of r.security.findings) o.push(`| ${x.type} | \`${esc(x.masked)}\` | ${esc(x.where)} | ${x.count} |`); } else o.push('_none found_');
  return o.join('\n');
}
const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
