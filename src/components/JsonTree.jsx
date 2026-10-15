import { useState } from 'react';

export function CopyButton({ value, label = 'Copy' }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    try { await navigator.clipboard.writeText(text); } catch {
      const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    setDone(true); setTimeout(() => setDone(false), 1200);
  };
  return <button className="btn small" onClick={copy}>{done ? 'Copied ✓' : label}</button>;
}

function Node({ k, v, depth, defaultOpen }) {
  const isObj = v && typeof v === 'object';
  const [open, setOpen] = useState(depth < defaultOpen);
  const keyEl = k != null ? <span className="jk">{JSON.stringify(k)}</span> : null;
  if (!isObj) {
    const cls = v === null ? 'jn' : typeof v === 'string' ? 'js' : typeof v === 'number' ? 'jnum' : 'jb';
    return <div className="jrow">{keyEl}{keyEl && ': '}<span className={cls}>{JSON.stringify(v)}</span></div>;
  }
  const arr = Array.isArray(v);
  const entries = arr ? v.map((x, i) => [i, x]) : Object.entries(v);
  return (
    <div className="jrow">
      <span className="jtoggle" onClick={() => setOpen(!open)}>{open ? '▾' : '▸'}</span>
      {keyEl}{keyEl && ': '}
      <span className="jp">{arr ? '[' : '{'}</span>
      {!open && <span className="jsum" onClick={() => setOpen(true)}> {entries.length} {arr ? 'items' : 'keys'} </span>}
      {open && <div className="jchildren">{entries.map(([ck, cv]) => <Node key={ck} k={arr ? null : ck} v={cv} depth={depth + 1} defaultOpen={defaultOpen} />)}</div>}
      <span className="jp">{arr ? ']' : '}'}</span>
    </div>
  );
}

export default function JsonTree({ value, defaultOpen = 3 }) {
  return <div className="jtree"><Node v={value} depth={0} defaultOpen={defaultOpen} /></div>;
}
