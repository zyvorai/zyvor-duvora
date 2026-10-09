import { useState } from 'react';

const TABS: Record<string, string> = {
  'Run it': `git clone https://github.com/zyvorai/duvora.git && cd duvora
make web
python3 -m duvora.server --demo
# open http://127.0.0.1:8787  ·  admin / Admin@321`,
  'Deploy': `./scripts/deploy-remote.sh user@10.0.1.5            # k3s + Helm
./scripts/deploy-remote.sh user@10.0.1.5 --docker   # podman/docker`,
  'CLI': `python3 -m pip install .
duvoractl login
duvoractl devices
duvoractl plan examples/isolate.json`,
};

export default function Quickstart() {
  const [t, setT] = useState('Run it');
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(TABS[t]).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }).catch(() => {});
  };
  return (
    <section id="start" className="section">
      <p className="eyebrow">Quickstart</p>
      <h2>Zero runtime dependencies. One command.</h2>
      <div className="tabs">{Object.keys(TABS).map((k) => <button key={k} className={k === t ? 'on' : ''} onClick={() => setT(k)}>{k}</button>)}</div>
      <div className="term code"><button className="copy" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button><pre>{TABS[t]}</pre></div>
    </section>
  );
}
