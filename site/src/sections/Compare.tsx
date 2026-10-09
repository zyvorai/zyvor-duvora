const ROWS = [
  ['Role', 'Operator workspace: inventory, plans, isolation, incidents, evidence', 'Provisioning and orchestration of BlueField DPUs and services'],
  ['Try without hardware', 'Yes, four simulated BlueField devices', 'Needs BlueField DPUs'],
  ['Change control', 'Expiring actor-bound plans, typed confirmations, revision-guarded rollback', 'Kubernetes resources and their controllers'],
  ['Runs on', 'One Python 3.11+ server with SQLite', 'Kubernetes with NVIDIA operators'],
  ['DPU provisioning & firmware', 'Not implemented', 'Yes'],
];

export default function Compare() {
  return (
    <section id="compare" className="section">
      <p className="eyebrow">Duvora vs NVIDIA DPF</p>
      <h2>Not a DPF replacement. The operator workflow around it.</h2>
      <p className="lede">Duvora reads DPF's DPU objects read-only and adds plans, evidence and isolation. Choose DPF when you need to provision BlueField DPUs and run DPU services in production.</p>
      <div className="table-wrap">
        <table>
          <thead><tr><th /><th>Duvora</th><th>NVIDIA DPF</th></tr></thead>
          <tbody>{ROWS.map((r) => <tr key={r[0]}><th>{r[0]}</th><td>{r[1]}</td><td>{r[2]}</td></tr>)}</tbody>
        </table>
      </div>
    </section>
  );
}
