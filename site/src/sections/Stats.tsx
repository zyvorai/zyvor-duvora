import { useCountUp, useInView } from '../hooks';

function Stat({ n, suffix = '', label, run }: { n: number; suffix?: string; label: string; run: boolean }) {
  const v = useCountUp(n, run);
  return (<div className="stat"><b>{v}{suffix}</b><span>{label}</span></div>);
}

export default function Stats() {
  const [ref, seen] = useInView<HTMLDivElement>();
  return (
    <div className="stats" ref={ref}>
      <Stat n={0} label="runtime dependencies" run={seen} />
      <Stat n={4} label="simulated BlueField DPUs" run={seen} />
      <Stat n={5} suffix=" min" label="plan expiry, actor-bound" run={seen} />
      <Stat n={1000} label="steering rules per set" run={seen} />
    </div>
  );
}
