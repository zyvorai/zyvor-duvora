import { links } from '../links';

export default function Cta() {
  return (
    <section className="section cta">
      <h2>Run your DPU fleet workflow before the hardware arrives.</h2>
      <p className="lede">Duvora is free and open source under Apache-2.0. Zyvor Enterprise adds supported releases, upgrade guidance, priority incident triage, a named technical contact and 24x7 critical intake.</p>
      <div className="cta-row center">
        <a className="btn" href={links.demo}>Book a demo</a>
        <a className="btn btn-dark" href={links.poc}>Start a 30-day PoC</a>
        <a className="btn btn-ghost" href={links.pricing}>Pricing</a>
        <a className="btn btn-ghost" href={links.sales}>Contact sales</a>
        <a className="btn btn-ghost" href={links.repo}>Star on GitHub</a>
      </div>
    </section>
  );
}
