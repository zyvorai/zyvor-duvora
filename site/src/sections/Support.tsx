// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { links } from '../links';

export default function Support() {
  return (
    <section className="section support" id="support">
      <h2>Support the project</h2>
      <p className="lede">A commercial license is required to run it (sales@zyvor.dev). If it helps you, you can donate any amount you like. A donation is voluntary and supports development and maintenance. It is not a purchase: it buys no support, SLA, features, priority or license, and it is not tax-deductible (Zyvor AI Labs Private Limited is a company, not a charity). Zyvor Enterprise (supported releases, SLAs, a named contact and enterprise features) is separate: <a href={links.sales}>sales@zyvor.dev</a>.</p>
      <div className="cta-row center">
        <a className="btn" href={links.donate}>Donate any amount</a>
      </div>
    </section>
  );
}
