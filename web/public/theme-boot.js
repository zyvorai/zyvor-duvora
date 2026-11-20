// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

(function () {
  try {
    var t = localStorage.getItem('duvora-theme');
    if (t !== 'dark' && t !== 'light') t = 'light';
    document.documentElement.setAttribute('data-theme', t);
    var m = document.querySelector('meta[name="theme-color"]');
    if (m) m.setAttribute('content', t === 'dark' ? '#000000' : '#ffffff');
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
