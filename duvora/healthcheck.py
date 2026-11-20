# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

"""Container health probe: GET /healthz on loopback, over TLS when the server serves TLS."""
import os
import ssl
import sys
import urllib.request


def main():
    port = os.environ.get("DUVORA_PORT", "8787")
    tls = bool(os.environ.get("DUVORA_TLS_CERT"))
    context = None
    if tls:
        # Loopback probe of our own listener; the certificate is usually self-signed for the host name.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    url = f"{'https' if tls else 'http'}://127.0.0.1:{port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=3, context=context) as response:
            sys.exit(0 if response.status == 200 else 1)
    except OSError:
        sys.exit(1)


if __name__ == "__main__":
    main()
