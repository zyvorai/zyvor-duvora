#!/usr/bin/env bash
# Duvora — remote deploy (SSH + rsync + K3s/Helm or a container runtime)
#
# Profiles:
#   default / --k3s   Install K3s if missing, build + import the image, Helm-install
#   --k8s             Helm on the host's existing kubeconfig (image must be pullable or imported)
#   --docker          Run one container with podman or docker (no Kubernetes)
#   --quick           Sync + Helm only (image must already exist on the host)
#
# Usage:
#   ./scripts/deploy-remote.sh user@10.0.1.5
#   ./scripts/deploy-remote.sh user@10.0.1.5 --docker
#   ./scripts/deploy-remote.sh HOST USER --k8s
#   ./scripts/deploy-remote.sh user@10.0.1.5 --dry-run       # print the remote script
#   ./scripts/deploy-remote.sh user@10.0.1.5 --verify-only   # health + pod status only
#
# Environment:
#   DUVORA_ADMIN_PASSWORD   initial admin password (default Admin@321; applied on first start only)
#   DUVORA_KEYS             optional JSON access/agent keys, stored in the Secret
#   DUVORA_DEMO             1 (default) seeds the fleet simulator with demo devices
#   DUVORA_NETRA            auto (default): connect to Netra when the host runs it in the same
#                           cluster (netra-system/netra + ~/.netra/api-key); off disables
#   DUVORA_NETRA_ENFORCE    1 allows promoting shadow isolation to enforcement (default 0)
#   DUVORA_EBPF_ENFORCE     same as DUVORA_NETRA_ENFORCE
#   DUVORA_AGENT            1 builds the native eBPF agent image and runs it as a DaemonSet,
#                           with a host-bound key per node kept in ~/.duvora/agent-keys.json (default 0)
#   DUVORA_AI_URL, DUVORA_AI_MODEL, DUVORA_AI_KEY, DUVORA_AI_REDACT, DUVORA_AI_ALLOW_HTTP
#                           optional OpenAI-compatible model for the copilot and written explanations
#   DUVORA_SIEM_URL, DUVORA_SIEM_KEY, DUVORA_SIEM_SYSLOG
#                           optional SIEM export (webhook and/or syslog)
#   DUVORA_NOTIFY_URL, DUVORA_NOTIFY_KEY   optional playbook notification webhook
#   DUVORA_REQUIRE_SCAN     1 blocks deploys of images without a passed artifact scan
#   DUVORA_REMOTE_SUBDIR    remote checkout relative to $HOME (default .deployments/duvora)
#   DUVORA_DEPLOY_MAX_DISK_PCT   refuse above this root-disk usage (default 95)
#   DUVORA_DEPLOY_READY_TIMEOUT  seconds to wait for the rollout (default 600)
#
# The console is served over HTTPS with a self-signed certificate generated on the
# host (~/.duvora/tls). duvoractl on the host trusts it through ~/.duvora/env.
# UI/API: https://<host>:30880
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="k3s"
DRY_RUN=false
VERIFY_ONLY=false
TARGET=""
POSITIONAL=()
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)
VERSION="0.5.0"
IMAGE="ghcr.io/zyvorai/duvora:${VERSION}"
AGENT_IMAGE="ghcr.io/zyvorai/duvora-agent:${VERSION}"
PORT=30880

usage() {
  sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --k3s) PROFILE="k3s"; shift ;;
    --k8s) PROFILE="k8s"; shift ;;
    --docker) PROFILE="docker"; shift ;;
    --quick) PROFILE="quick"; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

if [[ ${#POSITIONAL[@]} -eq 1 ]]; then
  TARGET="${POSITIONAL[0]}"
elif [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  if [[ "${POSITIONAL[0]}" == *@* ]]; then
    TARGET="${POSITIONAL[0]}"
  elif [[ "${POSITIONAL[1]}" == *@* ]]; then
    TARGET="${POSITIONAL[1]}"
  else
    TARGET="${POSITIONAL[1]}@${POSITIONAL[0]}"
  fi
fi
if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 user@host [--k3s|--k8s|--docker|--quick] [--dry-run|--verify-only]" >&2
  echo "   or: $0 HOST USER [...]" >&2
  exit 2
fi

ADMIN_PASSWORD="${DUVORA_ADMIN_PASSWORD:-Admin@321}"
KEYS="${DUVORA_KEYS:-}"
DEMO="${DUVORA_DEMO:-1}"
NETRA="${DUVORA_NETRA:-auto}"
NETRA_ENFORCE="${DUVORA_EBPF_ENFORCE:-${DUVORA_NETRA_ENFORCE:-0}}"
AGENT="${DUVORA_AGENT:-0}"
AI_URL="${DUVORA_AI_URL:-}"
AI_MODEL="${DUVORA_AI_MODEL:-}"
AI_KEY="${DUVORA_AI_KEY:-}"
AI_REDACT="${DUVORA_AI_REDACT:-0}"
AI_ALLOW_HTTP="${DUVORA_AI_ALLOW_HTTP:-0}"
SIEM_URL="${DUVORA_SIEM_URL:-}"
SIEM_KEY="${DUVORA_SIEM_KEY:-}"
SIEM_SYSLOG="${DUVORA_SIEM_SYSLOG:-}"
NOTIFY_URL="${DUVORA_NOTIFY_URL:-}"
NOTIFY_KEY="${DUVORA_NOTIFY_KEY:-}"
REQUIRE_SCAN="${DUVORA_REQUIRE_SCAN:-0}"
MAX_DISK="${DUVORA_DEPLOY_MAX_DISK_PCT:-95}"
READY_TIMEOUT="${DUVORA_DEPLOY_READY_TIMEOUT:-600}"
SUBDIR="${DUVORA_REMOTE_SUBDIR:-.deployments/duvora}"

log() { printf '[duvora-deploy] %s\n' "$*"; }
ssh_host() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

if $VERIFY_ONLY; then
  ssh_host 'bash -s' <<EOF
set -euo pipefail
if command -v kubectl >/dev/null 2>&1 && [[ -r "\$HOME/.kube/duvora-k3s.yaml" ]]; then
  KUBECONFIG="\$HOME/.kube/duvora-k3s.yaml" kubectl -n duvora get deploy,svc,pods,pvc || true
fi
for rt in podman docker; do
  command -v \$rt >/dev/null 2>&1 && \$rt ps --filter name=duvora 2>/dev/null || true
done
curl -sf --cacert "\$HOME/.duvora/tls/tls.crt" --resolve "duvora.local:${PORT}:127.0.0.1" "https://duvora.local:${PORT}/healthz" \
  || curl -skf "https://127.0.0.1:${PORT}/healthz"
echo
EOF
  exit 0
fi

# Values are shell-quoted so passwords with spaces or quotes survive the heredoc.
q() { printf '%q' "$1"; }

remote_script=$(cat <<EOF
set -euo pipefail
REMOTE_DIR="\$HOME/${SUBDIR}"
cd "\$REMOTE_DIR"
export PATH="/usr/local/bin:\$HOME/.local/bin:/usr/bin:\$PATH"
PROFILE=$(q "$PROFILE")
IMAGE=$(q "$IMAGE")
PORT=${PORT}
ADMIN_PASSWORD=$(q "$ADMIN_PASSWORD")
KEYS=$(q "$KEYS")
DEMO=$(q "$DEMO")
NETRA=$(q "$NETRA")
NETRA_ENFORCE=$(q "$NETRA_ENFORCE")
AGENT=$(q "$AGENT")
AGENT_IMAGE=$(q "$AGENT_IMAGE")
AI_URL=$(q "$AI_URL")
AI_MODEL=$(q "$AI_MODEL")
AI_KEY=$(q "$AI_KEY")
AI_REDACT=$(q "$AI_REDACT")
AI_ALLOW_HTTP=$(q "$AI_ALLOW_HTTP")
SIEM_URL=$(q "$SIEM_URL")
SIEM_KEY=$(q "$SIEM_KEY")
SIEM_SYSLOG=$(q "$SIEM_SYSLOG")
NOTIFY_URL=$(q "$NOTIFY_URL")
NOTIFY_KEY=$(q "$NOTIFY_KEY")
REQUIRE_SCAN=$(q "$REQUIRE_SCAN")
log() { printf '[duvora-remote] %s\n' "\$*"; }

used=\$(df -P / | awk 'NR==2 {gsub("%","",\$5); print \$5}')
if [[ "\${DUVORA_DEPLOY_SKIP_DISK_CHECK:-0}" != "1" && "\$used" -ge ${MAX_DISK} ]]; then
  echo "root disk is \${used}% full (limit ${MAX_DISK}%): free space or set DUVORA_DEPLOY_SKIP_DISK_CHECK=1" >&2
  exit 1
elif [[ "\$used" -ge 80 ]]; then
  log "warning: root disk is \${used}% full; kubelet image GC starts near 85%"
fi

HOST_IP="\$(hostname -I 2>/dev/null | awk '{print \$1}')"
HOST_IP="\${HOST_IP:-127.0.0.1}"
TLS_DIR="\$HOME/.duvora/tls"
mkdir -p "\$TLS_DIR" && chmod 700 "\$HOME/.duvora" "\$TLS_DIR"
if [[ ! -s "\$TLS_DIR/tls.crt" ]] || ! openssl x509 -in "\$TLS_DIR/tls.crt" -noout -checkend 2592000 >/dev/null 2>&1 \
   || ! openssl x509 -in "\$TLS_DIR/tls.crt" -noout -text | grep -q "IP Address:\$HOST_IP"; then
  log "generating self-signed certificate for \$HOST_IP"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=duvora" \
    -addext "subjectAltName=IP:\$HOST_IP,IP:127.0.0.1,DNS:\$(hostname),DNS:localhost,DNS:duvora.local" \
    -keyout "\$TLS_DIR/tls.key" -out "\$TLS_DIR/tls.crt" 2>/dev/null
  chmod 600 "\$TLS_DIR/tls.key"
fi

runtime=""
if command -v podman >/dev/null 2>&1; then runtime=podman
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then runtime=docker
fi

build_image() {
  if [[ -z "\$runtime" ]]; then
    echo "podman or a working docker is required to build the image" >&2
    exit 1
  fi
  if command -v npm >/dev/null 2>&1; then
    log "building the console on the host (\$(node --version))"
    npm --prefix web ci --no-audit --no-fund
    npm --prefix web run build
    \$runtime build -f Dockerfile.runtime -t "\$IMAGE" .
  else
    log "building with the multi-stage Dockerfile"
    \$runtime build -t "\$IMAGE" .
  fi
}

install_cli() {
  mkdir -p "\$HOME/.local/bin"
  cat > "\$HOME/.local/bin/duvoractl" <<CLIEOF
#!/bin/sh
PYTHONPATH="\$REMOTE_DIR\\\${PYTHONPATH:+:\\\$PYTHONPATH}" exec python3 -m duvora.cli "\\\$@"
CLIEOF
  chmod 755 "\$HOME/.local/bin/duvoractl"
  local env_file="\$HOME/.duvora/env"
  local token_lines=""
  [[ -f "\$env_file" ]] && token_lines="\$(grep -E '^DUVORA_TOKEN(_ID)?=' "\$env_file" || true)"
  {
    echo "# Written by deploy-remote.sh — read automatically by duvoractl."
    echo "DUVORA_URL=https://\$HOST_IP:\$PORT"
    echo "DUVORA_CA_FILE=\$TLS_DIR/tls.crt"
    [[ -n "\$token_lines" ]] && echo "\$token_lines"
  } > "\$env_file"
  chmod 600 "\$env_file"
}

wait_healthy() {
  for _ in \$(seq 1 60); do
    if curl -sf --cacert "\$TLS_DIR/tls.crt" "https://\$HOST_IP:\$PORT/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "Duvora did not answer on https://\$HOST_IP:\$PORT/healthz" >&2
  return 1
}

if [[ "\$PROFILE" == "docker" ]]; then
  [[ "\$AGENT" == 1 ]] && log "note: DUVORA_AGENT=1 needs Kubernetes; on a plain host run duvora-agent --ebpf auto instead"
  build_image
  log "running the container with \$runtime"
  \$runtime rm -f duvora >/dev/null 2>&1 || true
  \$runtime volume create duvora-state >/dev/null 2>&1 || true
  \$runtime volume create duvora-tls >/dev/null 2>&1 || true
  # Copy the certificate into a volume owned by the image's non-root user.
  \$runtime run --rm --user 0 --entrypoint sh -v duvora-tls:/tls -v "\$TLS_DIR:/src:ro" "\$IMAGE" \
    -c 'cp /src/tls.crt /src/tls.key /tls/ && chown 10001:10001 /tls/* && chmod 600 /tls/tls.key'
  env_file="\$(mktemp)"; chmod 600 "\$env_file"
  {
    echo "DUVORA_ADMIN_PASSWORD=\$ADMIN_PASSWORD"
    [[ -n "\$KEYS" ]] && echo "DUVORA_KEYS=\$KEYS"
    echo "DUVORA_DEMO=\$DEMO"
    echo "DUVORA_TLS_CERT=/tls/tls.crt"
    echo "DUVORA_TLS_KEY=/tls/tls.key"
  } > "\$env_file"
  \$runtime run -d --name duvora --restart unless-stopped \
    -p "\$PORT:8787" --env-file "\$env_file" \
    -v duvora-state:/data -v duvora-tls:/tls:ro \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
    "\$IMAGE" >/dev/null
  rm -f "\$env_file"
else
  if [[ "\$PROFILE" == "k3s" ]] && ! command -v k3s >/dev/null 2>&1; then
    log "installing k3s"
    curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 600
  fi
  mkdir -p "\$HOME/.kube"
  if [[ "\$PROFILE" != "k8s" ]]; then
    if [[ ! -r "\$HOME/.kube/duvora-k3s.yaml" ]] || [[ /etc/rancher/k3s/k3s.yaml -nt "\$HOME/.kube/duvora-k3s.yaml" ]]; then
      sudo cat /etc/rancher/k3s/k3s.yaml > "\$HOME/.kube/duvora-k3s.yaml"
      chmod 600 "\$HOME/.kube/duvora-k3s.yaml"
    fi
    export KUBECONFIG="\$HOME/.kube/duvora-k3s.yaml"
  fi
  if ! command -v helm >/dev/null 2>&1; then
    log "installing helm"
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  fi

  import_image() {
    if command -v k3s >/dev/null 2>&1; then
      \$runtime save "\${1:-\$IMAGE}" | sudo k3s ctr images import -
    fi
  }
  ensure_image() {
    # kubelet image GC can drop an imported image before the pod starts.
    local image="\${1:-\$IMAGE}"
    if command -v k3s >/dev/null 2>&1 && [[ -n "\$runtime" ]] && ! sudo k3s ctr images ls -q | grep -qx "docker.io/\$image\\|\$image"; then
      log "\$image missing from containerd; re-importing"
      import_image "\$image"
    fi
  }
  if [[ "\$PROFILE" != "quick" ]]; then
    build_image
    import_image
    if [[ "\$AGENT" == 1 ]]; then
      log "building the native eBPF agent image"
      \$runtime build -f Dockerfile.agent -t "\$AGENT_IMAGE" .
      import_image "\$AGENT_IMAGE"
    fi
  fi
  ensure_image
  [[ "\$AGENT" == 1 ]] && ensure_image "\$AGENT_IMAGE"

  # One host-bound agent key per node, kept across deploys.
  AGENT_KEYS=""
  if [[ "\$AGENT" == 1 ]]; then
    NODES="\$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}')"
    AGENT_KEYS="\$(N="\$NODES" F="\$HOME/.duvora/agent-keys.json" python3 -c 'import json, os, secrets
path = os.environ["F"]
try:
    keys = json.load(open(path))
except (OSError, ValueError):
    keys = {}
for node in os.environ["N"].split():
    keys.setdefault(node, secrets.token_urlsafe(32))
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(keys, f)
print(json.dumps(keys))')"
    log "native eBPF agent on: \$NODES"
  fi

  # Netra in the same cluster: reach it by service name and pin its serving certificate.
  NETRA_URL="" NETRA_KEY="" NETRA_CA=""
  if [[ "\$NETRA" != "off" && -r "\$HOME/.netra/api-key" ]] && kubectl -n netra-system get svc netra >/dev/null 2>&1; then
    svc_port="\$(kubectl -n netra-system get svc netra -o jsonpath='{.spec.ports[0].port}')"
    node_port="\$(kubectl -n netra-system get svc netra -o jsonpath='{.spec.ports[0].nodePort}')"
    # Netra's deploy keeps a stable cert in ~/.netra/tls.crt; older installs mint one per pod start.
    if [[ -s "\$HOME/.netra/tls.crt" ]]; then
      NETRA_CA="\$(cat "\$HOME/.netra/tls.crt")"
    else
      log "warning: ~/.netra/tls.crt missing; pinning the current Netra certificate, which changes when Netra restarts"
      NETRA_CA="\$(echo | openssl s_client -connect "127.0.0.1:\${node_port:-\$svc_port}" -servername netra.netra-system.svc 2>/dev/null | openssl x509 2>/dev/null || true)"
    fi
    if [[ -n "\$NETRA_CA" ]]; then
      NETRA_URL="https://netra.netra-system.svc:\$svc_port"
      NETRA_KEY="\$(cat "\$HOME/.netra/api-key")"
      log "connecting to Netra at \$NETRA_URL (enforcement \$([[ "\$NETRA_ENFORCE" == 1 ]] && echo allowed || echo disabled))"
    else
      log "warning: Netra found but its certificate could not be read; skipping the Netra bridge"
    fi
  fi

  # --set splits on commas, so the password and JSON keys go through a private values file (JSON is YAML).
  VALUES="\$(mktemp)"; chmod 600 "\$VALUES"; trap 'rm -f "\$VALUES"' EXIT
  P="\$ADMIN_PASSWORD" K="\$KEYS" D="\$DEMO" NU="\$NETRA_URL" NK="\$NETRA_KEY" NC="\$NETRA_CA" NE="\$NETRA_ENFORCE" \
  AK="\$AGENT_KEYS" AI="\$AGENT_IMAGE" AU="https://\$HOST_IP:\$PORT" \
  LU="\$AI_URL" LM="\$AI_MODEL" LK="\$AI_KEY" LR="\$AI_REDACT" LH="\$AI_ALLOW_HTTP" \
  SU="\$SIEM_URL" SK="\$SIEM_KEY" SS="\$SIEM_SYSLOG" OU="\$NOTIFY_URL" OK="\$NOTIFY_KEY" RS="\$REQUIRE_SCAN" python3 -c 'import json, os
v = {"auth": {"adminPassword": os.environ["P"], "keys": os.environ["K"]}, "demo": os.environ["D"] == "1",
     "ebpf": {"enforce": os.environ["NE"] == "1"}}
if os.environ["NU"]:
    v["netra"] = {"url": os.environ["NU"], "apiKey": os.environ["NK"], "caCert": os.environ["NC"] + "\\n", "enforce": os.environ["NE"] == "1"}
if os.environ["AK"]:
    repo, tag = os.environ["AI"].rsplit(":", 1)
    # The serving certificate names the host IP, so agents (host network) connect there.
    v["agent"] = {"enabled": True, "keys": json.loads(os.environ["AK"]), "url": os.environ["AU"],
                  "image": {"repository": repo, "tag": tag}}
if os.environ["LU"]:
    v["ai"] = {"url": os.environ["LU"], "model": os.environ["LM"], "key": os.environ["LK"],
               "redact": os.environ["LR"] == "1", "allowHttp": os.environ["LH"] == "1"}
if os.environ["SU"] or os.environ["SS"]:
    v["siem"] = {"url": os.environ["SU"], "key": os.environ["SK"], "syslog": os.environ["SS"]}
if os.environ["OU"]:
    v["notify"] = {"url": os.environ["OU"], "key": os.environ["OK"]}
v["scan"] = {"required": os.environ["RS"] == "1"}
print(json.dumps(v))' > "\$VALUES"
  helm upgrade --install duvora ./helm/duvora \
    --namespace duvora --create-namespace \
    -f "\$VALUES" \
    --set tls.enabled=true \
    --set-file tls.cert="\$TLS_DIR/tls.crt" \
    --set-file tls.key="\$TLS_DIR/tls.key" \
    --set image.repository="\${IMAGE%:*}" \
    --set image.tag="\${IMAGE##*:}" \
    --set service.type=NodePort \
    --set service.nodePort=\$PORT \
    --wait --timeout 300s

  # The tag is fixed, so the pod template does not change between builds; restart so
  # the freshly imported image is what runs, then wait for the rollout to complete.
  ensure_image
  kubectl -n duvora rollout restart deployment/duvora
  if ! kubectl -n duvora rollout status deployment/duvora --timeout=${READY_TIMEOUT}s; then
    kubectl -n duvora get pods -o wide >&2
    kubectl -n duvora describe pods >&2 || true
    exit 1
  fi
  if [[ "\$AGENT" == 1 ]]; then
    ensure_image "\$AGENT_IMAGE"
    kubectl -n duvora rollout restart daemonset/duvora-agent
    if ! kubectl -n duvora rollout status daemonset/duvora-agent --timeout=180s; then
      log "agent rollout stalled; re-checking its image and retrying once"
      ensure_image "\$AGENT_IMAGE"
      kubectl -n duvora delete pod -l app.kubernetes.io/component=agent --wait=false
      kubectl -n duvora rollout status daemonset/duvora-agent --timeout=\${READY_TIMEOUT}s || kubectl -n duvora logs -l app.kubernetes.io/component=agent --tail=30 >&2
    fi
  fi
fi

install_cli
wait_healthy
echo
echo "Duvora ready: https://\$HOST_IP:\$PORT"
echo "Sign in as admin (password from DUVORA_ADMIN_PASSWORD; default Admin@321 — change it under Govern → Users)."
echo "CLI on this host: duvoractl login && duvoractl status"
EOF
)

if $DRY_RUN; then
  log "dry-run (${PROFILE}) remote script:"
  echo "$remote_script"
  exit 0
fi

REMOTE_HOME="$(ssh_host 'printf %s "$HOME"')"
REMOTE_DIR="${REMOTE_HOME}/${SUBDIR}"
log "sync → ${TARGET}:${REMOTE_DIR}"
ssh_host "mkdir -p $(q "$REMOTE_DIR")"
rsync -az --delete \
  --exclude '.git' --exclude 'web/node_modules' --exclude '__pycache__' --exclude '*.db' --exclude '*.db-*' \
  --exclude '.DS_Store' --exclude '.cursor' --exclude 'test-results' --exclude 'dist' --exclude '.env' --exclude 'keys.json' \
  "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"

ssh_host 'bash -s' <<<"$remote_script"
log "done — open https://<host>:${PORT} and sign in as admin"
