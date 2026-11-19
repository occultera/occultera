# Public demo (demo.occultera.dev)

A read-only Occultera with synthetic data that anyone can open without a password. It needs the code after 0.15.0
(`WDT_PUBLIC_DEMO`); use the first release that contains it.

What makes it safe to publish:

- `WDT_DEMO=true`: synthetic alerts and vulnerabilities in memory, no Wazuh, no indexer, `LLM_PROVIDER=mock` (no model,
  no API key). Nothing is stored; a restart resets everything.
- `WDT_PUBLIC_DEMO=true`: every visitor is a **viewer** — reads everything, changes nothing (no runs, no decisions,
  no settings). The switch is ignored unless `WDT_DEMO=true`, so it cannot open a real installation.
- `APP_PASSWORD` is a long random value nobody needs; `MCP_TOKEN` and every notification channel stay empty.
- The container runs non-root, with a read-only root filesystem and no capabilities.

## Option A — any Docker host + Cloudflare Tunnel (no open port)

1. Cloudflare dashboard → Zero Trust → Networks → Tunnels → *Create a tunnel* (cloudflared), name `occultera-demo`.
   Public hostname: `demo.occultera.dev` → service `http://occultera-demo:8080`. Copy the tunnel token.
2. On the host:

   ```sh
   cd deploy/demo
   printf 'TUNNEL_TOKEN=%s\nAPP_PASSWORD=%s\nAPP_SECRET=%s\n' "<tunnel token>" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
   docker compose up -d
   ```

3. Reset the data every night (optional; a restart is the reset):

   ```sh
   (crontab -l 2>/dev/null; echo '17 3 * * * cd /path/to/deploy/demo && docker compose restart occultera-demo') | crontab -
   ```

## Option B — Kubernetes

```sh
kubectl create namespace occultera-demo
kubectl -n occultera-demo create secret generic occultera-secret \
  --from-literal=APP_PASSWORD="$(openssl rand -hex 32)" --from-literal=APP_SECRET="$(openssl rand -hex 32)"
kubectl apply -k deploy/demo/kubernetes
```

Expose the `occultera` Service in the `occultera-demo` namespace on `demo.occultera.dev` with your ingress (or a Cloudflare Tunnel in the
cluster). The CronJob in the overlay restarts the `occultera` Deployment at 03:17 UTC to reset the data.

## In front of it (Cloudflare)

- A rate-limiting rule for `demo.occultera.dev`, e.g. 120 requests per minute per IP.
- Caching off for the host (the pages are per visitor).
- After it is live, build the website with `DEMO_URL=https://demo.occultera.dev/ python3 src/build.py` so the
  “Live demo” buttons appear.
