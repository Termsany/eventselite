# Elite Events OS — Medical Event Operations

Internal Arabic-first web app for Elite Skin's medical events. Real SQLite storage for events, doctors, invitations, vendors, tasks, agenda; live check-in updates (refresh to sync), reports, user login.

## Quick start: local
Requires Python 3.11+. `pip install -r requirements.txt`. Create `.env` based on `.env.example`. Set a **strong** admin password and random 32+ character session secret. Example:

```bash
export ADMIN_USER=admin
export ADMIN_PASSWORD='A-unique-strong-password-CHANGE-ME'
export SESSION_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export COOKIE_SECURE=0   # only for local http:// testing; set to 1 on HTTPS VPS
uvicorn app:app --host 127.0.0.1 --port 8000
```
Visit http://127.0.0.1:8000 and sign in.

## VPS deployment (Ubuntu 22.04/24.04)
1. Point a domain `events.yourdomain.com` to the VPS public IP (A record).
2. Install Docker Engine, Docker Compose plugin, Nginx and Certbot using official Ubuntu / Docker instructions.
3. Upload this project to `/opt/elite-events-os`, `cd /opt/elite-events-os`, copy `.env.example` to `.env` and set `ADMIN_PASSWORD`, `SESSION_SECRET`, `COOKIE_SECURE=1` with safe random values. Never commit `.env` to git.
4. Run `mkdir -p data && sudo chown -R 10001:10001 data && docker compose up -d --build`.
5. Copy `deploy/nginx.conf.example` to `/etc/nginx/sites-available/elite-events`, replace `events.example.com` with your actual domain; enable the site and run `sudo nginx -t && sudo systemctl reload nginx`.
6. Set up HTTPS: `sudo certbot --nginx -d events.yourdomain.com` and verify renewal.
7. Login at `https://events.yourdomain.com`; backup `data/events.sqlite3` using SQLite `.backup` (not naïve file copy while DB is in use).

## Security / scope
- Prototype release: one administrator account from environment; not yet multi-user RBAC, audit trails, SMS/WhatsApp, uploads, vendor integrations or actual email delivery.
- Do not load real doctor phone numbers before establishing your company's privacy, consent and authorized-access workflow.
- Use HTTPS, firewall (80/443 only externally), secure password, restricted VPS access, monitoring and encrypted backups.
- SQLite suits a small internal starter deployment. For a larger concurrent team: migrate to PostgreSQL, add per-employee authentication/RBAC and audit logging.
- Direct browser calls only; data is NOT stored only in the browser.
