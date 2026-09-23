<div align="center">
  <img src="https://raw.githubusercontent.com/Gryt-chat/client/main/public/logo.svg" width="80" alt="Gryt logo" />
  <h1>Gryt Auth</h1>
  <p>Keycloak-based authentication for <a href="https://github.com/Gryt-chat/gryt">Gryt</a>, the voice, video and text chat platform.<br />One identity across every Gryt server, with token-based auth.</p>
</div>

<br />

> **This repository is open source for transparency — you aren't expected to host this yourself.**

## Why one central auth service

Gryt uses a single auth service at **auth.gryt.chat**, and everyone
authenticates through it whatever server they connect to. If anyone could run
their own, they could mint an identity claiming to be anyone else, so the
identities would stop meaning anything.

For a server host that means no auth setup: your server validates tokens against
`auth.gryt.chat`. For a user it means signing up once and being the same person
on every Gryt server. For a contributor it means this repo is here to be audited,
and the development setup below is only needed if you're working on auth
itself.

## Overview

| Component | Description |
|-----------|-------------|
| **Keycloak** | Identity provider with custom Gryt realm and themes |
| **Identity** | Certificate authority that binds Keycloak identities to client public keys ([details](identity/README.md)) |
| **HAProxy** | Reverse proxy for production TLS termination |
| **Bootstrap** | One-shot containers that bring a fresh Keycloak into a usable state ([details](#bootstrap)) |
| **Ops** | Backup, off-site copy and restore tooling for the Postgres database |

## Development setup

> Only needed if you're contributing to the auth service itself.

```bash
cp .env.example .env
./up.sh
```

Starts a local Keycloak instance via Docker Compose — completely separate from production.

## Bootstrap

Five one-shot containers run around the Keycloak server, in this order. All of them
exit immediately and are safe to re-run.

| Service | What it does |
|---------|--------------|
| `keycloak-pre-import-backup` | Dumps Postgres to `./backups` before an import can overwrite anything. Only when `GRYT_IMPORT_REALM=1`. |
| `keycloak-import` | Imports `realm/gryt-realm.json`, substituting SMTP settings. Only when `GRYT_IMPORT_REALM=1`. **`--override true` deletes the realm first — every user in it goes too.** Refuses to run while Keycloak is up; stop it first. |
| `keycloak-bootstrap-admin` | Creates the master-realm admin if there isn't one. |
| `keycloak-user-profile` | Applies `bootstrap/gryt-user-profile.json` through the admin API, once the server is up. |
| `keycloak-security-policy` | Turns on brute-force protection and a password policy, through the admin API. |

Two things about this are worth knowing before you change any of it.

**The import is an offline operation.** `kc.sh import` rewrites the database directly, and a
running Keycloak goes on holding the realm id it started with — so importing underneath one
leaves it serving 500s until it's restarted, with every user in the realm already gone. It's
easy to do by accident, because `docker compose up -d` re-runs a one-shot whose config changed
without restarting `keycloak`, whose own definition didn't. `import_realm.sh` checks for a
listening server and refuses. To import deliberately:

```bash
docker compose -f docker-compose.keycloak.yml stop keycloak
docker compose -f docker-compose.keycloak.yml up -d
```

**The admin isn't created by `KC_BOOTSTRAP_ADMIN_*` alone.** Keycloak only does that
when `start` finds no master realm, and `keycloak-import` creates master as a side
effect of running first. On a genuinely fresh database that left a deployment with no
administrator at all, which is why `keycloak-bootstrap-admin` exists.

**The user profile has to go through the admin API.** A `userProfile` block in the
realm JSON is rejected on import and takes the whole stack down. Without the profile,
the realm falls back to Keycloak's built-in one, which requires `firstName` and
`lastName` — and since the realm sets `registrationEmailAsUsername` and the login theme
hides both fields, registration then fails on inputs nobody can see.

`bootstrap/gryt-user-profile.json` is the source of truth for what registration
collects. Editing the profile in the admin console works until the next time this runs.
`docker compose up -d` won't re-run a one-shot that has already exited, so
after a realm import you need `up.sh`, or:

```bash
docker compose -f docker-compose.keycloak.yml up -d --force-recreate --no-deps keycloak-user-profile
```

**Login hardening is not in the realm file either.** `gryt-realm.json` sets no
`bruteForceProtected`, no `failureFactor` and no `passwordPolicy`, so a stack brought up
without `keycloak-security-policy` accepts unlimited login attempts against any account
and whatever password a user picks. It runs through the admin API for the same reason the
user profile does, and it re-runs the same way:

```bash
docker compose -f docker-compose.keycloak.yml up -d --force-recreate --no-deps keycloak-security-policy
```

The password policy is checked when a password is set, never when one is used, so turning
it on locks nobody out — existing passwords keep working until they are next changed.
Lockouts are temporary rather than permanent, because a permanent one hands anybody who
knows an email address a way to lock its owner out.

### What stops a bot registering

Most of it isn't in this repository.

**A Cloudflare Managed Challenge on the registration path** (GRYT-782). It judges the
browser and the address it comes from, so it turns away crude automation. Someone driving a
real browser through a residential proxy gets past it.

**Email verification.** `verifyEmail` is on, so every account needs a mailbox somebody can
read. That forces an attacker onto a throwaway-mail service or a domain they own. It's also
why blocking throwaway domains would help here.

**Brute-force protection** is about guessing a password, not making an account.
`apply_security_policy.sh` turns it on, and it does nothing for registration.

**No captcha inside the Keycloak flow, and that's deliberate.** Keycloak 26.5.3 ships two
captcha authenticators and both are Google's — `RegistrationRecaptcha` has
`/recaptcha/api/siteverify` written into it, with no way to point it somewhere else. So
Turnstile needs a Java authenticator rather than a setting. That's GRYT-790, and we haven't
built it on purpose. Google's would work today, and it would hand Google every registration.

If you do add one, both halves are things you do in the admin console, and a realm import
with `--override true` wipes them. Check them again afterwards.

#### The gap

Nothing rate-limits registration. Brute-force protection only covers logging in, and a
Managed Challenge weighs reputation rather than volume. So nothing stops a slow trickle from
ordinary-looking addresses. Fixing that means a Cloudflare rate-limiting rule on the
registration path, not a change in here.

## Applying settings against a running Keycloak

`apply_security_policy.sh` and `apply_user_profile.sh` both need an admin token. On
gryt.chat the master-realm `admin` account is **disabled on purpose**, so both fail with
`invalid_grant / Account disabled`.

**Do not enable it with SQL.** `UPDATE user_entity SET enabled=true` writes a row Keycloak
is not reading — users are cached, so the token endpoint keeps refusing until Keycloak
restarts, and the re-disable afterwards needs a second restart. That is two auth outages
for a config change. It was done that way on 2026-09-08 before anybody found the
alternative.

Make a temporary admin instead. It needs no restart, and `admin` stays disabled:

```bash
docker exec -e PW='<pick one>' -e KC_HTTP_MANAGEMENT_PORT=9999 gryt-auth-keycloak \
  /opt/keycloak/bin/kc.sh bootstrap-admin user \
  --username tmpadmin --password:env PW --no-prompt
```

`KC_HTTP_MANAGEMENT_PORT` is not optional on this deployment. `bootstrap-admin` starts its
own Keycloak runtime, which tries to bind the management port — and `KC_HEALTH_ENABLED` means
the running server already holds 9000. Without the override it exits with `Unable to start
the management interface on 0.0.0.0:9000 / Address already in use`, and the caller sees only
a missing token. Any port nothing else is using will do.

Run the one-shot as that user:

```bash
docker compose -f docker-compose.keycloak.yml run --rm --no-deps -T \
  -e GRYT_KEYCLOAK_ADMIN_USERNAME=tmpadmin \
  -e GRYT_KEYCLOAK_ADMIN_PASSWORD='<the same one>' \
  keycloak-security-policy
```

Then delete it. It is a real admin until you do:

```bash
KC=http://keycloak:8080
CURL="docker run --rm --network auth_gryt-auth-network curlimages/curl:8.11.1 -s"
TOKEN=$($CURL -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password \
  --data-urlencode "username=tmpadmin" --data-urlencode "password=<the same one>" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
TID=$($CURL "$KC/admin/realms/master/users?username=tmpadmin" \
  -H "Authorization: Bearer $TOKEN" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
$CURL -o /dev/null -w '%{http_code}\n' -X DELETE \
  "$KC/admin/realms/master/users/$TID" -H "Authorization: Bearer $TOKEN"
```

Wants `204`. The curl runs in a container because the Keycloak image has no curl.

Verified on Keycloak 26.5.3 against Postgres: created, used to apply the full policy,
deleted, and `admin` answered `Account disabled` throughout. It does not work on the H2
dev database — `bootstrap-admin` opens its own JDBC connection and H2 locks the file.

The port collision was missed the first time this was written because the local Keycloak it
was tested against had no management port set. It failed on the first real use.

The script names both failures now rather than retrying ten times and giving up:
`Account disabled` prints these steps, and a wrong password says so and stops. Neither
retries, because neither gets better on the second attempt.

## Monitoring and alerts

Prometheus scrapes Keycloak and Postgres, Grafana draws it, and Alertmanager emails
`GRYT_ALERT_EMAIL` when a rule fires. Grafana is the only one with a public address:

| | Where | Public |
|---|---|---|
| Grafana | [monitoring.gryt.chat](https://monitoring.gryt.chat) | yes |
| Prometheus | `127.0.0.1:19090` on the box | no |
| Alertmanager | `127.0.0.1:19093` on the box | no |

**The "View in Alertmanager" link in an alert email points at `http://localhost:19093`.**
That is deliberate. Alertmanager has no public route, and without `--web.external-url` it
advertises its own container id instead — `http://8d18958c298e:9093`, which resolves
nowhere at all.

To make that link work, open a tunnel first and leave it running:

```bash
ssh -N -L 19093:127.0.0.1:19093 edition35
```

Then the URL in the email opens the real Alertmanager. Same shape for Prometheus on 19090
if you want to check why a rule fired.

Most alerts do not need any of that. The email carries the summary, the description and
every label, and the auth dashboard on monitoring.gryt.chat covers the rest. The tunnel is
for silencing an alert or reading its history.

To prove the whole path still works without waiting for something to break:

```bash
ssh edition35 'docker run --rm --network auth_gryt-auth-network curlimages/curl:8.11.1 \
  -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" \
  -d "[{\"labels\":{\"alertname\":\"DeliveryTest\"},\"annotations\":{\"summary\":\"Ignore me\"}}]" \
  http://alertmanager:9093/api/v2/alerts'
```

It sends within `group_wait`, 30 seconds. Check it landed with
`alertmanager_notifications_total{integration="email"}` on the Alertmanager metrics
endpoint; it was 0 until the first deliberate test on 2026-09-08, which is how long that
last hop went unproven.

## Backups

`pg-backup` dumps Postgres every six hours to `GRYT_AUTH_BACKUP_DIR`, keeps 30 days, and
prunes only after a dump it's checked. On dev that directory is a CIFS mount from the NAS,
so the dumps are already off the disk the database lives on.

They're still in the same building. A fire, a theft or ransomware on the LAN takes the
database and all 126 backups together, and every Gryt account with them.

### One copy out of the building

`ops/offsite_backup.sh` runs once a day on dev, from `gryt-offsite-backup.timer`. For every
dump that isn't on the far end yet, it encrypts to an age recipient and sends it over ssh.
Then it asks the far end to prune its own window. The far end is the Gigahost VPS: dev
already reaches it by key, and it has 33 GB free against 17 MB of dumps.

Retention there is 90 days against 30 on dev. It's set in `ops/offsite_receive.sh` rather
than passed in, so nothing on dev can shorten it.

**The dumps are encrypted before they leave.** Since GRYT-783 a Keycloak dump carries every
account's sealed message-key blob alongside its credentials, so a copy of one is worth
stealing.

age rather than GPG. The private key is one line, so it goes into a password manager as it
is and comes back out when you need it. There's no keyring on dev to drift. Decrypting is
`age -d -i` on any machine that has the binary, where GPG wants a `gpg --import` into a
trust store first. What GPG has going for it is that dev already has it and age has to be
installed.

Somebody who takes the VPS gets the encrypted bytes and the file names. The names say when
each dump was taken and roughly how big the database is. They can't decrypt any of it: the
private half is in a password manager and on neither machine, so no accounts, no password
hashes, no message keys, no client secrets. They can delete the copies, because by then the
box is theirs. So this covers losing the building, and nothing else.

The key dev holds is pinned to `ops/offsite_receive.sh` as a forced command, so it can't
open a shell there. It has three verbs: list, put and prune. `put` refuses a name that
isn't a dump name, refuses to overwrite a file that's already there, and checks the sha256
it was promised before it names the file. A dev that's been taken over can add copies. It
can't replace or read back what's already on the VPS.

### How you find out it stopped

Every failure exits non-zero, so the unit sits in `systemctl --failed` with the reason in
`journalctl -u gryt-offsite-backup`. Set `GRYT_OFFSITE_ALERT_WEBHOOK` and it posts to
Discord as well. Without it, somebody has to go and look.

A run that uploads nothing is still a failure. After the uploads the script re-reads the far
end and fails if the newest scheduled dump there is more than `GRYT_OFFSITE_STALE_HOURS`
old. That covers the dumper on dev dying while the copy step carries on working fine.

**The timer never firing isn't covered.** Nothing outside the house is watching for silence.
A box that's off, a disabled unit and a revoked key all look like a quiet week. GRYT-1401
covers that.

### Restoring one

Run it once before you need it. These commands were run on 2026-09-23 against a real dump.

```bash
ssh vps 'sudo ls -1 /home/gryt-backup/keycloak | tail -5'
ssh vps 'sudo cat /home/gryt-backup/keycloak/keycloak-<timestamp>.sql.gz.age' > keycloak.sql.gz.age

age -d -i keycloak-offsite.key -o keycloak.sql.gz keycloak.sql.gz.age
gzip -t keycloak.sql.gz

docker run -d --name restore-test -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak \
  -e POSTGRES_PASSWORD=restore_test_password postgres:16-alpine
gzip -dc keycloak.sql.gz | docker exec -i restore-test psql -q -U keycloak -d keycloak
docker exec restore-test psql -U keycloak -d keycloak -c 'select name, enabled from realm;'
docker rm -f restore-test
```

`keycloak-offsite.key` is the private half, pasted out of the password manager into a file
for as long as the restore takes. `ops/pg_restore_smoketest.sh` does the container half of
this on a plain `.sql.gz` if you want it scripted.

Stop Keycloak before putting a dump back into the real stack. A restore rewrites the
database underneath a server that goes on holding the realm id it started with, the same
way `kc.sh import` does.

### Setting it up

One-time, in this order. The account on the VPS needs a real shell, because sshd runs a
forced command through it and `nologin` would refuse.

```bash
# 1. On your machine. Put the file in the password manager, then delete it.
#    Keep the age1... line it prints; step 7 needs it.
age-keygen -o keycloak-offsite.key

# 2. Bring the checkout on dev up to date and install age.
ssh edition35 'cd /home/sivert/gryt/packages/auth && git pull \
  && sudo apt-get update && sudo apt-get install -y age'

# 3. A key on dev for this job and nothing else. Prints the public half.
ssh edition35 'sudo ssh-keygen -t ed25519 -N "" -C gryt-offsite \
  -f /root/.ssh/id_ed25519_gryt_offsite && sudo cat /root/.ssh/id_ed25519_gryt_offsite.pub'

# 4. Teach dev the VPS host key, so BatchMode ssh doesn't stop to ask.
ssh edition35 'sudo ssh-keyscan -H 193.200.238.156 | sudo tee -a /root/.ssh/known_hosts'

# 5. The account and the directory on the VPS.
ssh vps 'sudo useradd -m -s /bin/sh gryt-backup \
  && sudo -u gryt-backup mkdir -p /home/gryt-backup/keycloak /home/gryt-backup/.ssh \
  && sudo -u gryt-backup chmod 700 /home/gryt-backup/.ssh'

# 6. The receiver, and the key from step 3 pinned to it. Paste that ssh-ed25519
#    line in place of KEY below.
ssh edition35 'cat /home/sivert/gryt/packages/auth/ops/offsite_receive.sh' \
  | ssh vps 'sudo mkdir -p /usr/local/lib/gryt \
    && sudo tee /usr/local/lib/gryt/offsite_receive.sh >/dev/null \
    && sudo chmod 755 /usr/local/lib/gryt/offsite_receive.sh'

ssh vps 'sudo -u gryt-backup tee -a /home/gryt-backup/.ssh/authorized_keys >/dev/null \
  && sudo -u gryt-backup chmod 600 /home/gryt-backup/.ssh/authorized_keys' <<'EOF'
restrict,command="/bin/sh /usr/local/lib/gryt/offsite_receive.sh" KEY
EOF

# 7. The settings on dev. Put the age1... line from step 1 in place of RECIPIENT.
ssh edition35 'sudo tee /etc/default/gryt-offsite-backup >/dev/null \
  && sudo chmod 600 /etc/default/gryt-offsite-backup' <<'EOF'
GRYT_AUTH_BACKUP_DIR=/mnt/gryt-backups/keycloak
GRYT_OFFSITE_HOST=gryt-backup@193.200.238.156
GRYT_OFFSITE_RECIPIENT=RECIPIENT
GRYT_OFFSITE_SSH_KEY=/root/.ssh/id_ed25519_gryt_offsite
EOF

# 8. The timer, and one run now. The first run sends the whole local window.
ssh edition35 'sudo ln -sf /home/sivert/gryt/packages/auth/ops/offsite_backup.sh \
    /usr/local/bin/gryt-offsite-backup \
  && sudo cp /home/sivert/gryt/packages/auth/ops/systemd/gryt-offsite-backup.service \
    /home/sivert/gryt/packages/auth/ops/systemd/gryt-offsite-backup.timer /etc/systemd/system/ \
  && sudo systemctl daemon-reload \
  && sudo systemctl enable --now gryt-offsite-backup.timer \
  && sudo systemctl start gryt-offsite-backup.service \
  && sudo journalctl -u gryt-offsite-backup -n 20 --no-pager'

# 9. Check it landed.
ssh edition35 'sudo systemctl list-timers gryt-offsite-backup --no-pager'
ssh vps 'sudo ls -1 /home/gryt-backup/keycloak | wc -l'
```

## Themes

Three of them, and they are built three different ways because they are three different
kinds of page.

| Theme | Where it lives | How it is built |
|-------|----------------|-----------------|
| **login** | `login-theme/` | Keycloakify, compiled into a jar. Real React, built from `@gryt/ui` so the sign-in page and the client share components rather than a look. |
| **email** | `themes/gryt/email/` | Hand-written FreeMarker. Works, and Keycloakify's email support is a separate job. |
| **account** | `themes/gryt/account/` | Keycloak's own console with Gryt's palette on it. |

The account theme is the odd one, so here is why it is not a Keycloakify theme like the
login one. `@keycloakify/keycloak-account-ui` peers on React 18 and PatternFly 5, and
`login-theme/` is on React 19 — and every published line of that package wants React 18,
including the one built for Keycloak 26.7, so a Keycloak upgrade would not resolve it.

Painting the console we already serve turned out to be the better trade anyway. Every colour
in PatternFly resolves from one table of custom properties, so remapping that table is the
whole theme: no component is restyled, and a Keycloak upgrade that changes a component
cannot break it. `themes/gryt/account/resources/css/account.css` is that table, and its
palette comes from `@gryt/ui` through `npm run account-tokens` rather than being restated.

The console is dark whatever the browser is set to, matching the login page it is reached
from.

**Changing `accountTheme` in `realm/gryt-realm.json` does not change a running Keycloak.**
Realm JSON is read on a fresh import only. On a server that is already up, set it in the
admin console under Realm settings → Themes, or with `kcadm.sh update realms/gryt -s
accountTheme=gryt`.

## Documentation

See the [architecture overview](https://docs.gryt.chat/docs/guide/architecture) for how auth fits into the Gryt platform.

## Issues

Please report bugs and request features in the [main Gryt repository](https://github.com/Gryt-chat/gryt/issues).

## Sponsors

What sponsoring pays for, the tiers, and everyone who has sponsored:
[gryt.chat/sponsors](https://gryt.chat/sponsors). To sponsor:
[GitHub Sponsors](https://github.com/sponsors/Gryt-chat).

The list itself lives in the [Gryt README](https://github.com/Gryt-chat/gryt#sponsors),
in one place rather than ten, so it cannot fall out of step across repositories.

## License

[AGPL-3.0](https://github.com/Gryt-chat/gryt/blob/main/LICENSE) — Part of [Gryt](https://github.com/Gryt-chat/gryt)
