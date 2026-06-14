# Recalibrate the "Cert rotated late" trigger

**Date:** 2026-06-14
**Template:** `web-service-by-itforprof` → bump `7.0-2.2.9` → **`7.0-2.3.0`**
**web_check.py:** unchanged

## Problem

The trigger **`Cert rotated unexpectedly (was about to expire)`** (template trigger,
severity **HIGH**) fires when:

```
change(cert.fingerprint_sha256)=1 and max(cert.days_to_expire, 2h:now-15m) < {$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}   # default 14
```

i.e. a cert rotated while the *outgoing* cert had fewer than 14 days left. Its
premise — "your renewal automation is running dangerously late, go fix it" — is
only actionable when **we** own the renewal (our own certbot). On
**hosting-provider-managed** sites we do not control the renewal cadence; a
provider that habitually renews at ~10 days out trips this every ~60–90 days for
something we cannot act on.

The noise is amplified by automation: HIGH events auto-create Planfix tickets.
Confirmed against the live Zabbix actions — the enabled ticketing actions fire at
**Average (3) and above**:

| Action | Severity threshold |
|--------|--------------------|
| 89 `PlanFix \| Report average`  | Average  |
| 88 `PlanFix \| Report high`     | High     |
| 87 `PlanFix \| Report disaster` | Disaster |

WARNING (2) and below do **not** create tickets (the "warning to all" / "warning
to GLPI" actions are disabled). Real example: event 20485659 on `millystyle.ru`
spawned Planfix task 28223.

## Key insight

By the time this trigger fires, **a fresh cert is already installed** — there is
no active outage. It is a *retrospective near-miss / hygiene* signal, and the
genuine outage risk (cert actually lapses) is already covered by the separate
cert-expiry triggers (`CRIT_DAYS=7` HIGH, `days_to_expire<0`). HIGH + auto-ticket
overstates a near-miss.

## Decision (scope: soften globally)

Two global template changes. No per-host work — verified there are **no per-host
overrides** of the macro (the only `usermacro.get` hits, hostid 14003 on prod /
10690 on myzabbix, are the *template's own* macro definition).

| | Before | After |
|---|---|---|
| Trigger severity | `HIGH` (4) → auto-tickets | `WARNING` (2) → no Planfix ticket (below Average threshold) |

> **Caveat — group-scoped WARNING-floor actions still notify.** The Planfix
> actions (87/88/89) gate at Average+, so WARNING removes ticketing for the
> general fleet (groups 20/31/166). But one linked host, `avs.itforprof.ru`
> (11513), is in group **17 (AVAKS)**, which is matched by the enabled action
> **82 `AVAKS Report warning-disaster problems to ZNT`** at severity **≥ WARNING**.
> That host therefore keeps notifying ZNT after the downgrade (it already did at
> HIGH — no new noise, but not silenced either). True silence for AVAKS, if
> wanted, is a separate decision: per-host trigger-severity override, an action
> exclusion, or maintenance — out of scope here and intentionally not touched.
| `{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}` default | `14` | `3` |

**Why WARNING:** drops below the Average ticket threshold, killing the auto-ticket
noise, while keeping the problem visible on the dashboard. Justified because the
event is a near-miss, not an active outage.

**Why 3 days (not 7, not 14):** the user wants maximum quiet. At `<3` the trigger
fires only on a genuinely alarming last-minute rotation. For self-managed hosts a
sub-3-day rotation is still a real "certbot is broken" signal worth a glance; for
provider hosts it is a rare, ignorable WARNING.

## Edits (all in `templates/web-service-by-itforprof/template_web_service_by_itforprof_com.yaml`)

1. Trigger `Cert rotated unexpectedly (was about to expire)`: `priority: HIGH` → `priority: WARNING`.
2. Macro `{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}`: value `'14'` → `'3'`; reword its
   description to drop the "HIGH" wording and state the new 3-day / near-miss intent.
3. Reword the trigger `description`: replace "dangerously late … brief outage
   window" with near-miss framing; note the active-outage risk lives in the
   expiry triggers. Keep the `max(…,2h:now-15m)` mechanism explanation intact.
4. Bump template `version` field (line ~43): `7.0-2.2.9` → `7.0-2.3.0`.
5. `CHANGELOG.md`: add a `## [7.0-2.3.0]` entry under **Changed**.

## Rollout

- Re-import the template to **both** Zabbix servers (`production` and `myzabbix`).
- The severity change and the macro-default change propagate automatically to all
  linked host triggers (e.g. trigger 96541 on `millystyle.ru`) — no host edits.
- Existing **open** problems from the old HIGH trigger are not retroactively
  re-rated by Zabbix; they can be closed manually (the trigger is `manual_close`).
  New events fire at WARNING.

## Out of scope

- Per-host opt-out ergonomics (rejected: user chose "soften globally").
- Touching the cert-expiry triggers or `web_check.py`.
- Any change to the plain INFO `Cert rotated` trigger.

## Testing / verification

- `yamllint` / template re-import dry-run (`configuration_import` with
  `createMissing`/`updateExisting`) parses without error on both servers.
- Post-import: `trigger.get` on a sample host trigger confirms `priority=2` and
  the expanded expression shows `< 3`.
- CHANGELOG + version string consistent.
