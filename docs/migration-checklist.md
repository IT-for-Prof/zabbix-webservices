# Migration checklist: from `Template Website metrics (itmicus.ru)` to `Web service by itforprof.com`

Phased rollout per `architecture.md §"Migration plan"`. Reversible at any
step until the legacy template is unlinked.

## Pre-deploy (per monitor node)

- [ ] Install `web_check.py` + venv on each Zabbix server/proxy that monitors
      web hosts:
      ```
      curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-webservices/main/scripts/deploy/install.sh | sudo sh
      ```
      Current target nodes: `mon.itforprof.com`, `ET-VPS01`, `SR-VPS01-PROXY`,
      `IFP-VPS12-PROXY`, `IFP-VPS15-PROXY`.
- [ ] Smoke test:
      `sudo -u zabbix /usr/lib/zabbix/externalscripts/web_check.py self-test`
      must exit 0 and report `cache roundtrip: ok` on each node.
- [ ] Import the template YAML in Zabbix UI (Configuration → Templates → Import):
      `templates/web-service-by-itforprof/template_web_service_by_itforprof_com.yaml`.

## Inventory check

- [ ] `scripts/migrate-from-itmicus.py --list` — enumerate every host
      currently linked to the legacy template and review the planned actions.
- [ ] Confirm each host has `{$WEBSITE_METRICS_URL}` set; hosts without it
      get a no-op (and won't have `{$WEB_SERVICE.HOST}` derived either —
      they'll need it set manually before linking).
- [ ] Note hosts where the legacy `{$WEBSITE_METRICS_TIMEOUT}` deviates from
      the new template's default `{$WEB_SERVICE.TIMEOUT}=15` — those values
      carry over via the migration script.
- [ ] Review per-host `{$WEBSITE_METRICS_PHRASE}` values for regex
      metacharacters (`.`, `(`, `[`, `|`). Zabbix Web Scenarios treat the
      `required` field as PCRE; escape if literal matching was intended.

## Pilot (2 hosts, 24h parallel run)

- [ ] Pick `mon.itforprof.com` (server-monitored) and `eurotrade-group.ru`
      (proxy-monitored via ET-VPS01).
- [ ] `scripts/migrate-from-itmicus.py --only mon.itforprof.com --only eurotrade-group.ru --apply --keep-old`
      — links the new template alongside the legacy one and translates macros
      (including the derived `{$WEB_SERVICE.HOST}` for Layer 4 diag).
- [ ] Wait 24 hours.
- [ ] Compare each pair:
      - `web_check.cert.days_to_expire` vs legacy `website_metrics.ssl.daystoexpire`
      - `web_check.whois.days_to_expire` vs legacy `domain.daystoexpire`
        (if the legacy template was producing it)
      - `web_check.cert.chain_status="ok"` vs legacy `website_metrics.ssl.status=1`
      - `web.test.fail[Web service]=0` vs legacy `website_metrics.test.status=1`
- [ ] Investigate any systematic divergence; fix or document before
      proceeding.

## Tenant-by-tenant rollout

Order recommended in architecture.md: EUROTRADE → SeaRegion → IFP →
ARC/NORD/AVAKS/EXTRO. 12-hour soak between batches.

- [ ] Per tenant: `scripts/migrate-from-itmicus.py --only <host1> --only <host2> ... --apply --keep-old`
      (still keeping the legacy template alongside).
- [ ] Watch for any "Cert/WHOIS check failing" or NODATA triggers on the
      newly-linked hosts during the soak window.
- [ ] After the soak: `scripts/migrate-from-itmicus.py --only <same hosts> --apply`
      (drops `--keep-old`) to unlink the legacy template.

## Cleanup

- [ ] Once all hosts have unlinked the legacy template, disable / delete
      `Template Website metrics (itmicus.ru)` in the Zabbix UI (manual step,
      after a grace period).
- [ ] Confirm no items still reference `website_metrics.py`:
      `item.get filter={"key_": "website_metrics.*"}` returns empty.
- [ ] Remove `/usr/lib/zabbix/externalscripts/website_metrics.py` and any
      pip-installed leftovers from the original `whois==0.9` / monkey-patched
      `requests` install on `mon`, vps12, vps15, ET-VPS01, SR-VPS01-PROXY.

## Rollback (any time before final cleanup)

- [ ] `scripts/migrate-from-itmicus.py --only <host> --keep-old --apply`
      is idempotent — re-running while the new template is already linked
      and the legacy is still attached is a no-op.
- [ ] To revert a host: unlink the new template via the Zabbix UI; the legacy
      template (still attached when `--keep-old` was used) resumes as the
      sole source.
