# Examples

## Gate a pull request

Run the audit in CI and let a non-zero exit fail the job:

```shell
kms-rotation-audit audit --region us-east-1
```

A complete GitHub Actions workflow (OIDC role, weekly schedule, 180-day
policy) is in [`github-actions/kms-rotation-audit.yml`](github-actions/kms-rotation-audit.yml).

Table output when violations exist:

```
REGION     KEY ID                                REASON
us-east-1  1234abcd-12ab-34cd-56ef-1234567890ab  automatic rotation disabled

1 key(s) violate the rotation policy.
```

## Machine-readable output

`--json` prints an object with `findings`, `skipped` (keys where automatic
rotation does not apply, and multi-Region replicas reported on their primary)
and `errors` (regions that could not be scanned), see
[`findings.json`](findings.json):

```shell
kms-rotation-audit audit --json --max-days 180 --all-regions
```

## Remediate

`fix` runs the same scan, then calls `EnableKeyRotation` on every flagged key:

```shell
kms-rotation-audit fix --region us-east-1
```

With `--max-days N`, `fix` also sets each flagged key's rotation period to
`min(N, 365)` days, so keys flagged for a slow period come back clean on the
next audit, and a loose `N` such as 2000 never makes rotation rarer than the
365-day KMS default. KMS accepts periods from 90 to 2560 days; `fix` refuses
a `--max-days` below 90 because no key could satisfy it:

```shell
kms-rotation-audit fix --region us-east-1 --max-days 180
```

Keys that already rotate, AWS-managed keys, disabled keys, asymmetric keys,
keys with imported key material, keys in a custom key store, and
multi-Region replicas are all left untouched.
