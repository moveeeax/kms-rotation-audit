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
KEY ID                                REASON
1234abcd-12ab-34cd-56ef-1234567890ab  automatic rotation disabled

1 key(s) violate the rotation policy.
```

## Machine-readable output

`--json` prints an array of findings (see [`findings.json`](findings.json)):

```shell
kms-rotation-audit audit --json --max-days 180
```

## Remediate

`fix` runs the same scan, then calls `EnableKeyRotation` on every flagged key:

```shell
kms-rotation-audit fix --region us-east-1
```

With `--max-days N`, `fix` also sets each flagged key's rotation period to
`N` days, so keys flagged for a slow period come back clean on the next
audit. KMS accepts periods from 90 to 2560 days; `fix` refuses a
`--max-days` below 90 because no key could satisfy it:

```shell
kms-rotation-audit fix --region us-east-1 --max-days 180
```

Keys that already rotate, AWS-managed keys, disabled keys, and asymmetric keys
are all left untouched.
