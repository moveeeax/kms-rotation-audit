# Examples

## Gate a pull request

Run the audit in CI and let a non-zero exit fail the job:

```shell
kms-rotation-audit audit --region us-east-1
```

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

Keys that already rotate, AWS-managed keys, disabled keys, and asymmetric keys
are all left untouched.
