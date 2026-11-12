# kms-rotation-audit

[![ci](https://github.com/moveeeax/kms-rotation-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/kms-rotation-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26+-00ADD8?logo=go)](https://go.dev)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Audit AWS KMS **customer-managed** keys for disabled automatic rotation and
fail CI before an auditor does.

When you create a customer-managed KMS key, automatic rotation is **off by
default**. Teams turn a few keys on by hand and forget the rest, so months
later a SOC 2 / PCI review turns up a pile of long-lived keys that never
rotate. `kms-rotation-audit` is the cheap gate that catches an un-rotated key
at pull-request time and, optionally, fixes it.

## How it works

1. `ListKeys` (paginated) enumerates every key in the region. With
   `--regions` or `--all-regions` this runs in several regions, up to 4 at a
   time.
2. `DescribeKey` filters to **customer-managed, enabled, symmetric
   encryption** keys — AWS-managed keys, disabled/pending-deletion keys, and
   asymmetric keys are skipped, because rotation does not apply to them.
   Keys with imported key material (`Origin` `EXTERNAL`) and keys in a
   custom key store (CloudHSM or external) are symmetric, but KMS does not
   support automatic rotation for them
   ([EnableKeyRotation](https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html)).
   They are listed as skipped, not as violations; `--include-unrotatable`
   reports them with reason `rotation not supported: imported key material`
   or `rotation not supported: custom key store <id>`, and `fix` leaves them
   alone.
3. `GetKeyRotationStatus` flags any key with rotation disabled. With
   `--max-days N` it also flags an enabled key whose rotation period is longer
   than `N` days.
4. `audit` exits **1** when it finds a violation, so it gates CI. `fix` runs
   the same scan and then calls `EnableKeyRotation` on each flagged key;
   with `--max-days N` it also sets the rotation period to `min(N, 365)`
   days. A tight `N` brings slow keys within the policy; a loose `N` never
   stretches a key past the 365-day KMS default. KMS accepts periods of at
   least 90 days, so `fix` rejects a smaller `N`.
5. Exit codes: `0` clean, `1` violations found by `audit`, `2` error. A
   region that cannot be scanned (for example `AccessDenied`) is reported in
   stderr and in the JSON `errors` array, the other regions still run, and
   the exit code is `2`.

### Multi-Region keys

Rotation of a multi-Region key is set on the primary and shared by its
replicas. When the run covers the primary's region, the replica is listed as
skipped and the key set is reported once, on the primary. When it does not
(say, a single-region run in the replica's region), the replica is audited
in its own region; `fix` does not call `EnableKeyRotation` on it, since KMS
only accepts that on the primary.

## Install

```shell
go install github.com/moveeeax/kms-rotation-audit@latest
```

Or build from source:

```shell
git clone https://github.com/moveeeax/kms-rotation-audit
cd kms-rotation-audit
go build -o kms-rotation-audit .
```

Credentials are resolved the standard AWS SDK way (environment, shared config,
SSO, instance role). It needs `kms:ListKeys`, `kms:DescribeKey`,
`kms:GetKeyRotationStatus`, and — for `fix` — `kms:EnableKeyRotation`.
`--all-regions` also needs `ec2:DescribeRegions`.

## Usage

```shell
# Report keys with rotation disabled; exit 1 if any are found.
kms-rotation-audit audit --region us-east-1

# Machine-readable findings, and also flag slow (>180d) rotation.
kms-rotation-audit audit --json --max-days 180

# Every region enabled for the account, or an explicit list.
kms-rotation-audit audit --all-regions
kms-rotation-audit audit --regions us-east-1,eu-west-1

# Remediate: turn rotation on for every flagged key.
kms-rotation-audit fix --region us-east-1
```

Example table output:

```
REGION     KEY ID                                REASON
us-east-1  1234abcd-12ab-34cd-56ef-1234567890ab  automatic rotation disabled

1 key(s) violate the rotation policy.
1 key(s) skipped: automatic rotation does not apply (imported key material or custom key store); --include-unrotatable reports them.
```

See [`examples/`](examples/) for JSON output and a CI snippet.

## Flags

| Flag | Meaning |
| --- | --- |
| `--json` | Emit a JSON object with `findings`, `skipped` and `errors` arrays instead of a table. Each entry has `keyId`, `arn`, `region`, `reason`; findings `fix` cannot change also carry `unfixable`. |
| `--max-days N` | Also flag enabled keys whose rotation period exceeds `N` days. With `fix`, set the rotation period of flagged keys to `min(N, 365)`; `N` below 90 is rejected. |
| `--include-unrotatable` | Report keys with imported key material or in a custom key store as findings instead of skipping them. |
| `--region R` | AWS region (defaults to the SDK's resolved region). |
| `--regions R1,R2` | Scan these regions. |
| `--all-regions` | Scan every region enabled for the account (`ec2:DescribeRegions`, opted-in regions only). |
| `--profile P` | Shared-config profile to use. |

## Development

```shell
go test ./...   # unit tests run against a mocked KMS client
go vet ./...
```

## License

MIT — see [LICENSE](LICENSE).
