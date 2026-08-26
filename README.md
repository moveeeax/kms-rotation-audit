# kms-rotation-audit

[![ci](https://github.com/moveeeax/kms-rotation-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/kms-rotation-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go)](https://go.dev)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Audit AWS KMS **customer-managed** keys for disabled automatic rotation and
fail CI before an auditor does.

When you create a customer-managed KMS key, automatic rotation is **off by
default**. Teams turn a few keys on by hand and forget the rest, so months
later a SOC 2 / PCI review turns up a pile of long-lived keys that never
rotate. `kms-rotation-audit` is the cheap gate that catches an un-rotated key
at pull-request time and, optionally, fixes it.

## How it works

1. `ListKeys` (paginated) enumerates every key in the region.
2. `DescribeKey` filters to **customer-managed, enabled, symmetric
   encryption** keys — AWS-managed keys, disabled/pending-deletion keys, and
   asymmetric keys are skipped, because rotation does not apply to them.
3. `GetKeyRotationStatus` flags any key with rotation disabled. With
   `--max-days N` it also flags an enabled key whose rotation period is longer
   than `N` days.
4. `audit` exits **1** when it finds a violation, so it gates CI. `fix` runs
   the same scan and then calls `EnableKeyRotation` on each flagged key.

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

## Usage

```shell
# Report keys with rotation disabled; exit 1 if any are found.
kms-rotation-audit audit --region us-east-1

# Machine-readable findings, and also flag slow (>180d) rotation.
kms-rotation-audit audit --json --max-days 180

# Remediate: turn rotation on for every flagged key.
kms-rotation-audit fix --region us-east-1
```

Example table output:

```
KEY ID                                REASON
1234abcd-12ab-34cd-56ef-1234567890ab  automatic rotation disabled

1 key(s) violate the rotation policy.
```

See [`examples/`](examples/) for JSON output and a CI snippet.

## Flags

| Flag | Meaning |
| --- | --- |
| `--json` | Emit findings as a JSON array instead of a table. |
| `--max-days N` | Also flag enabled keys whose rotation period exceeds `N` days. |
| `--region R` | AWS region (defaults to the SDK's resolved region). |
| `--profile P` | Shared-config profile to use. |

## Development

```shell
go test ./...   # unit tests run against a mocked KMS client
go vet ./...
```

## License

MIT — see [LICENSE](LICENSE).
