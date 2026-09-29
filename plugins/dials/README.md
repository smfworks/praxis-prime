# Dial plugins

Each directory is a future `policy_dial` plugin. None of them are loaded, and every matching config dial defaults to `off`.

| Directory | Config id | Wave |
|---|---|---|
| `hipaa/` | `hipaa` | first |
| `ferpa_coppa/` | `ferpa`, `coppa` | first |
| `gdpr/` | `gdpr` | first |
| `us_states/` | `state_ct` … `state_wv` (13 codes) | first |
| `state_nc/` | `state_nc` | first |
| `soc2/` | `soc2` | v1.0 |
| `euaiact/` | `eu_ai_act` | v1.0 |
| `ccpa/` | `ccpa` | v1.0 |
| `pci/` | `pci` | v1.0 |
| `nist_rmf/` | `nist_ai_rmf` | v1.0 |
| `iso42001/` | `iso_42001` | v1.0 |

The catalog in code is `praxis_prime.policy.dials`. Technical controls are not certifications.

TODO: ARCHITECTURE §17.
