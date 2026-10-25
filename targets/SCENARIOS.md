# Synthetic exercise scenarios

These are local development inputs. They contain no customer logs, credentials,
or commands to run on a host. A human must authorize and select the actual
exercise tool and targets before any live replay.

| Scenario | Original signal | Variant | Normal control | Expected backward probe |
|---|---|---|---|---|
| Persistence | A new user cron entry and unfamiliar outbound connection appear together | A new autostart service replaces cron | A scheduled backup task is added by an authorized administrator | Cron/service and connection changes return to baseline; no recurrence |
| Access expansion | An unfamiliar SSH key and account privilege change appear | A new account with elevated group membership appears | A planned access rotation replaces an existing key | New access is removed while approved access and service health remain |
| Outbound transfer | An unfamiliar process sends data to an unseen external destination | The destination changes but process provenance is similar | An approved backup sends data to its known destination | Process and destination disappear; service health and unrelated files remain stable |

For each scenario, capture T0 before the simulated event, T1 at detection, T2
after approved remediation, and at least one observation snapshot. Retest a
candidate note on the original and variant; it must not flag the normal
control. Run the full labeled suite before keeping a new note active.

`synthetic_persistence.json` is a harmless example of the snapshot shape and
retest inputs. It is not a live exercise definition.
