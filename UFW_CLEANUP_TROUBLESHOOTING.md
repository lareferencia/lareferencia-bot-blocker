# UFW Cleanup Troubleshooting

This document explains how to diagnose and recover when `blocker.py --clean-rules` fails because `ufw delete` cannot remove numbered rules.

It documents a real failure mode observed in production.

## Symptom

Cleanup starts normally, selects expired rules, and then fails during deletion with errors like:

```text
ERROR: initcaps
[Errno 2] iptables: Chain already exists.
```

The same failure can be reproduced manually:

```bash
ufw delete 330
```

If the manual `ufw delete <n>` command fails with the same message, the problem is not in the cleanup selection logic. The problem is in the UFW runtime state on the server.

## What This Means

`blocker.py --clean-rules` uses:

1. `ufw status numbered` to find expired rules
2. `ufw --force delete <rule_number>` to remove them

If step 1 works but step 2 fails with `initcaps`, UFW is failing while re-initializing its internal chains.

This is not a parsing issue in the bot blocker.

## Most Likely Cause

The most likely cause is a stale internal UFW chain left in the active iptables state, especially:

- `ufw-caps-test`
- `ufw6-caps-test`

During `ufw delete`, UFW runs an internal capability check (`initcaps`) and attempts to create those chains.

If they already exist, UFW aborts with:

```text
iptables: Chain already exists.
```

## How To Confirm The Diagnosis

Run:

```bash
ufw version
iptables --version
ip6tables --version
readlink -f "$(command -v iptables)"
readlink -f "$(command -v ip6tables)"
iptables-save | grep -E '(^:ufw|^-A ufw)'
ip6tables-save | grep -E '(^:ufw|^-A ufw)'
systemctl is-active firewalld
```

Important things to check:

- Whether `ufw status numbered` works
- Whether `ufw delete <n>` fails manually
- Whether `iptables-save` shows `:ufw-caps-test - [0:0]`
- Whether `ip6tables-save` shows `:ufw6-caps-test - [0:0]`
- Whether another firewall manager is active

If `ufw-caps-test` or `ufw6-caps-test` appear in the active ruleset, that strongly supports this diagnosis.

## Check Whether The Problem Is Persisted In Files

Before changing runtime state, check whether those chains are defined in UFW files:

```bash
grep -R "ufw-caps-test\\|ufw6-caps-test" /etc/ufw /lib/ufw 2>/dev/null
```

Interpretation:

- If they appear in files, the bad state may be reintroduced on reload.
- If they do not appear in files, the stale chain is probably only present in the active kernel ruleset.

## Safe Recovery Procedure

### 1. Back Up The Current Firewall State

Do this first:

```bash
iptables-save > /root/iptables-backup-$(date +%F-%H%M%S).rules
ip6tables-save > /root/ip6tables-backup-$(date +%F-%H%M%S).rules
```

### 2. Remove Only The Stale Capability-Test Chains

Remove the temporary UFW test chains, if present:

```bash
iptables -F ufw-caps-test 2>/dev/null || true
iptables -X ufw-caps-test 2>/dev/null || true

ip6tables -F ufw6-caps-test 2>/dev/null || true
ip6tables -X ufw6-caps-test 2>/dev/null || true
```

This targets only the temporary capability-test chains. It does not reset the full firewall.

### 3. Re-Test UFW Directly

Verify UFW works again:

```bash
ufw status numbered
ufw delete <rule_number>
```

If `ufw delete <rule_number>` now succeeds, the runtime state was the problem.

### 4. Re-Run Cleanup

Once manual deletion works again, re-run:

```bash
python3 blocker.py --clean-rules
```

Or first check with:

```bash
python3 blocker.py --clean-rules --dry-run
```

## What Not To Do

Do not start with:

- `ufw reset`
- flushing all iptables chains
- removing random `ufw-*` chains

Those actions are much more disruptive and can drop intended firewall state.

Target only:

- `ufw-caps-test`
- `ufw6-caps-test`

unless you have direct evidence of a broader corruption.

## Why The Bot Blocker Is Not The Root Cause

If you can reproduce the failure with:

```bash
ufw delete <n>
```

outside of `blocker.py`, then the bot blocker is only surfacing a UFW backend problem.

In that case:

- the cleanup selection logic may still be correct
- the failure is in UFW state management on that host

## Operational Recommendation

If this happens again:

1. confirm the failure manually with `ufw delete <n>`
2. check for `ufw-caps-test` / `ufw6-caps-test`
3. back up the current ruleset
4. remove only those stale test chains
5. re-test UFW manually
6. re-run `blocker.py --clean-rules`

## Suggested Future Improvement

The cleanup code should detect this specific failure mode and stop after the first `initcaps` error, with a clear message explaining:

- that the issue is in UFW runtime state
- that `ufw-caps-test` / `ufw6-caps-test` should be checked

That avoids repeated log spam and makes the root cause clearer during incidents.
