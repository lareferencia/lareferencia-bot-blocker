# Current Blocking Strategy (February 2026)

## Goal
Protect the server under bot pressure without depending only on per-subnet spikes, because recent attacks are distributed (many IPs, many `/24`, low-and-slow per subnet).

## Why the Strategy Changed
The previous model focused mostly on `/24` intensity (RPM + sustained activity).  
That worked for concentrated bursts, but not for distributed swarms where each `/24` looks mild while total pressure is high.

Observed pattern:
- High unique IP cardinality.
- Many active `/24` at the same time.
- Low individual RPM per `/24`, but high aggregate impact.
- Very high CPU/load with few local threshold hits.

## Current Strategy (High Level)
The blocker now uses a layered model:

1. Distributed-pressure detection at `/16` (principal anti-swarm layer).
2. Local detection at `/24` using unified scoring.
3. Per-IP persistence layer with stricter single-IP thresholds.
4. Strike-based duration escalation.
5. Controlled cleanup of expired UFW rules (drip release, not mass release).

## Layer 1: Principal `/16` Distributed-Pressure Blocking
When CPU is in aggressive mode, the blocker aggregates `/24` metrics into `/16` totals and blocks a `/16` if it passes all conditions:
- minimum total RPM in the `/16`
- minimum total unique IPs in the `/16`
- minimum total requests in the `/16`
- minimum sustained presence (using effective sustained threshold)

Reason:
- Captures distributed attacks that evade strict `/24` thresholds.
- Blocks infrastructure-level pressure earlier.

## Layer 2: `/24` Unified Strategy Scoring
For individual subnet decisions, blocking uses unified scoring with:
- base conditions (RPM + sustained)
- score bonuses (RPM, volume, IP diversity)
- swarm-aware behavior (IP count has stronger weight)

The strategy also supports swarm-oriented blocking logic where very high IP diversity can still trigger blocking even if RPM is only moderately above a reduced factor of the effective RPM threshold.

Reason:
- Improves detection of bot swarms that fan out across many IPs.
- Keeps sensitivity to concentrated subnet abuse.

## Layer 3: Single-IP Persistence Layer
After `/16` and `/24` decisions, the blocker evaluates each IP with stricter thresholds (minimum requests, sustained presence, and window-normalized RPM).

Reason:
- Avoids penalizing an entire subnet for a single short burst.
- Still blocks persistent abusive IPs even if subnet-level thresholds are not met.

## Dynamic Thresholds by System Load
Thresholds are adjusted dynamically using normalized system load and CPU trigger level:
- under high load, effective RPM and sustained thresholds are reduced
- aggressive mode trigger uses `>=` to avoid edge-case misses at exact threshold

Reason:
- During incidents, strict static thresholds react too late.
- Dynamic lowering increases response speed when the server is already stressed.

## Strike History and Block Duration
Every blocked target accumulates strikes in a history file.
- normal block duration applies for low strike count
- escalated duration applies once strike threshold is reached

Reason:
- Repeat offenders stay blocked longer.
- Reduces unblock/reblock churn for known abusive sources.

## Cleanup Strategy (No Runtime Parameters)
Expired UFW rules are not deleted all at once. The cleanup heuristic is fixed in code:
- grace period after expiry (45 min)
- max deletions per run (24)
- lower cap under high host load (8)
- per-family cap per run (IPv4 grouped by `/16`, IPv6 by `/48`, max 2)
- oldest expired rules are released first

Reason:
- Prevents sudden mass unblocking of recently abusive networks.
- Reduces risk of immediate re-flood and rule thrashing.

## Practical Effect
This strategy is built to handle both:
- concentrated attackers (strong `/24` or single IP),
- distributed swarms (many mild `/24` that are harmful in aggregate).

It prioritizes service stability first, then precision tuning with whitelist and threshold adjustments.

## Operational Notes
- Always validate major threshold changes with `--dry-run`.
- Keep whitelist strict and auditable.
- Run periodic cleanup (`--clean-rules`) so rule set remains healthy while keeping controlled release behavior.
- Re-tune based on recent logs and false-positive feedback, not isolated snapshots.
- Use `tuning_snapshot.py` to generate a Markdown report before changing thresholds; it can auto-read the blocker baseline from cron and the latest blocker `PARAMS` log line.
