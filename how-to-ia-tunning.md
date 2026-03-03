# How To Use AI For Tuning Analysis

This guide explains how to use the tuning workflow in this repository with another AI system.

The workflow is built around two files:

- `tuning_snapshot.py`: generates a Markdown snapshot of recent traffic and current blocker behavior
- `TUNING_SNAPSHOT_CONTEXT.md`: gives an AI the rules and constraints it should follow when analyzing that snapshot

The purpose is not to let an AI make blind changes. The purpose is to:

- summarize the current traffic pattern
- understand which blocker layer is limiting detection
- compare conservative vs aggressive tuning options
- propose one safe experiment at a time

## What This Workflow Does

The blocker has multiple decision layers:

- single-IP persistence (`IP`)
- local subnet detection (`/24`)
- distributed-pressure detection (`/16`)

Reading raw logs directly is noisy and expensive for an AI. Instead, `tuning_snapshot.py` compresses a time window into a structured Markdown report.

That report includes:

- traffic volume
- host load
- IP and subnet cardinality
- effective dynamic thresholds
- current baseline outcome
- near-miss analysis
- sensitivity profiles
- recommended tuning direction

`TUNING_SNAPSHOT_CONTEXT.md` then tells another AI how to interpret that report correctly.

## When To Use It

Use this workflow when:

- the blocker is active but coverage seems low
- the server is under pressure and you want safer tuning guidance
- you want to compare tuning options before changing cron parameters
- you want a repeatable analysis method for future incidents

Do not use this workflow as the only basis for permanent production changes. A single snapshot should guide an experiment, not define a final configuration.

## Step 1: Generate A Snapshot

The fastest way is:

```bash
python3 tuning_snapshot.py
```

By default, this will:

- analyze `/var/log/httpd/access_log`
- use the last hour if no explicit window is provided
- try to detect the blocker baseline from:
  1. `--execution-log` if you pass one
  2. the blocker execution log inferred from cron redirection
  3. the blocker cron command
  4. the internal preset `lareferencia-hourly`
- write the report to `tuning-snapshot.md`

Useful variants:

```bash
# Write to a specific output file
python3 tuning_snapshot.py -o /tmp/tuning-snapshot.md

# Analyze a different access log
python3 tuning_snapshot.py -f /var/log/nginx/access.log -o /tmp/tuning-snapshot.md

# Analyze a specific time range start
python3 tuning_snapshot.py -s 01/Mar/2026:09:00:00 -o /tmp/tuning-snapshot.md

# Use a larger profile sweep
python3 tuning_snapshot.py --profile-set extended -o /tmp/tuning-snapshot.md
```

## Step 2: Collect The Context Files

To let another AI analyze the snapshot correctly, provide:

1. the generated snapshot report
2. the context guide from this repository

Minimum set:

- `tuning-snapshot.md`
- `TUNING_SNAPSHOT_CONTEXT.md`

Recommended additional context when available:

- the current cron line for `blocker.py`
- the current whitelist file
- any notes about known legitimate crawlers or trusted networks

Without that context, an AI may overreact to legitimate traffic and recommend overly aggressive thresholds.

## Step 3: Feed Both Files To The AI

The best pattern is:

1. provide `TUNING_SNAPSHOT_CONTEXT.md` first
2. provide `tuning-snapshot.md` second
3. ask for a constrained recommendation

This ordering matters. The context file tells the AI how to think before it sees the data.

## Step 4: Use A Constrained Prompt

Use a prompt that asks for:

- traffic interpretation
- main bottlenecks
- one conservative next experiment
- exact parameter changes
- validation steps

Example prompt:

```text
Use TUNING_SNAPSHOT_CONTEXT.md as the analysis policy.
Analyze the attached tuning-snapshot.md.

I want:
1. The dominant traffic pattern
2. The main blocking constraints
3. The safest next experiment
4. Exact blocker parameter changes
5. Risks or caveats
6. A validation step using dry-run

Do not recommend a final permanent configuration from one snapshot.
Prefer conservative changes unless the report clearly justifies a stronger move.
```

This keeps the AI focused on bounded recommendations instead of broad security advice.

## Step 5: Understand What The AI Should Analyze

The AI should read the snapshot in this order:

1. `Executive Summary`
2. `Window Summary`
3. `Traffic Shape`
4. `Current Config Outcome`
5. `Near Miss Analysis`
6. `Sensitivity Sweep`

The most important section for tuning is usually `Near Miss Analysis`.

Why:

- top offenders show examples
- near misses show where the real thresholds are blocking broader detection

If many candidates fail for the same single reason, that reason is usually the cleanest tuning lever.

## How To Interpret Common Patterns

### Pattern: Very high unique IPs, low per-IP activity

Typical meaning:

- distributed swarm
- fan-out traffic
- many weak participants

Typical implication:

- do not start by lowering IP thresholds
- look at `/16` and `/24` constraints first

### Pattern: Many `/24` fail only by RPM

Typical meaning:

- local subnet activity is close to blockable
- current `/24` RPM gate is slightly too strict

Typical implication:

- test a small reduction in `--min-rpm-threshold`

### Pattern: Many `/16` fail only by IP count

Typical meaning:

- distributed pressure exists but the `/16` cardinality gate is too strict

Typical implication:

- test a small reduction in `--supernet-min-ip-count`

### Pattern: IP layer is already active

Typical meaning:

- persistent single-IP outliers are already being caught

Typical implication:

- do not lower `--ip-min-*` first unless the report clearly shows IP-only misses

### Pattern: Aggressive profile adds many rules for little coverage gain

Typical meaning:

- the traffic is too diffuse for brute-force threshold lowering

Typical implication:

- reject the aggressive option
- prefer a smaller experiment

## How To Use The Sensitivity Profiles

The snapshot includes profiles such as:

- `Balanced A`
- `Conservative A`
- `Balanced B`
- `Aggressive A`

These are simulated alternatives, not automatic recommendations.

Use them this way:

- `Balanced A`: the current baseline
- `Conservative A`: safer, lower sensitivity
- `Balanced B`: a moderate experiment
- `Aggressive A`: stress test for higher containment

When comparing profiles, focus on:

- coverage increase
- rule growth
- which layer changed most

Good profile:

- small or moderate rule growth
- meaningful coverage improvement
- no obvious jump in collateral risk

Bad profile:

- large rule increase
- tiny coverage improvement
- gains coming mainly from wider `/24` expansion

## How To Avoid Bad Recommendations

Another AI can still make bad calls if the operator provides poor context.

Avoid these mistakes:

1. Do not send only the top offender rows.
2. Do not ask for “the best settings” without constraints.
3. Do not hide known legitimate crawler traffic.
4. Do not let the AI recommend changes without naming exact parameters.
5. Do not apply recommendations directly to production without a dry-run.

If the top offenders include likely legitimate networks, tell the AI that explicitly or provide the whitelist.

## Step 6: Convert The AI Recommendation Into A Test

Once the AI proposes a conservative experiment:

1. keep the current baseline
2. change only one or two thresholds
3. run `blocker.py` in `--dry-run`
4. review what would be blocked
5. generate a new snapshot after the change

Example:

```bash
python3 blocker.py \
  --file /var/log/httpd/access_log \
  --time-window hour \
  --min-rpm-threshold 5.5 \
  --min-sustained-percent 20 \
  --max-cpu-load-threshold 75 \
  --ip-swarm-threshold 30 \
  --ip-swarm-rpm-factor 0.45 \
  --ip-swarm-bonus-max 2.0 \
  --ip-min-rpm-threshold 20 \
  --ip-min-sustained-percent 35 \
  --ip-min-requests 120 \
  --supernet-min-rpm-total 5.5 \
  --supernet-min-ip-count 90 \
  --supernet-min-requests 180 \
  --block-duration 120 \
  --whitelist /opt/lareferencia-bot-blocker/whitelist.txt \
  --strike-file /opt/lareferencia-bot-blocker/strike_history.json \
  --block \
  --dry-run
```

The exact values should come from the snapshot analysis, not from this example.

## Step 7: Re-Run The Snapshot

After testing a tuning change:

1. generate a new `tuning-snapshot.md`
2. compare it with the previous one
3. ask the AI whether the change improved the intended layer

This turns tuning into an iterative loop:

1. snapshot
2. AI review
3. small experiment
4. dry-run validation
5. new snapshot

That is the intended workflow.

## Recommended Questions To Ask Another AI

Use narrow questions. Good examples:

- “Which blocker layer is the main bottleneck in this snapshot?”
- “Is the best next step a `/24` change or a `/16` change?”
- “Which single threshold should I test first?”
- “Does the aggressive profile justify its rule growth?”
- “Do the top networks suggest a whitelist review before tuning?”

Avoid vague questions such as:

- “What do you think?”
- “Can you optimize this?”
- “What are the best parameters?”

Vague questions produce generic answers.

## Expected Quality Bar For AI Answers

A useful answer should:

- identify the dominant traffic pattern
- name the main limiting thresholds
- explain why one layer should be tuned before another
- recommend one conservative experiment
- include exact parameter names
- include a validation step

A weak answer usually:

- repeats the report summary without judgment
- suggests lowering everything
- ignores false-positive risk
- ignores likely legitimate traffic
- does not mention `--dry-run`

## Practical Example

A typical good conclusion looks like this:

- The traffic is highly distributed, so this is not primarily an IP-layer problem.
- The IP layer is already active, so do not lower IP thresholds first.
- The next experiment should be a small `/24` or `/16` adjustment, not an aggressive profile.
- The aggressive profile is not justified if rule growth is high and coverage gain is small.
- Validate the proposed change with `blocker.py --dry-run` and generate a new snapshot afterward.

That is the level of precision this workflow is designed to support.

## Final Rule

Use AI as an analysis assistant, not as an automatic controller.

The AI should help you:

- understand the snapshot
- choose the next experiment
- avoid over-tuning

The operator should still decide:

- whether the traffic is legitimate
- whether the risk of collateral blocking is acceptable
- whether the experiment is safe to move toward production
