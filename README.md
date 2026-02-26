# LA Referencia Dynamic Bot Blocker

Current version: `v1.1`

> **⚠️ DISCLAIMER: EXPERIMENTAL SOFTWARE**
>
> This software is experimental. It is crucial to fully understand the implications of adding firewall restrictions based on log analysis before applying it to production environments. Incorrect parameterization of this script could block legitimate access. LA Referencia is not responsible for improper use or any consequences arising from its use. **Thorough testing in development environments is strongly recommended before production deployment.**

This tool analyzes web server logs (e.g., Apache, Nginx) to identify potential bot threats based on request patterns and activity levels. It groups suspicious activity by subnet and can optionally block identified threats using UFW (Uncomplicated Firewall) rules with automatic expiration.

## Features

-   ✅ **Log Analysis:** Parses common web server log formats using **streaming generators** for memory efficiency.
-   ✅ **Lightweight Processing:** Uses native Python data structures and streaming to handle large log files with minimal RAM.
-   ✅ **Unified Strategy:** Evaluation based on request rate, sustained activity, and **System Load Average** with **gradual scoring**.
-   ✅ **Gradual Threat Scoring:** Ranks threats using bonus points for RPM intensity, request volume, and IP diversity.
-   ✅ **Threat Grouping:** Aggregates IP-level metrics by subnet (/24 for IPv4, /64 for IPv6).
-   ✅ **Principal `/16` Distributed-Pressure Blocking:** Blocks `/16` supernets using aggregated pressure thresholds under aggressive load.
-   ✅ **Per-IP Persistence Layer:** Evaluates single IPs with stricter persistence thresholds to avoid penalizing whole subnets for isolated bursts.
-   ✅ **Automated Blocking:** Integrates with UFW to insert temporary `deny` rules with expiration time.
-   ✅ **Strike System & Escalation:** Tracks block events and escalates block duration for repeat offenders.
-   ✅ **Rule Cleanup:** Includes a mode to automatically remove expired UFW rules.
-   ✅ **Whitelisting:** Supports excluding specific IPs or subnets from analysis and blocking.
-   ✅ **Multiple Export Formats:** Outputs threat reports in JSON, CSV, or human-readable text.

## How It Works

The unified strategy evaluates two conditions for each subnet with **Load Average-based** dynamic adjustment:

1. **RPM Threshold:** Request rate per minute (default: 10 req/min at normal system load)
2. **Sustained Activity:** Percentage of analysis window subnet was active (default: 25% at normal system load)

**System Load-Based Dynamic Thresholds:**
- **Normal load (≤80% Normalized Load Avg):** Uses base thresholds (10 req/min, 25% time window)
- **High load (80-100% Normalized Load Avg):** Progressively reduces thresholds:
  - At 80%: 5 req/min (50%), 12.5% time window
  - At 90%: 2.5 req/min (25%), 6.25% time window
  - At 100%: 2.5 req/min (fixed), 3% time window (minimum)
  - Linear interpolation between threshold points

*Note: Load Average is normalized by the number of CPUs (Load Avg 1min / CPU Count * 100).*

**Blocking occurs when conditions 1 AND 2 are met** (score >= 2.0). All subnets exceeding thresholds are blocked, not just a limited number.

## Installation

Requires **Python 3.7+**, **UFW** (for blocking), and **psutil**.

```bash
# 1. Clone the repository
git clone https://github.com/LA-Referencia/lareferencia-bot-blocker.git
cd lareferencia-bot-blocker

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt  # Installs psutil
```

## Usage

### Basic Analysis (No Blocking)

```bash
# Analyze entire log, show top 10 threats exceeding thresholds
python3 blocker.py -f /var/log/apache2/access.log

# Analyze last hour (default), show top 20 threats
python3 blocker.py -f /var/log/nginx/access.log --top 20

# Analyze last 6 hours, show all threats exceeding thresholds
python3 blocker.py -f /var/log/nginx/access.log --time-window 6hour --top 0
```

### Analysis and Blocking

**Requires `sudo` or appropriate permissions.**

```bash
# Analyze last day, block all threats exceeding thresholds
sudo python3 blocker.py -f /var/log/apache2/access.log \
    --time-window day \
    --block \
    --min-rpm-threshold 10.0 \
    --min-sustained-percent 25.0 \
    --max-cpu-load-threshold 80.0 \
    --block-duration 120

# Dry run to see what would be blocked (last hour by default)
sudo python3 blocker.py -f /var/log/nginx/access.log \
    --block \
    --dry-run
```

### Exporting Results

```bash
# Save results to JSON
python3 blocker.py -f /var/log/apache2/access.log \
    --output threats_report.json \
    --format json

# Analyze last week and save to CSV
python3 blocker.py -f /var/log/nginx/access.log \
    --time-window week \
    --output weekly_threats.csv \
    --format csv
```

### Cleaning Expired Rules

**Requires `sudo` or appropriate permissions.**

```bash
# Remove expired UFW rules
sudo python3 blocker.py --clean-rules

# See which rules would be removed (Dry Run)
sudo python3 blocker.py --clean-rules --dry-run
```

## Options

| Option                         | Description                                                                                              | Default                   |
| :----------------------------- | :------------------------------------------------------------------------------------------------------- | :------------------------ |
| `--file, -f`                   | Path to the log file to analyze (required unless `--clean-rules`).                                      | `None`                    |
| `--start-date, -s`             | Analyze logs from this date/time (Format: `dd/Mmm/YYYY:HH:MM:SS`).                                      | `None`                    |
| `--time-window, -tw`           | Analyze logs from the `hour` (default), `6hour`, `day`, or `week` (overrides `--start-date`).           | `hour`                    |
| `--top, -n`                    | Number of threats to display in report (0 = show all). All threats exceeding thresholds are blocked.    | `10`                      |
| `--whitelist, -w`              | Path to a file containing IPs/subnets to exclude (one per line, `#` for comments).                      | `None`                    |
| `--block`                      | Enable blocking of threats using UFW. Requires appropriate permissions.                                 | `False`                   |
| `--min-rpm-threshold`          | Minimum requests per minute threshold for blocking (base value, adjusted by CPU load).                  | `10.0`                    |
| `--min-sustained-percent`      | Minimum percentage of analysis window duration a subnet must be active (base value, adjusted by CPU).   | `25.0`                    |
| `--max-cpu-load-threshold`     | CPU load percentage threshold for aggressive mode (80-100% triggers dynamic reduction).                 | `80.0`                    |
| `--ip-swarm-threshold`         | Minimum unique IP count in one subnet to consider swarm behavior.                                       | `40`                      |
| `--ip-swarm-rpm-factor`        | RPM factor over effective RPM used by swarm condition (`0.60` = 60%).                                  | `0.60`                    |
| `--ip-swarm-bonus-max`         | Maximum score bonus granted by IP diversity (swarm penalty weight).                                     | `1.50`                    |
| `--ip-min-rpm-threshold`       | Per-IP persistence layer: minimum req/min (window-normalized) to block a single IP.                    | `20.0`                    |
| `--ip-min-sustained-percent`   | Per-IP persistence layer: minimum % of analysis window an IP must stay active.                          | `35.0`                    |
| `--ip-min-requests`            | Per-IP persistence layer: minimum total requests required to block a single IP.                         | `120`                     |
| `--supernet-min-rpm-total`     | Principal `/16` distributed-pressure threshold: minimum aggregated req/min across `/24` members.         | `6.0`                     |
| `--supernet-min-ip-count`      | Principal `/16` distributed-pressure threshold: minimum aggregated unique IP count across `/24` members. | `120`                     |
| `--supernet-min-requests`      | Principal `/16` distributed-pressure threshold: minimum aggregated request volume in the `/16`.          | `200`                     |
| `--block-duration`             | Default duration (minutes) for UFW blocks (used if strike count < escalation threshold).               | `60`                      |
| `--block-escalation-strikes`   | Number of strikes within history window required to trigger escalated block duration (1440 min).       | `4`                       |
| `--strike-file`                | Path to the JSON file for storing strike history.                                                       | `strike_history.json`     |
| `--strike-max-age-hours`       | Strike history entries older than this many hours are purged on load.                                   | `48`                      |
| `--dry-run`                    | Show UFW commands that would be executed, but do not execute them.                                      | `False`                   |
| `--output, -o`                 | File path to save the analysis results.                                                                 | `None`                    |
| `--format`                     | Output format for the results file (`json`, `csv`, `text`).                                             | `text`                    |
| `--log-file`                   | File path to save execution logs.                                                                       | `None`                    |
| `--log-level`                  | Logging detail level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).                                 | `INFO`                    |
| `--clean-rules`                | Run cleanup of expired UFW rules and exit. Requires permissions.                                        | `False`                   |
| `--silent`                     | Suppress most console output (except block actions and final summary).                                  | `False`                   |

## Unified Strategy

The strategy evaluates two base conditions:

1. **RPM >= min_rpm_threshold** - Sustained request rate check (base: 10 req/min)
2. **Sustained activity >= min_sustained_percent** - Activity persistence over analysis window (base: 25%)

**System Load-Based Dynamic Thresholds:**
System **Load Average (1-minute, normalized)** is used to dynamically adjust blocking thresholds:
- **≤80% Load:** Normal mode - use base thresholds (10 req/min, 25%)
- **>=80% Load:** Aggressive mode - progressively reduce thresholds
  - 80%: 5 req/min (50%), 12.5% time window
  - 90%: 2.5 req/min (25%), 6.25% time window
  - 100%: 2.5 req/min (fixed), 3% time window (minimum)
  - Linear interpolation between threshold points

**Blocking decision:** Blocks when (1 AND 2) are met, or when swarm condition is met (high IP cardinality + sustained activity + partial RPM).

When a blockable subnet has only one observed IP, the blocker targets that IP directly instead of blocking the whole subnet.

### Principal /16 Distributed-Pressure Escalation

In block mode, the blocker always evaluates `/16` supernets using aggregated pressure from their `/24` members (distributed attack pattern).

The `/16` is blocked when all configured thresholds are met and CPU is in aggressive mode:

- `--supernet-min-rpm-total`
- `--supernet-min-ip-count`
- `--supernet-min-requests`

The sustained activity requirement still uses the effective dynamic sustained threshold.

### Per-IP Persistence Layer

After `/16` and subnet decisions, block mode evaluates individual IPs as a safety layer.
This preserves subnet-centric behavior for swarms, but avoids penalizing an entire subnet for an isolated burst.

A single IP is blocked only when all are met:
- `total_requests >= --ip-min-requests`
- `req/min(window) >= effective(--ip-min-rpm-threshold)`
- `timespan >= effective(--ip-min-sustained-percent)`

### Gradual Scoring System

Threats are ranked using a gradual score (0-5) for better prioritization:

| Component | Range | Description |
|-----------|-------|-------------|
| Base score | 0-2 | +1 for each condition met (RPM, Sustained) |
| Bonus RPM intensity | 0-1.0 | Higher bonus if RPM greatly exceeds threshold |
| Bonus volume | 0-0.5 | Higher bonus for larger total request count |
| Bonus IP diversity | 0-1.5 | Higher bonus for large IP swarms in the same /24 (stronger distributed-bot penalty) |

**All subnets exceeding thresholds are blocked**, not just a limited number. The `--top` parameter only controls how many are displayed in reports.

## Strike System

-   **History Storage:** Maintains block events in JSON file specified by `--strike-file`
-   **Configurable Window:** Automatically discards timestamps older than `--strike-max-age-hours` (default: 48)
-   **Escalation:** If strike count >= `--block-escalation-strikes` (default 4), block duration escalates to 1440 minutes (24 hours)
-   **Default Duration:** Otherwise uses `--block-duration` (default 60 minutes)

## Scheduled Execution with Cron

For periodic analysis and blocking, use `cron`. Ensure you use absolute paths.

```bash
# Open crontab editor (requires sudo for UFW access)
sudo crontab -e

# Analyze last hour every hour and block all threats exceeding thresholds (default time window is now 1 hour)
0 * * * * /path/to/venv/bin/python3 /path/to/blocker.py -f /var/log/apache2/access.log --block --whitelist /etc/bot-blocker/whitelist.txt --strike-file /var/log/bot-blocker/strikes.json --silent >> /var/log/bot-blocker-cron.log 2>&1

# Clean up expired rules every 30 minutes
*/30 * * * * /path/to/venv/bin/python3 /path/to/blocker.py --clean-rules >> /var/log/bot-blocker-clean.log 2>&1
```

**Cron Considerations:**

-   **Permissions:** User needs `sudo` privileges (without password prompt) for `ufw` commands
-   **Paths:** Always use absolute paths
-   **Logging:** Use `--log-file` and redirect output for debugging
-   **Tuning:** Start with higher thresholds and shorter durations; monitor and adjust

## Whitelist Format

The whitelist file should contain one IP address or CIDR subnet per line. Lines starting with `#` are ignored.

```
# Example whitelist
127.0.0.1
::1
192.168.1.0/24
2001:db8::/32
```

## Project Structure

-   `blocker.py`: Main script
-   `parser.py`: Log parsing functions
-   `threat_analyzer.py`: Core analysis logic
-   `ufw_handler.py`: UFW interaction logic
-   `strategies/`: Directory containing strategy modules
    -   `base_strategy.py`: Abstract base class
    -   `unified.py`: Unified blocking strategy

## License

This software is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License** (CC BY-NC 4.0).

You are free to:
- Share: copy and redistribute the material in any medium or format
- Adapt: remix, transform, and build upon the material

Under the following terms:
- Attribution: You must give appropriate credit to LA Referencia, provide a link to the license, and indicate if changes were made.
- NonCommercial: You may not use the material for commercial purposes.

Full license: [https://creativecommons.org/licenses/by-nc/4.0/legalcode](https://creativecommons.org/licenses/by-nc/4.0/legalcode)

> **⚠️ DISCLAIMER: EXPERIMENTAL SOFTWARE**
>
> This software is experimental. It is crucial to fully understand the implications of adding firewall restrictions based on log analysis before applying it to production environments. Incorrect parameterization could generate massive blocks of legitimate access. LA Referencia is not responsible for improper use or consequences arising from its use. Thorough testing in development environments is strongly recommended before production deployment.
