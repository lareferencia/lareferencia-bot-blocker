# LA Referencia Dynamic Bot Blocker - Simplified Version

> **⚠️ DISCLAIMER: EXPERIMENTAL SOFTWARE**
>
> This software is experimental. It is crucial to fully understand the implications of adding firewall restrictions based on log analysis before applying it to production environments. Incorrect parameterization of this script could block legitimate access. LA Referencia is not responsible for improper use or any consequences arising from its use. **Thorough testing in development environments is strongly recommended before production deployment.**

This simplified tool analyzes web server logs (e.g., Apache, Nginx) using Pandas to identify potential bot threats based on a unified strategy that considers:

1. **Request rate per minute (RPM)** - Activity intensity
2. **Sustained activity** - How long the activity has been maintained
3. **System CPU load** - Server stress level (15-minute average)

The tool groups suspicious activity by subnet and can optionally block identified threats using UFW (Uncomplicated Firewall) with automatic expiration and a strike system for repeat offenders.

## Key Features

-   ✅ **Unified Simple Strategy:** Single streamlined strategy considering RPM, sustained activity, and CPU load
-   ✅ **Log Analysis:** Parses common web server log formats efficiently with Pandas
-   ✅ **Subnet Grouping:** Aggregates IP-level metrics by subnet (/24 for IPv4, /64 for IPv6)
-   ✅ **Supernet Blocking:** Automatically blocks /16 supernets if >= 2 contained /24 subnets are blockable
-   ✅ **Automated Blocking:** Integrates with UFW for temporary deny rules with expiration timestamps
-   ✅ **Strike System:** Tracks repeat offenders and escalates block duration automatically
-   ✅ **High-Rate IP Blocking:** Blocks individual IPs exceeding configurable req/hour threshold
-   ✅ **Rule Cleanup:** Automatically removes expired UFW rules
-   ✅ **Whitelisting:** Supports excluding specific IPs/subnets from analysis
-   ✅ **Multiple Export Formats:** JSON, CSV, or text output

## How It Works

1. **Log Parsing:** Reads log file and extracts IP addresses and timestamps
2. **Filtering:** Applies whitelist and time window filters
3. **Metric Calculation:** For each subnet, calculates:
   - Total requests
   - Number of unique IPs
   - Activity timespan
   - Requests per minute (over analysis window)
4. **Unified Strategy Evaluation:** Each subnet is scored based on:
   - RPM exceeding threshold (default: 20 req/min)
   - Activity sustained for required % of window (default: 50%)
   - System CPU load above threshold (default: 5.0)
5. **Blocking Decision:** Subnets meeting RPM AND sustained activity criteria (score >= 2.0) are blocked
6. **Strike Tracking:** Repeat offenders within 48 hours get escalated block duration (24h instead of default)

## Installation

Requires **Python 3.7+**, **UFW** (for blocking), and the following Python packages:

```bash
# 1. Clone the repository
git clone https://github.com/LA-Referencia/lareferencia-bot-blocker.git
cd lareferencia-bot-blocker

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Analysis (No Blocking)

```bash
# Analyze entire log, show top 10 threats
python3 blocker.py -f /var/log/apache2/access.log

# Analyze last hour, show top 20 threats
python3 blocker.py -f /var/log/nginx/access.log --time-window hour --top 20
```

### Analysis and Blocking

**Requires `sudo` or appropriate permissions.**

```bash
# Analyze last day and block threats
sudo python3 blocker.py -f /var/log/apache2/access.log --time-window day --block \
    --min-rpm-threshold 30 \
    --min-sustained-percent 60 \
    --block-duration 120  # Block for 2 hours

# Dry run to see what would be blocked
sudo python3 blocker.py -f /var/log/nginx/access.log --time-window hour --block --dry-run \
    --min-rpm-threshold 25 \
    --max-cpu-load-threshold 4.0
```

### Cleaning Expired Rules

```bash
# Remove expired UFW rules
sudo python3 blocker.py --clean-rules

# Dry run to see which rules would be removed
sudo python3 blocker.py --clean-rules --dry-run
```

## Main Options

| Option | Description | Default |
|:-------|:------------|:--------|
| `--file, -f` | Path to log file to analyze | Required |
| `--time-window, -tw` | Analyze from last `hour`, `6hour`, `day`, or `week` | None (all) |
| `--top, -n` | Number of top threats to display/block | `10` |
| `--whitelist, -w` | File with IPs/subnets to exclude | None |
| `--block` | Enable UFW blocking | `False` |
| `--min-rpm-threshold` | Minimum requests/minute for blocking | `20.0` |
| `--min-sustained-percent` | Minimum % of window subnet must be active | `50.0` |
| `--max-cpu-load-threshold` | CPU load threshold (15-min avg) | `5.0` |
| `--block-duration` | Default block duration in minutes | `60` |
| `--block-ip-min-req-per-hour` | Block individual IPs above this rate | `400` |
| `--block-ip-duration` | Duration for high-rate IP blocks (minutes) | `1440` |
| `--block-escalation-strikes` | Strikes needed for 24h escalated block | `4` |
| `--strike-file` | Path to strike history JSON file | `strike_history.json` |
| `--dry-run` | Show what would be blocked without executing | `False` |
| `--output, -o` | File to save results | None |
| `--format` | Output format: `json`, `csv`, `text` | `text` |
| `--silent` | Suppress most output | `False` |

## Unified Strategy

The simplified strategy evaluates three conditions for each subnet:

1. **RPM Check:** `subnet_req_per_min_window > min_rpm_threshold`
2. **Sustained Activity:** `activity_timespan >= (analysis_window * min_sustained_percent / 100)`
3. **CPU Load:** `system_load_15min >= max_cpu_load_threshold` (indicates server stress)

**Blocking occurs if conditions 1 AND 2 are met** (RPM and sustained activity). Condition 3 (CPU load) adds to the score but is not mandatory for basic blocking. This allows the system to be more aggressive when under load while still catching sustained high-rate activity regardless of current system state.

**Score:** 0.0 to 3.0 (one point per condition met)  
**Blocking Threshold:** Score >= 2.0 with RPM and sustained conditions met

## Strike System

- Tracks each blocked target's history for 48 hours
- When a target accumulates `--block-escalation-strikes` (default 4) within 48 hours, block duration escalates to 24 hours
- Strike count and escalation status shown in block messages
- High-rate IP blocks do not interact with strike system

## Scheduled Execution with Cron

```bash
sudo crontab -e

# Analyze last hour every hour, block threats
0 * * * * /path/to/venv/bin/python3 /path/to/blocker.py \
    -f /var/log/apache2/access.log --time-window hour --block \
    --min-rpm-threshold 25 --whitelist /etc/bot-blocker/whitelist.txt \
    --strike-file /var/log/bot-blocker/strike_history.json --silent \
    >> /var/log/bot-blocker-cron.log 2>&1

# Clean expired rules every 30 minutes
*/30 * * * * /path/to/venv/bin/python3 /path/to/blocker.py --clean-rules \
    >> /var/log/bot-blocker-clean.log 2>&1
```

## Whitelist Format

One IP address or CIDR subnet per line. Lines starting with `#` are ignored.

```
# Local network
127.0.0.1
::1
192.168.0.0/16

# Trusted services
203.0.113.0/24
```

## Tuning Guidelines

- **`--min-rpm-threshold`**: Start with 20-30 req/min, adjust based on typical traffic patterns
- **`--min-sustained-percent`**: 50% ensures activity isn't just a brief spike
- **`--max-cpu-load-threshold`**: Set based on your server's typical load (check with `uptime`)
- Monitor the "OVERALL MAXIMUMS OBSERVED" section in output to guide threshold adjustments
- Start with shorter `--block-duration` (30-60 min) and increase as needed
- Use `--dry-run` extensively before enabling actual blocking

## License

This software is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License** (CC BY-NC 4.0).

You are free to:
- Share: copy and redistribute the material
- Adapt: remix, transform, and build upon the material

Under the following terms:
- Attribution: Credit LA Referencia, provide license link, indicate changes
- NonCommercial: No commercial use

Full license: [https://creativecommons.org/licenses/by-nc/4.0/legalcode](https://creativecommons.org/licenses/by-nc/4.0/legalcode)

## Development Notes

### Simplified Architecture

- `blocker.py`: Main script orchestrating analysis and blocking
- `parser.py`: Log file parsing into Pandas DataFrames
- `threat_analyzer.py`: Metric calculation and threat identification  
- `ufw_handler.py`: UFW firewall interaction
- `strategies/unified.py`: Unified simplified blocking strategy

### Removed Complexity

This simplified version removes:
- Multiple strategy options (now single unified strategy)
- Complex per-IP RPM calculations
- Detailed IP-level reporting
- Per-subnet total RPM metrics  
- Multiple configurable thresholds (simplified to 3 main parameters)

The focus is on lightweight, effective bot detection using essential metrics only.
