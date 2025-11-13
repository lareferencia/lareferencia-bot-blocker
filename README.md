# LA Referencia Dynamic Bot Blocker

> **⚠️ DISCLAIMER: EXPERIMENTAL SOFTWARE**
>
> This software is experimental. It is crucial to fully understand the implications of adding firewall restrictions based on log analysis before applying it to production environments. Incorrect parameterization of this script could block legitimate access. LA Referencia is not responsible for improper use or any consequences arising from its use. **Thorough testing in development environments is strongly recommended before production deployment.**

This tool analyzes web server logs (e.g., Apache, Nginx) to identify potential bot threats based on request patterns and activity levels. It groups suspicious activity by subnet and can optionally block identified threats using UFW (Uncomplicated Firewall) rules with automatic expiration.

## Features

-   ✅ **Log Analysis:** Parses common web server log formats.
-   ✅ **Lightweight Processing:** Uses native Python data structures for efficient metric calculation.
-   ✅ **Unified Strategy:** Simple evaluation based on request rate, sustained activity, and CPU load.
-   ✅ **Threat Grouping:** Aggregates IP-level metrics by subnet (/24 for IPv4, /64 for IPv6).
-   ✅ **Simplified Supernet Blocking:** Automatically blocks /16 supernet if it contains >= 2 blockable /24 subnets.
-   ✅ **Automated Blocking:** Integrates with UFW to insert temporary `deny` rules with expiration time.
-   ✅ **Strike System & Escalation:** Tracks block events and escalates block duration for repeat offenders.
-   ✅ **Rule Cleanup:** Includes a mode to automatically remove expired UFW rules.
-   ✅ **Whitelisting:** Supports excluding specific IPs or subnets from analysis and blocking.
-   ✅ **Multiple Export Formats:** Outputs threat reports in JSON, CSV, or human-readable text.

## How It Works

The unified strategy evaluates three conditions for each subnet:

1. **RPM Threshold:** Request rate per minute (default: 20 req/min)
2. **Sustained Activity:** Percentage of analysis window subnet was active (default: 50%)
3. **CPU Load:** System 15-minute load average (default: 5.0)

**Blocking occurs when conditions 1 AND 2 are met** (score >= 2.0). CPU load is monitored but not required for blocking.

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
# Analyze entire log, show top 10 threats
python3 blocker.py -f /var/log/apache2/access.log

# Analyze last hour, show top 20 threats
python3 blocker.py -f /var/log/nginx/access.log --time-window hour --top 20
```

### Analysis and Blocking

**Requires `sudo` or appropriate permissions.**

```bash
# Analyze last day, block top threats
sudo python3 blocker.py -f /var/log/apache2/access.log \
    --time-window day \
    --block \
    --min-rpm-threshold 20.0 \
    --min-sustained-percent 50.0 \
    --max-cpu-load-threshold 5.0 \
    --block-duration 120

# Dry run to see what would be blocked
sudo python3 blocker.py -f /var/log/nginx/access.log \
    --time-window hour \
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
| `--time-window, -tw`           | Analyze logs from the `hour`, `6hour`, `day`, or `week` (overrides `--start-date`).                     | `None`                    |
| `--top, -n`                    | Number of top threats (/24 or /64) to display and consider for blocking.                                | `10`                      |
| `--whitelist, -w`              | Path to a file containing IPs/subnets to exclude (one per line, `#` for comments).                      | `None`                    |
| `--block`                      | Enable blocking of threats using UFW. Requires appropriate permissions.                                 | `False`                   |
| `--min-rpm-threshold`          | Minimum requests per minute threshold for blocking.                                                     | `20.0`                    |
| `--min-sustained-percent`      | Minimum percentage of analysis window duration a subnet must be active for blocking.                    | `50.0`                    |
| `--max-cpu-load-threshold`     | Maximum CPU load threshold (15-minute average) for blocking consideration.                              | `5.0`                     |
| `--block-duration`             | Default duration (minutes) for UFW blocks (used if strike count < escalation threshold).               | `60`                      |
| `--block-escalation-strikes`   | Number of strikes within history window required to trigger escalated block duration (1440 min).       | `4`                       |
| `--strike-file`                | Path to the JSON file for storing strike history.                                                       | `strike_history.json`     |
| `--dry-run`                    | Show UFW commands that would be executed, but do not execute them.                                      | `False`                   |
| `--output, -o`                 | File path to save the analysis results.                                                                 | `None`                    |
| `--format`                     | Output format for the results file (`json`, `csv`, `text`).                                             | `text`                    |
| `--log-file`                   | File path to save execution logs.                                                                       | `None`                    |
| `--log-level`                  | Logging detail level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).                                 | `INFO`                    |
| `--dump-data`                  | Dump raw log data to Parquet file (requires `pyarrow`).                                                 | `False`                   |
| `--clean-rules`                | Run cleanup of expired UFW rules and exit. Requires permissions.                                        | `False`                   |
| `--silent`                     | Suppress most console output (except block actions and final summary).                                  | `False`                   |

## Unified Strategy

The simplified strategy evaluates:

1. **RPM >= min_rpm_threshold** - Sustained request rate check
2. **Sustained activity >= min_sustained_percent** - Activity persistence over analysis window
3. **CPU load <= max_cpu_load_threshold** - System resource impact (informational)

**Blocking decision:** Score >= 2.0 (conditions 1 AND 2 met)

This replaces the previous multi-strategy system with a single, focused evaluation method.

## Strike System

-   **History Storage:** Maintains block events in JSON file specified by `--strike-file`
-   **48-Hour Window:** Automatically discards timestamps older than 48 hours
-   **Escalation:** If strike count >= `--block-escalation-strikes` (default 4), block duration escalates to 1440 minutes (24 hours)
-   **Default Duration:** Otherwise uses `--block-duration` (default 60 minutes)

## Scheduled Execution with Cron

For periodic analysis and blocking, use `cron`. Ensure you use absolute paths.

```bash
# Open crontab editor (requires sudo for UFW access)
sudo crontab -e

# Analyze last hour every hour and block threats
0 * * * * /path/to/venv/bin/python3 /path/to/blocker.py -f /var/log/apache2/access.log --time-window hour --block --whitelist /etc/bot-blocker/whitelist.txt --strike-file /var/log/bot-blocker/strikes.json --silent >> /var/log/bot-blocker-cron.log 2>&1

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
