# LA Referencia Dynamic Bot Blocker

> **⚠️ DISCLAIMER: EXPERIMENTAL SOFTWARE**
>
> This software is experimental. It is crucial to fully understand the implications of adding firewall restrictions based on log analysis before applying it to production environments. Incorrect parameterization of this script could block legitimate access. LA Referencia is not responsible for improper use or any consequences arising from its use. **Thorough testing in development environments is strongly recommended before production deployment.**

This tool analyzes web server logs (e.g., Apache, Nginx) using Pandas to identify potential bot threats based on request patterns and activity levels. It groups suspicious activity by subnet and can optionally block identified threats using UFW (Uncomplicated Firewall) rules with automatic expiration.

## Features

-   ✅ **Log Analysis:** Parses common web server log formats.
-   ✅ **Pandas Integration:** Leverages Pandas DataFrames for efficient metric calculation (RPM, request counts, time spans).
-   ✅ **Threat Grouping:** Aggregates IP-level metrics by subnet (/24 for IPv4, /64 for IPv6) to identify coordinated activity.
-   ✅ **Simplified Supernet Blocking (NEW):** Automatically blocks the encompassing /16 supernet (IPv4) if it contains multiple /24 subnets where at least one meets the blocking criteria, preventing redundant individual blocks.
-   ✅ **Configurable Strategies:** Uses selectable strategies to score threats (/24 or /64) and determine blocking actions based on different criteria (volume, danger score, IP count, peak RPM).
-   ✅ **Automated Blocking:** Integrates with UFW to insert temporary `deny` rules with comments indicating expiration time (ISO 8601 UTC). Supports blocking individual IPs, /24 or /64 subnets, and /16 supernets based on the simplified logic.
-   ✅ **Rule Cleanup:** Includes a mode to automatically remove expired UFW rules added by this script.
-   ✅ **Whitelisting:** Supports excluding specific IPs or subnets from analysis and blocking.
-   ✅ **Efficient Log Reading:** Can process logs in reverse when a time window (`--time-window` or `--start-date`) is specified, significantly speeding up analysis of recent activity in large files.
-   ✅ **Multiple Export Formats:** Outputs detailed threat reports in JSON, CSV, or human-readable text.
-   ✅ **Logging:** Provides configurable logging for monitoring script execution.

## Comparison with Fail2Ban

While Fail2Ban is an excellent general-purpose intrusion prevention tool, this script offers specific advantages for web server bot detection:

-   **Focus on Request Patterns:** Analyzes request rates (RPM) and volumes over time, rather than just matching specific log lines (like failed logins).
-   **Subnet Aggregation:** Automatically groups related IPs by network to detect broader, potentially distributed activity from a single source network.
-   **Strategy-Based Scoring:** Offers flexible, configurable strategies to define what constitutes a "threat" based on combinations of metrics (volume, danger, coordination, peak activity).
-   **Retrospective Analysis:** Easily analyze historical logs for specific time windows (e.g., "last day," "last hour").
-   **Pandas Efficiency:** Uses Pandas for potentially faster and more memory-efficient calculation of metrics on large datasets compared to iterative line-by-line processing for complex stats.

This tool can complement Fail2Ban by focusing specifically on abusive web crawling/scraping patterns.

## How Analysis Works

1.  **Log Parsing:** Reads the specified log file (forwards or backwards). Each line matching the common log format is parsed to extract IP, timestamp, and other details.
2.  **Filtering:**
    *   Lines with malformed dates are skipped.
    *   IPs/subnets present in the whitelist file are ignored.
    *   If `--start-date` or `--time-window` is used, only entries within the specified period are processed.
3.  **IP Metrics Calculation (Pandas):**
    *   The filtered log entries (IP, Timestamp) are loaded into a Pandas DataFrame.
    *   For each unique IP address, the script calculates various metrics like request counts, RPM, etc.
4.  **Subnet Aggregation (Pandas):**
    *   IPs are grouped by their calculated subnet (/24 for IPv4, /64 for IPv6).
    *   For each subnet, the script aggregates metrics from the IPs within it (total requests, IP count, danger score, average/max IP RPM, total subnet RPM, etc.).
5.  **Strategy Application (/24 or /64):**
    *   The script loads the selected `--block-strategy`.
    *   For each subnet, the strategy calculates a `strategy_score` and determines if it `should_block` based on the strategy's criteria and thresholds (e.g., `--block-threshold`, `--block-danger-threshold`). A list of 'blockable' threats is maintained.
6.  **Sorting & Filtering:** All threats (/24 or /64) are sorted in descending order based on the `strategy_score` for reporting purposes.
7.  **Blocking (Optional):** If `--block` is enabled:
    *   **Supernet /16 Blocking Check:** The script groups all 'blockable' IPv4 /24 threats by their /16 supernet. If any /16 supernet contains **two or more** such /24 threats, the entire /16 supernet is blocked using the standard `--block-duration`. Subnets contained within a blocked /16 are marked to avoid redundant blocking.
    *   **Individual Blocking:** It then iterates through the **top N** individual threats (/24, /64, or single IPs) from the sorted list. If a threat `should_block` (based on its strategy) AND it wasn't already covered by a /16 block, `ufw_handler` attempts to insert a `deny` rule using `--block-duration`.
8.  **Reporting:** Displays the top N individual threats to the console, indicating if they were blocked directly or covered by a /16 block. Optionally exports the *individual* threat list to a file (`--output`).
9.  **Rule Cleanup:** The `--clean-rules` mode scans UFW rules for comments matching the script's format and removes rules whose expiration timestamp has passed.

## Installation

Requires **Python 3.7+** (due to Pandas dependencies and f-string usage) and **UFW** (for blocking).

```bash
# 1. Clone the repository
git clone https://github.com/LA-Referencia/lareferencia-bot-blocker.git
cd lareferencia-bot-blocker

# 2. (Recommended) Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt # Installs pandas
```

## Scheduled Execution with Cron

For periodic analysis and blocking, use `cron`. Ensure you use absolute paths and the correct Python executable (especially if using a virtual environment).

```bash
# Open the crontab editor (usually requires sudo for UFW access)
sudo crontab -e

# --- Example 1: Analyze last hour's logs every hour, block based on 'combined' strategy ---
# Note: Adjust paths, log file, and parameters as needed.
# Use the Python from the virtual environment if you created one.
# Add --log-file for better debugging. Redirect stdout/stderr for cron logs.
0 * * * * /path/to/lareferencia-bot-blocker/venv/bin/python3 /path/to/lareferencia-bot-blocker/stats.py \
    -f /var/log/apache2/access.log \
    --time-window hour \
    --block \
    --block-strategy combined \
    --block-threshold 100 \
    --block-danger-threshold 50 \
    --block-ip-count-threshold 10 \
    --block-duration 120 \
    --whitelist /etc/lareferencia-bot-blocker/whitelist.txt \
    --log-file /var/log/lareferencia-bot-blocker.log \
    >> /var/log/lareferencia-bot-blocker-cron.log 2>&1

# --- Example 2: Analyze last day's logs once daily at 1 AM ---
0 1 * * * /path/to/lareferencia-bot-blocker/venv/bin/python3 /path/to/lareferencia-bot-blocker/stats.py \
    -f /var/log/nginx/access.log \
    --time-window day \
    --block \
    --block-strategy volume_danger \
    --block-threshold 200 \
    --block-danger-threshold 100 \
    --block-duration 1440 \
    --whitelist /etc/lareferencia-bot-blocker/whitelist.txt \
    --log-file /var/log/lareferencia-bot-blocker.log \
    >> /var/log/lareferencia-bot-blocker-cron.log 2>&1

# --- Example 3: Run rule cleanup every 15 minutes ---
*/15 * * * * /path/to/lareferencia-bot-blocker/venv/bin/python3 /path/to/lareferencia-bot-blocker/stats.py --clean-rules >> /var/log/lareferencia-bot-blocker-clean.log 2>&1

```

**Cron Job Considerations:**

-   **Permissions:** The user running the cron job needs `sudo` privileges (without password prompt) to execute `ufw` commands if `--block` or `--clean-rules` is used. Configure `sudoers` carefully.
-   **Paths:** Always use absolute paths for the script, log files, whitelist, and Python executable.
-   **Logging:** Use `--log-file` and redirect cron output (`>> ... 2>&1`) to capture errors and execution details.
-   **Time Windows:** Ensure the `--time-window` aligns logically with the cron frequency. Analyzing the 'last hour' every 5 minutes might be inefficient. Analyzing the 'last day' once a day is typical.
-   **Parameter Tuning:** Start with higher thresholds and shorter `--block-duration` in production. Monitor logs and adjust parameters based on observed behavior and false positives.

## Usage

### Basic Analysis (No Blocking)

```bash
# Analyze entire log, show top 10 threats sorted by default strategy ('volume_danger')
python3 stats.py -f /var/log/apache2/access.log

# Analyze last hour, show top 20 threats
python3 stats.py -f /var/log/nginx/access.log --time-window hour --top 20

# Analyze using a different strategy for sorting/display
python3 stats.py -f /var/log/apache2/access.log --block-strategy volume_coordination
```

### Analysis and Blocking

**Requires `sudo` or appropriate permissions.**

```bash
# Analyze last day, block top 10 threats meeting 'volume_danger' criteria
# Automatically blocks /16 if >=2 contained /24s are blockable
sudo python3 stats.py -f /var/log/apache2/access.log --time-window day --block \
    --block-strategy volume_danger \
    --block-threshold 100 \
    --block-danger-threshold 50 \
    --block-duration 120 # Block for 2 hours

# Analyze last hour, block top 5 threats meeting 'combined' criteria (Dry Run)
# Also shows potential /16 blocks in dry run output
sudo python3 stats.py -f /var/log/nginx/access.log --time-window hour --block --top 5 --dry-run \
    --block-strategy combined \
    --block-threshold 50 \
    --block-danger-threshold 25 \
    --block-ip-count-threshold 8 \
    --block-duration 60
```

### ~~Analysis with Supernet Evaluation~~ (Removed - Now Automatic)

### Exporting Results

```bash
# Analyze and save results to a JSON file
python3 stats.py -f /var/log/apache2/access.log --output threats_report.json --format json

# Analyze last week and save to CSV
python3 stats.py -f /var/log/nginx/access.log --time-window week --output weekly_threats.csv --format csv
```

### Cleaning Expired Rules

**Requires `sudo` or appropriate permissions.**

```bash
# Remove expired UFW rules added by this script
sudo python3 stats.py --clean-rules

# See which rules would be removed (Dry Run)
sudo python3 stats.py --clean-rules --dry-run
```

## Options

| Option                       | Description                                                                                                | Default         |
| :--------------------------- | :--------------------------------------------------------------------------------------------------------- | :-------------- |
| `--file, -f`                 | Path to the log file to analyze (required unless `--clean-rules`).                                         | `None`          |
| `--start-date, -s`           | Analyze logs from this date/time (Format: `dd/Mmm/YYYY:HH:MM:SS`, e.g., `16/Apr/2024:10:00:00`).             | `None`          |
| `--time-window, -tw`         | Analyze logs from the `hour`, `day`, or `week` (overrides `--start-date`).                                   | `None`          |
| `--top, -n`                  | Number of top *individual* threats (/24 or /64 by strategy score) to display and consider for blocking.    | `10`            |
| `--whitelist, -w`            | Path to a file containing IPs/subnets to exclude (one per line, `#` for comments).                         | `None`          |
| `--block`                    | Enable blocking of threats using UFW. Requires appropriate permissions.                                    | `False`         |
| `--block-strategy`           | Strategy for scoring *individual* threats (`volume_danger`, `volume_coordination`, `volume_peak_rpm`, `combined`, `peak_total_rpm`, `coordinated_sustained`). | `volume_danger` |
| `--block-threshold`          | Base: Minimum total requests for an individual subnet to be considered by any strategy.                    | `100`           |
| `--block-danger-threshold`   | Strategy: Minimum aggregated IP danger score (used by `volume_danger`, `combined`).                        | `50.0`          |
| `--block-ip-count-threshold` | Strategy: Minimum number of unique IPs (used by `volume_coordination`, `combined`, `coordinated_sustained`). | `10`            |
| `--block-max-rpm-threshold`  | Strategy: Minimum peak RPM from any *individual* IP (used by `volume_peak_rpm`).                           | `62.0`          |
| `--block-total-max-rpm-threshold` | Strategy: Minimum peak **TOTAL SUBNET RPM** (max requests per minute for the entire subnet) (used by `peak_total_rpm`). | `62.0`          |
| `--block-subnet-avg-rpm-threshold` | Strategy: Minimum average **TOTAL SUBNET RPM** (average requests per minute for the entire subnet when active) (used by `coordinated_sustained`). | `60.0`          |
| `--block-min-timespan-seconds` | Strategy: Minimum duration in seconds of subnet activity (first to last request) (used by `coordinated_sustained`). | `1800`          |
| `--block-duration`           | Duration of the UFW block in minutes (used for individual blocks and automatic /16 blocks).              | `60`            |
| `--dry-run`                  | Show UFW commands that would be executed, but do not execute them.                                         | `False`         |
| `--output, -o`               | File path to save the analysis results (currently exports individual threats).                             | `None`          |
| `--format`                   | Output format for the results file (`json`, `csv`, `text`).                                                | `text`          |
| `--log-file`                 | File path to save execution logs.                                                                          | `None`          |
| `--log-level`                | Logging detail level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).                                    | `INFO`          |
| `--clean-rules`              | Run cleanup of expired UFW rules (matching script's comment format) and exit. Requires permissions.        | `False`         |

## Blocking Strategies (`--block-strategy`)

Strategies define how threats are scored and whether they should be blocked. All strategies first check if `total_requests >= --block-threshold`.

1.  **`volume_danger` (Default)**
    *   **Goal:** Catch subnets with significant request volume where the *combined behavior* of IPs is aggressive.
    *   **Score:** Primarily based on `aggregated_ip_danger_score`, secondarily on `total_requests`.
    *   **Blocks If:** `total_requests >= --block-threshold` **AND** `aggregated_ip_danger_score >= --block-danger-threshold`.
    *   **Tuning:** Adjust `--block-threshold` and `--block-danger-threshold`. Good general-purpose starting point.

2.  **`volume_coordination`**
    *   **Goal:** Catch potentially distributed attacks or widespread scanning from multiple IPs within the same network range.
    *   **Score:** Primarily based on `ip_count`, secondarily on `total_requests`.
    *   **Blocks If:** `total_requests >= --block-threshold` **AND** `ip_count >= --block-ip-count-threshold`.
    *   **Tuning:** Adjust `--block-threshold` and `--block-ip-count-threshold`. Useful for high IP count scenarios.

3.  **`volume_peak_rpm`**
    *   **Goal:** Catch subnets containing at least one *highly* aggressive *individual* IP (bursts).
    *   **Score:** Primarily based on `subnet_max_ip_rpm` (max RPM of any single IP), secondarily on `total_requests`.
    *   **Blocks If:** `total_requests >= --block-threshold` **AND** `subnet_max_ip_rpm >= --block-max-rpm-threshold`.
    *   **Tuning:** Adjust `--block-threshold` and `--block-max-rpm-threshold`. Useful for stopping brute-force bursts from single IPs.

4.  **`combined`**
    *   **Goal:** Catch subnets meeting volume threshold and *either* high aggregated danger *or* high coordination.
    *   **Score:** Weighted sum of `aggregated_ip_danger_score`, `ip_count`, and `total_requests`.
    *   **Blocks If:** `total_requests >= --block-threshold` **AND** (`aggregated_ip_danger_score >= --block-danger-threshold` **OR** `ip_count >= --block-ip-count-threshold`).
    *   **Tuning:** Requires tuning three thresholds. Acts as a broader net.

5.  **`peak_total_rpm`** (Replaces `sustained_avg_rpm`)
    *   **Goal:** Catch subnets exhibiting high *peak* request rates **considering all requests from the subnet combined in any single minute**.
    *   **Score:** Primarily based on `subnet_total_max_rpm`, secondarily on `total_requests`.
    *   **Blocks If:** `total_requests >= --block-threshold` **AND** `subnet_total_max_rpm >= --block-total-max-rpm-threshold`.
    *   **Tuning:** Adjust `--block-threshold` for volume and `--block-total-max-rpm-threshold` to define the peak *total subnet rate* considered abusive. Good for identifying short, intense, coordinated bursts from a subnet.

6.  **`coordinated_sustained` (NEW)**
    *   **Goal:** Catch subnets showing strong signs of coordinated, sustained, and high-rate activity. Designed to target persistent, distributed bots.
    *   **Score:** Weighted sum prioritizing `ip_count`, then `total_requests`, then `subnet_total_avg_rpm`, then `subnet_time_span`.
    *   **Blocks If:** `total_requests >= --block-threshold` **AND** `ip_count >= --block-ip-count-threshold` **AND** `subnet_total_avg_rpm >= --block-subnet-avg-rpm-threshold` **AND** `subnet_time_span >= --block-min-timespan-seconds`.
    *   **Tuning:** Requires tuning four thresholds (`--block-threshold`, `--block-ip-count-threshold`, `--block-subnet-avg-rpm-threshold`, `--block-min-timespan-seconds`). More specific targeting, potentially fewer blocks than broader strategies.

**Note:** The final list of threats is always sorted based on the `strategy_score` calculated by the selected strategy. Blocking actions only apply to the `--top` N threats *that also meet the strategy's specific blocking conditions*.

## Whitelist Format

The whitelist file (specified via `--whitelist`) should contain one IP address or CIDR subnet per line. Lines starting with `#` are ignored.

## Project Structure

The code is organized in modules:

- `stats.py`: Main script that coordinates the entire process
- `log_parser.py`: Module for parsing and analyzing web server logs
- `threat_analyzer.py`: Module for analysis and threat detection
- `ufw_handler.py`: Module for handling interactions with UFW

## Development

To contribute to the project:

1. Fork the repository
2. Create a branch for your feature (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new functionality'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## License

This software is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License** (CC BY-NC 4.0).

You are free to:
- Share: copy and redistribute the material in any medium or format
- Adapt: remix, transform, and build upon the material

Under the following terms:
- Attribution: You must give appropriate credit to LA Referencia, provide a link to the license, and indicate if changes were made.
- NonCommercial: You may not use the material for commercial purposes.

This is a human-readable summary of the license. The full license is available at:
[https://creativecommons.org/licenses/by-nc/4.0/legalcode](https://creativecommons.org/licenses/by-nc/4.0/legalcode)

> **⚠️ DISCLAIMER: EXPERIMENTAL SOFTWARE**
> 
> This software is experimental in nature. It is crucial to fully understand the implications of adding firewall restrictions to a system based on log analysis before applying it to production environments. Incorrect parameterization of this script could generate massive blocks of legitimate access to the service. LA Referencia is not responsible for the improper use of this script or any consequences arising from its use. It is strongly recommended to test it thoroughly in development environments before considering its use in production.