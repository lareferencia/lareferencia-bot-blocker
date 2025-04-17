# LA Referencia Dynamic Bot Blocker


> **⚠️ DISCLAIMER: EXPERIMENTAL SOFTWARE**
> 
> This software is experimental in nature. It is crucial to fully understand the implications of adding firewall restrictions to a system based on log analysis before applying it to production environments. Incorrect parameterization of this script could generate massive blocks of legitimate access to the service. LA Referencia is not responsible for the improper use of this script or any consequences arising from its use. It is strongly recommended to test it thoroughly in development environments before considering its use in production.

Tool for analyzing web server logs, detecting potential bot threats or attacks, and optionally blocking suspicious IPs using UFW (Uncomplicated Firewall).

## Features

- ✅ Log analysis for detection of suspicious behaviors
- ✅ Attack detection based on requests per minute (RPM) patterns
- ✅ Support for IPv4 and IPv6
- ✅ Threat grouping by subnets (/24 for IPv4, /64 for IPv6)
- ✅ Automated blocking of IPs/subnets through UFW rules with expiration
- ✅ Whitelist of IPs/subnets that should never be blocked
- ✅ Optimized processing of large logs (reads backwards efficiently when time window is specified)
- ✅ Multiple export formats (JSON, CSV, text)
- ✅ Complete logging system
- ✅ Modular and object-oriented structure

## Comparison with Fail2Ban

While Fail2Ban is a powerful intrusion prevention tool, LA Referencia Bot Blocker offers several key differences:

- **Specialized Bot Detection**: Focused specifically on identifying bot patterns and suspicious crawler behaviors in web servers, rather than general intrusion attempts.
- **Subnet Analysis**: Automatically groups related threats by subnets to detect coordinated attacks from IP ranges.
- **Request Per Minute (RPM) Analysis**: Uses RPM patterns to identify aggressive crawling rather than just matching regex patterns.
- **Batch Analysis**: Designed for both real-time monitoring and retrospective analysis of log files over specified time windows.
- **Flexible Export Options**: Provides comprehensive reports in multiple formats for integration with other tools.
- **Low Dependencies**: Minimal requirements with no database needed, making it lightweight and easy to deploy.
- **Customized for Academic Repositories**: Optimized for detecting specific patterns common in academic repository and digital library environments.

LA Referencia Bot Blocker is not a replacement for Fail2Ban but rather a complementary tool focused on web crawler behavior analysis and specialized bot detection for web applications.

## How IP Analysis Works

The LA Referencia Bot Blocker's IP analysis follows a structured approach to detect potential threats:

### Log Processing

- Processes log files in configurable chunks to optimize memory usage
- Parses each log line to extract IP addresses, timestamps, URLs, and user agents
- Applies optional date filtering to analyze only entries within a specified timeframe
- Automatically excludes whitelisted IPs from analysis

### Metrics Calculation

For each detected IP address, the system:

- Tracks all access timestamps, visited URLs, and used user agents
- Calculates key metrics:
  - RPM (Requests Per Minute): The rate of requests over time
  - Total requests made during the analyzed period
  - Time span of activity

### Threat Detection

An IP address is flagged as suspicious when:
- Its RPM exceeds the defined threshold (default: 100 RPM)
- A "danger score" is calculated based on:
  - Request rate (RPM)
  - Total request volume
  - Presence of suspicious user agents (when applicable)

### Subnet-Based Analysis

The system identifies coordinated attacks by:
- Grouping suspicious IPs by subnet:
  - IPv4: /24 subnets (256 addresses)
  - IPv6: /64 subnets
- Calculating subnet metrics:
  - Combined total requests across all IPs in the subnet
  - Aggregated danger score for the subnet
  - Count of distinct suspicious IPs within the subnet

### Threat Classification

Threats are classified into two types:
- **Individual IP threats**: Single IP addresses showing suspicious behavior
- **Subnet threats**: Multiple related IPs exhibiting coordinated suspicious activity

### Prioritization

Finally, the system:
- Sorts all threats by their danger score from highest to lowest
- Prepares the prioritized list for potential blocking action or reporting
- Exports comprehensive threat information in multiple formats (JSON, CSV, text)

This multi-tiered approach enables detection of both individual suspicious actors and more sophisticated coordinated attacks using multiple addresses within the same network range.

## Installation

The script doesn't require special installation, it only needs Python 3.6 or higher.

Requirements:
- Python 3.6+
- UFW (for blocking functionality) - Usually pre-installed on Ubuntu distributions

```bash
# Clone the repository
git clone https://github.com/username/lareferencia-botstats.git
cd lareferencia-botstats

# Optional: Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Scheduled Execution with Cron

For periodic execution, you can add the script to your system's crontab:

```bash
# Open the crontab editor
sudo crontab -e

# Add a line to run the script every hour
# Format: minute hour day month weekday command
0 * * * * /usr/bin/python3 /path/to/lareferencia-botstats/stats.py -f /var/log/apache2/access.log --block --block-threshold 50 --block-duration 120 --whitelist /etc/botstats/whitelist.txt --log-file /var/log/botstats.log >> /var/log/botstats_cron.log 2>&1

# Or run it daily at midnight
0 0 * * * /usr/bin/python3 /path/to/lareferencia-botstats/stats.py -f /var/log/apache2/access.log --time-window day --block --block-threshold 100 --block-duration 1440 --whitelist /etc/botstats/whitelist.txt --log-file /var/log/botstats.log >> /var/log/botstats_cron.log 2>&1

# Add a line to clean expired rules every 15 minutes
*/15 * * * * /usr/bin/python3 /path/to/lareferencia-botstats/stats.py --clean-rules >> /var/log/botstats_clean.log 2>&1
```

Important considerations when scheduling with cron:
- Use absolute paths for all files and executables
- If using a virtual environment, either activate it in the command or use the full path to the Python executable in the virtual environment
- Include proper logging options to track the script's behavior
- Make sure the user running the cron job (usually root for UFW operations) has appropriate permissions
- When using `--time-window`, ensure that the window size and cron frequency make sense together to avoid analysis gaps
- For production environments, start with conservative blocking thresholds and durations, then adjust after monitoring results


## Usage

### Basic Example

```bash
python stats.py -f /var/log/apache2/access.log
```

This command will analyze the log and display the 10 most dangerous threats detected, without performing any blocking action.

### Analysis and Automatic Blocking

```bash
sudo python stats.py -f /var/log/apache2/access.log --block --block-threshold 20 --block-duration 120
```

This command will analyze the log, block IPs/subnets with more than 20 requests in the analyzed period for 120 minutes.

### Advanced Options

```bash
python stats.py -f /var/log/nginx/access.log \
  --time-window day \
  --threshold 200 \
  --whitelist /etc/botstats/whitelist.txt \
  --output threats.json \
  --format json \
  --log-file /var/log/botstats.log \
  --log-level DEBUG
```

This command:
- Analyzes only entries from the last day (reads log backwards efficiently)
- Uses a threshold of 200 RPM to consider IPs suspicious
- Uses a whitelist of IPs/subnets that should not be blocked
- Exports the results in JSON format
- Saves detailed logs to a file
- Processes the log file efficiently, stopping when entries are outside the time window

### Only Clean Expired Rules

```bash
sudo python stats.py --clean-rules
```

This command only removes expired UFW rules and exits.

## Options

| Option | Description |
|--------|-------------|
| `--file, -f` | Path to the log file to analyze |
| `--start-date, -s` | Date from which to analyze the log (format: dd/mmm/yyyy:HH:MM:SS). Implies reverse reading. |
| `--time-window, -tw` | Analyze only entries from the last hour, day or week. Implies reverse reading. |
| `--threshold, -t` | RPM threshold to consider an IP suspicious (default: 100) |
| `--top, -n` | Number of most dangerous threats to display (default: 10) |
| `--block` | Enable blocking of threats using UFW |
| `--block-threshold` | Threshold of total requests to activate UFW blocking (default: 10) |
| `--block-duration` | Duration of the block in minutes (default: 60) |
| `--dry-run` | Show UFW commands without executing them |
| `--whitelist, -w` | File with list of IPs or subnets that should never be blocked |
| `--output, -o` | File to save the analysis results |
| `--format` | Output format: json, csv or text (default: text) |
| `--log-file` | File to save execution logs |
| `--log-level` | Log detail level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO) |
| `--clean-rules` | Run cleanup of expired UFW rules and exit |

## Whitelist Format

The whitelist file should contain one IP or subnet per line. Examples:

```
# Comments start with #
192.168.1.1
10.0.0.0/8
2001:db8::/64
# Individual IPv6 IPs can also be included
2001:db8::1
```

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