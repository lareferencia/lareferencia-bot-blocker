# LA Referencia Dynamic Bot Blocker

Tool for analyzing web server logs, detecting potential bot threats or attacks, and optionally blocking suspicious IPs using UFW (Uncomplicated Firewall).

## Features

- ✅ Log analysis for detection of suspicious behaviors
- ✅ Attack detection based on requests per minute (RPM) patterns
- ✅ Support for IPv4 and IPv6
- ✅ Threat grouping by subnets (/24 for IPv4, /64 for IPv6)
- ✅ Automated blocking of IPs/subnets through UFW rules with expiration
- ✅ Whitelist of IPs/subnets that should never be blocked
- ✅ Optimized processing of large logs in chunks
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
  --log-level DEBUG \
  --chunk-size 50000
```

This command:
- Analyzes only entries from the last day
- Uses a threshold of 200 RPM to consider IPs suspicious
- Uses a whitelist of IPs/subnets that should not be blocked
- Exports the results in JSON format
- Saves detailed logs to a file
- Processes the log file in chunks of 50,000 lines to optimize memory

### Only Clean Expired Rules

```bash
sudo python stats.py --clean-rules
```

This command only removes expired UFW rules and exits.

## Options

| Option | Description |
|--------|-------------|
| `--file, -f` | Path to the log file to analyze |
| `--start-date, -s` | Date from which to analyze the log (format: dd/mmm/yyyy:HH:MM:SS) |
| `--time-window, -tw` | Analyze only entries from the last hour, day or week |
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
| `--chunk-size` | Chunk size for processing large logs (default: 10000, 0 to not fragment) |
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

[MIT](LICENSE)