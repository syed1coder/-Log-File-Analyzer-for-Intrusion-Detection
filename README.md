# Log File Analyzer for Intrusion Detection

A Python-based security tool that analyzes Apache and SSH log files to detect suspicious patterns including brute-force attacks, port scanning, DoS attempts, and various web-based attacks.

## Features

- Parse Apache access logs and SSH authentication logs
- Detect multiple attack patterns:
  - Brute-force authentication attempts
  - Port/path scanning activity
  - Denial of Service (DoS) attacks
  - SQL injection attempts
  - Cross-site scripting (XSS) attempts
  - Path traversal attacks
- Cross-reference IPs with threat intelligence blacklists
- Generate visualizations of access patterns
- Export detailed incident reports in JSON format

## Requirements

- Python 3.7+
- pandas
- matplotlib

## Installation

```bash
pip install pandas matplotlib
```

## Usage

### Basic Usage (with sample logs)

```bash
python3 log_analyzer.py
```

This will create sample log files and analyze them automatically.

### Analyze Your Own Logs

```bash
python3 log_analyzer.py /path/to/apache.log /path/to/ssh.log
```

### Analyze Only Apache Logs

```bash
python3 log_analyzer.py /path/to/apache.log
```

### Analyze Only SSH Logs

```bash
python3 log_analyzer.py "" /path/to/ssh.log
```

## Output

The analyzer generates:

1. **Console Summary**: Overview of detected threats
2. **Visualizations** (in `output/` directory):
   - `top_ips.png`: Top 10 IP addresses by request count
   - `status_codes.png`: HTTP response status distribution
   - `ssh_status.png`: SSH authentication status distribution
   - `threat_severity.png`: Threat distribution by severity level
3. **Incident Report** (`incident_report.json`): Detailed JSON report of all detected threats

## Detection Thresholds

The analyzer uses the following thresholds (configurable in code):

- **Brute-Force**: 5+ failed login attempts from same IP
- **Port Scanning**: 10+ different paths accessed from same IP
- **DoS Attack**: 100+ requests from same IP

## Log Format Support

### Apache Access Log Format
```
IP - - [timestamp] "METHOD path PROTOCOL" status size
```

### SSH Authentication Log Format
```
timestamp hostname sshd[PID]: Failed password for user from IP port PORT
timestamp hostname sshd[PID]: Accepted password for user from IP port PORT
timestamp hostname sshd[PID]: Invalid user username from IP
```

## Customization

### Adjusting Detection Thresholds

Edit the `__init__` method in the `LogAnalyzer` class:

```python
self.BRUTE_FORCE_THRESHOLD = 5
self.SCAN_THRESHOLD = 10
self.DOS_THRESHOLD = 100
```

### Adding Custom IP Blacklist

Modify the `load_blacklist()` method to fetch from external sources:

```python
def load_blacklist(self):
    # Fetch from abuse.ch, Spamhaus, etc.
    blacklist = set()
    # Add your blacklist loading logic
    return blacklist
```

## Example Output

```
============================================================
INTRUSION DETECTION ANALYSIS SUMMARY
============================================================
Total threats detected: 5

Threat breakdown:
  - brute_force: 1
  - scanning: 1
  - blacklisted: 2
  - path_traversal: 1

Top threats:

1. Brute-Force Attack [HIGH]
   IP: 203.0.113.0
   Details: 9 failed login attempts

2. Port/Path Scanning [MEDIUM]
   IP: 192.0.2.0
   Details: Accessed 54 different paths
============================================================
```

## Security Considerations

- This tool is for analysis purposes only
- Always review automated threat detections manually
- Integrate with your incident response procedures
- Consider using additional threat intelligence feeds
- Regularly update IP blacklists from trusted sources

## License

This tool is provided as-is for educational and security analysis purposes.

## Author

Created for intrusion detection and log analysis projects.
