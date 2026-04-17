#!/usr/bin/env python3
"""
Example Usage of Log File Analyzer
Demonstrates how to use the analyzer with custom configurations
"""

from log_analyzer import LogAnalyzer

# Example 1: Basic usage with default settings
print("Example 1: Basic Analysis")
print("-" * 60)
analyzer = LogAnalyzer()
analyzer.analyze(apache_log='sample_apache.log', ssh_log='sample_ssh.log')

# Example 2: Custom threshold configuration
print("\n\nExample 2: Custom Thresholds")
print("-" * 60)
analyzer2 = LogAnalyzer()
# Adjust thresholds for more sensitive detection
analyzer2.BRUTE_FORCE_THRESHOLD = 3  # Lower threshold = more sensitive
analyzer2.SCAN_THRESHOLD = 5
analyzer2.DOS_THRESHOLD = 50
analyzer2.analyze(apache_log='sample_apache.log', ssh_log='sample_ssh.log')

# Example 3: Programmatic access to results
print("\n\nExample 3: Programmatic Result Access")
print("-" * 60)
analyzer3 = LogAnalyzer()
logs = analyzer3.analyze(apache_log='sample_apache.log', ssh_log='sample_ssh.log')

# Access threats programmatically
high_severity_threats = [t for t in analyzer3.threats if t['severity'] == 'HIGH']
print(f"\nFound {len(high_severity_threats)} HIGH severity threats:")
for threat in high_severity_threats:
    print(f"  - {threat['type']} from {threat['ip']}")

# Get unique attacking IPs
attacking_ips = set([t['ip'] for t in analyzer3.threats])
print(f"\nUnique attacking IPs: {attacking_ips}")

# Example 4: Export and read report
print("\n\nExample 4: Working with Reports")
print("-" * 60)
import json

# Export report
analyzer4 = LogAnalyzer()
analyzer4.analyze(apache_log='sample_apache.log', ssh_log='sample_ssh.log')

# Read and process the JSON report
with open('incident_report.json', 'r') as f:
    report = json.load(f)
    
print(f"Report timestamp: {report['timestamp']}")
print(f"Total threats: {report['summary']['total_threats']}")
print("\nThreat type breakdown:")
for threat_type, count in report['summary']['threat_types'].items():
    print(f"  {threat_type}: {count}")
