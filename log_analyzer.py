#!/usr/bin/env python3
"""
Log File Analyzer for Intrusion Detection
Detects suspicious patterns in Apache and SSH logs
"""

import re
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from collections import defaultdict, Counter
import json
import sys
from pathlib import Path

class LogAnalyzer:
    def __init__(self):
        # Known malicious IP blacklist (sample)
        self.blacklist = self.load_blacklist()
        
        # Thresholds for detection
        self.BRUTE_FORCE_THRESHOLD = 5  # Failed attempts from same IP
        self.SCAN_THRESHOLD = 10  # Different endpoints from same IP
        self.DOS_THRESHOLD = 100  # Requests per minute from same IP
        
        # Results storage
        self.threats = []
        self.stats = defaultdict(int)
        
    def load_blacklist(self):
        """Load IP blacklist from public sources"""
        # Sample blacklist - in production, fetch from abuse.ch, Spamhaus, etc.
        blacklist = {
            '192.0.2.0',  # TEST-NET-1 (example)
            '198.51.100.0',  # TEST-NET-2 (example)
            '203.0.113.0',  # TEST-NET-3 (example)
        }
        return blacklist
    
    def parse_apache_log(self, log_file):
        """Parse Apache access log"""
        apache_pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-)'
        
        logs = []
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.match(apache_pattern, line)
                    if match:
                        ip, timestamp, method, path, protocol, status, size = match.groups()
                        logs.append({
                            'ip': ip,
                            'timestamp': timestamp,
                            'method': method,
                            'path': path,
                            'status': int(status),
                            'size': 0 if size == '-' else int(size),
                            'type': 'apache'
                        })
        except FileNotFoundError:
            print(f"Warning: Apache log file {log_file} not found")
        
        return logs
    
    def parse_ssh_log(self, log_file):
        """Parse SSH authentication log"""
        ssh_patterns = {
            'failed': r'Failed password for (\w+) from (\S+) port (\d+)',
            'accepted': r'Accepted password for (\w+) from (\S+) port (\d+)',
            'invalid': r'Invalid user (\w+) from (\S+)',
        }
        
        logs = []
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Extract timestamp
                    timestamp_match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                    timestamp = timestamp_match.group(1) if timestamp_match else 'Unknown'
                    
                    # Check for failed login
                    match = re.search(ssh_patterns['failed'], line)
                    if match:
                        user, ip, port = match.groups()
                        logs.append({
                            'ip': ip,
                            'timestamp': timestamp,
                            'user': user,
                            'status': 'failed',
                            'type': 'ssh'
                        })
                    
                    # Check for successful login
                    match = re.search(ssh_patterns['accepted'], line)
                    if match:
                        user, ip, port = match.groups()
                        logs.append({
                            'ip': ip,
                            'timestamp': timestamp,
                            'user': user,
                            'status': 'accepted',
                            'type': 'ssh'
                        })
                    
                    # Check for invalid user
                    match = re.search(ssh_patterns['invalid'], line)
                    if match:
                        user, ip = match.groups()
                        logs.append({
                            'ip': ip,
                            'timestamp': timestamp,
                            'user': user,
                            'status': 'invalid',
                            'type': 'ssh'
                        })
        except FileNotFoundError:
            print(f"Warning: SSH log file {log_file} not found")
        
        return logs
    
    def detect_brute_force(self, logs):
        """Detect brute-force attacks (SSH)"""
        ssh_logs = [log for log in logs if log.get('type') == 'ssh']
        failed_attempts = defaultdict(list)
        
        for log in ssh_logs:
            if log.get('status') in ['failed', 'invalid']:
                failed_attempts[log['ip']].append(log)
        
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= self.BRUTE_FORCE_THRESHOLD:
                self.threats.append({
                    'type': 'Brute-Force Attack',
                    'severity': 'HIGH',
                    'ip': ip,
                    'details': f"{len(attempts)} failed login attempts",
                    'usernames': list(set([a.get('user', 'unknown') for a in attempts])),
                    'first_seen': attempts[0]['timestamp'],
                    'last_seen': attempts[-1]['timestamp']
                })
                self.stats['brute_force'] += 1
    
    def detect_port_scanning(self, logs):
        """Detect port scanning activity (Apache)"""
        apache_logs = [log for log in logs if log.get('type') == 'apache']
        ip_paths = defaultdict(set)
        
        for log in apache_logs:
            ip_paths[log['ip']].add(log['path'])
        
        for ip, paths in ip_paths.items():
            if len(paths) >= self.SCAN_THRESHOLD:
                self.threats.append({
                    'type': 'Port/Path Scanning',
                    'severity': 'MEDIUM',
                    'ip': ip,
                    'details': f"Accessed {len(paths)} different paths",
                    'sample_paths': list(paths)[:10]
                })
                self.stats['scanning'] += 1
    
    def detect_dos(self, logs):
        """Detect potential DoS attacks"""
        apache_logs = [log for log in logs if log.get('type') == 'apache']
        
        # Count requests per IP per minute approximation
        ip_requests = defaultdict(int)
        
        for log in apache_logs:
            ip_requests[log['ip']] += 1
        
        for ip, count in ip_requests.items():
            # Simplified: check total requests (in production, use time windows)
            if count >= self.DOS_THRESHOLD:
                self.threats.append({
                    'type': 'Potential DoS Attack',
                    'severity': 'CRITICAL',
                    'ip': ip,
                    'details': f"{count} requests detected"
                })
                self.stats['dos'] += 1
    
    def check_blacklist(self, logs):
        """Cross-reference IPs with blacklist"""
        unique_ips = set([log['ip'] for log in logs])
        
        for ip in unique_ips:
            if ip in self.blacklist:
                self.threats.append({
                    'type': 'Blacklisted IP',
                    'severity': 'HIGH',
                    'ip': ip,
                    'details': 'IP found in threat intelligence blacklist'
                })
                self.stats['blacklisted'] += 1
    
    def detect_suspicious_patterns(self, logs):
        """Detect other suspicious patterns"""
        apache_logs = [log for log in logs if log.get('type') == 'apache']
        
        # SQL Injection attempts
        sql_patterns = [r'union.*select', r'or\s+1\s*=\s*1', r'drop\s+table', r"'\s*or\s*'1"]
        
        # XSS attempts
        xss_patterns = [r'<script', r'javascript:', r'onerror=']
        
        # Path traversal
        traversal_patterns = [r'\.\./\.\./']
        
        for log in apache_logs:
            path = log['path'].lower()
            
            # Check for SQL injection
            for pattern in sql_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    self.threats.append({
                        'type': 'SQL Injection Attempt',
                        'severity': 'HIGH',
                        'ip': log['ip'],
                        'details': f"Suspicious pattern in: {log['path']}"
                    })
                    self.stats['sql_injection'] += 1
                    break
            
            # Check for XSS
            for pattern in xss_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    self.threats.append({
                        'type': 'XSS Attempt',
                        'severity': 'MEDIUM',
                        'ip': log['ip'],
                        'details': f"Suspicious pattern in: {log['path']}"
                    })
                    self.stats['xss'] += 1
                    break
            
            # Check for path traversal
            for pattern in traversal_patterns:
                if re.search(pattern, path):
                    self.threats.append({
                        'type': 'Path Traversal Attempt',
                        'severity': 'HIGH',
                        'ip': log['ip'],
                        'details': f"Suspicious pattern in: {log['path']}"
                    })
                    self.stats['path_traversal'] += 1
                    break
    
    def visualize_results(self, logs, output_dir='output'):
        """Create visualizations of access patterns"""
        Path(output_dir).mkdir(exist_ok=True)
        
        if not logs:
            print("No logs to visualize")
            return
        
        # IP distribution
        ip_counts = Counter([log['ip'] for log in logs])
        top_ips = ip_counts.most_common(10)
        
        if top_ips:
            plt.figure(figsize=(12, 6))
            ips, counts = zip(*top_ips)
            plt.barh(range(len(ips)), counts)
            plt.yticks(range(len(ips)), ips)
            plt.xlabel('Number of Requests')
            plt.title('Top 10 IP Addresses by Request Count')
            plt.tight_layout()
            plt.savefig(f'{output_dir}/top_ips.png', dpi=300, bbox_inches='tight')
            plt.close()
        
        # Apache status codes distribution
        apache_logs = [log for log in logs if log.get('type') == 'apache']
        if apache_logs:
            status_counts = Counter([log['status'] for log in apache_logs])
            
            plt.figure(figsize=(10, 6))
            statuses, counts = zip(*sorted(status_counts.items()))
            colors = ['green' if s < 400 else 'orange' if s < 500 else 'red' for s in statuses]
            plt.bar(range(len(statuses)), counts, color=colors)
            plt.xticks(range(len(statuses)), statuses)
            plt.xlabel('HTTP Status Code')
            plt.ylabel('Count')
            plt.title('HTTP Response Status Distribution')
            plt.tight_layout()
            plt.savefig(f'{output_dir}/status_codes.png', dpi=300, bbox_inches='tight')
            plt.close()
        
        # SSH activity
        ssh_logs = [log for log in logs if log.get('type') == 'ssh']
        if ssh_logs:
            status_counts = Counter([log.get('status', 'unknown') for log in ssh_logs])
            
            plt.figure(figsize=(8, 6))
            labels = list(status_counts.keys())
            sizes = list(status_counts.values())
            colors = ['red' if l == 'failed' else 'orange' if l == 'invalid' else 'green' for l in labels]
            plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            plt.title('SSH Authentication Status Distribution')
            plt.tight_layout()
            plt.savefig(f'{output_dir}/ssh_status.png', dpi=300, bbox_inches='tight')
            plt.close()
        
        # Threat severity distribution
        if self.threats:
            severity_counts = Counter([t['severity'] for t in self.threats])
            
            plt.figure(figsize=(8, 6))
            severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            counts = [severity_counts.get(s, 0) for s in severities]
            colors = ['darkred', 'red', 'orange', 'yellow']
            
            plt.bar(severities, counts, color=colors)
            plt.xlabel('Severity Level')
            plt.ylabel('Number of Threats')
            plt.title('Threat Distribution by Severity')
            plt.tight_layout()
            plt.savefig(f'{output_dir}/threat_severity.png', dpi=300, bbox_inches='tight')
            plt.close()
        
        print(f"Visualizations saved to {output_dir}/")
    
    def export_report(self, output_file='incident_report.json'):
        """Export incident report as JSON"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_threats': len(self.threats),
                'threat_types': dict(self.stats)
            },
            'threats': self.threats
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Incident report exported to {output_file}")
        return report
    
    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("INTRUSION DETECTION ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total threats detected: {len(self.threats)}")
        print("\nThreat breakdown:")
        for threat_type, count in self.stats.items():
            print(f"  - {threat_type}: {count}")
        
        print("\nTop threats:")
        for i, threat in enumerate(self.threats[:10], 1):
            print(f"\n{i}. {threat['type']} [{threat['severity']}]")
            print(f"   IP: {threat['ip']}")
            print(f"   Details: {threat['details']}")
        
        if len(self.threats) > 10:
            print(f"\n... and {len(self.threats) - 10} more threats")
        print("="*60 + "\n")
    
    def analyze(self, apache_log=None, ssh_log=None):
        """Main analysis function"""
        all_logs = []
        
        # Parse logs
        if apache_log:
            print(f"Parsing Apache log: {apache_log}")
            all_logs.extend(self.parse_apache_log(apache_log))
        
        if ssh_log:
            print(f"Parsing SSH log: {ssh_log}")
            all_logs.extend(self.parse_ssh_log(ssh_log))
        
        if not all_logs:
            print("No logs to analyze")
            return
        
        print(f"Total log entries parsed: {len(all_logs)}")
        
        # Run detection algorithms
        print("\nRunning intrusion detection...")
        self.detect_brute_force(all_logs)
        self.detect_port_scanning(all_logs)
        self.detect_dos(all_logs)
        self.check_blacklist(all_logs)
        self.detect_suspicious_patterns(all_logs)
        
        # Generate visualizations
        print("\nGenerating visualizations...")
        self.visualize_results(all_logs)
        
        # Print summary
        self.print_summary()
        
        # Export report
        self.export_report()
        
        return all_logs


def create_sample_logs():
    """Create sample log files for demonstration"""
    # Sample Apache log
    apache_sample = """192.168.1.100 - - [18/Apr/2026:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.101 - - [18/Apr/2026:10:15:24 +0000] "GET /admin HTTP/1.1" 404 567
192.0.2.0 - - [18/Apr/2026:10:15:25 +0000] "GET /login.php?id=1' OR '1'='1 HTTP/1.1" 403 0
192.168.1.102 - - [18/Apr/2026:10:15:26 +0000] "POST /contact HTTP/1.1" 200 890
192.0.2.0 - - [18/Apr/2026:10:15:27 +0000] "GET /admin/config HTTP/1.1" 404 0
192.0.2.0 - - [18/Apr/2026:10:15:28 +0000] "GET /wp-admin HTTP/1.1" 404 0
192.0.2.0 - - [18/Apr/2026:10:15:29 +0000] "GET /phpmyadmin HTTP/1.1" 404 0
192.168.1.103 - - [18/Apr/2026:10:15:30 +0000] "GET /products HTTP/1.1" 200 2345
192.0.2.0 - - [18/Apr/2026:10:15:31 +0000] "GET /../../etc/passwd HTTP/1.1" 403 0
192.168.1.104 - - [18/Apr/2026:10:15:32 +0000] "GET /about HTTP/1.1" 200 1567
""" + "\n".join([f'192.0.2.0 - - [18/Apr/2026:10:15:{33+i} +0000] "GET /page{i} HTTP/1.1" 404 0' for i in range(50)])
    
    # Sample SSH log
    ssh_sample = """Apr 18 10:15:23 server sshd[1234]: Failed password for root from 203.0.113.0 port 52134 ssh2
Apr 18 10:15:25 server sshd[1235]: Failed password for admin from 203.0.113.0 port 52135 ssh2
Apr 18 10:15:27 server sshd[1236]: Failed password for root from 203.0.113.0 port 52136 ssh2
Apr 18 10:15:29 server sshd[1237]: Invalid user test from 203.0.113.0
Apr 18 10:15:31 server sshd[1238]: Failed password for root from 203.0.113.0 port 52138 ssh2
Apr 18 10:15:33 server sshd[1239]: Failed password for admin from 203.0.113.0 port 52139 ssh2
Apr 18 10:15:35 server sshd[1240]: Accepted password for user1 from 192.168.1.100 port 52140 ssh2
Apr 18 10:15:37 server sshd[1241]: Failed password for root from 203.0.113.0 port 52141 ssh2
Apr 18 10:15:39 server sshd[1242]: Invalid user administrator from 203.0.113.0
Apr 18 10:15:41 server sshd[1243]: Failed password for root from 203.0.113.0 port 52143 ssh2
"""
    
    with open('/home/claude/sample_apache.log', 'w') as f:
        f.write(apache_sample)
    
    with open('/home/claude/sample_ssh.log', 'w') as f:
        f.write(ssh_sample)
    
    print("Sample log files created: sample_apache.log, sample_ssh.log")


def main():
    """Main entry point"""
    print("Log File Analyzer for Intrusion Detection")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        # Use provided log files
        apache_log = sys.argv[1] if len(sys.argv) > 1 else None
        ssh_log = sys.argv[2] if len(sys.argv) > 2 else None
    else:
        # Create and use sample logs
        print("\nNo log files provided. Creating sample logs...\n")
        create_sample_logs()
        apache_log = 'sample_apache.log'
        ssh_log = 'sample_ssh.log'
    
    # Create analyzer and run analysis
    analyzer = LogAnalyzer()
    analyzer.analyze(apache_log=apache_log, ssh_log=ssh_log)
    
    print("\nAnalysis complete!")
    print("Check the 'output' directory for visualizations")
    print("Check 'incident_report.json' for detailed threat information")


if __name__ == "__main__":
    main()
