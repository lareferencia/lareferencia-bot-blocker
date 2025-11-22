import os
import logging
from threat_analyzer import ThreatAnalyzer

# Setup basic logging
logging.basicConfig(level=logging.INFO)

def create_dummy_log(filename):
    entries = [
        '192.168.1.1 - - [22/Nov/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"', # Whitelisted
        '192.168.1.1 - - [22/Nov/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"', # Whitelisted
        '10.0.0.1 - - [22/Nov/2025:10:00:03 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"'     # Normal
    ]
    with open(filename, 'w') as f:
        for e in entries:
            f.write(e + '\n')
    return len(entries)

def test_whitelist():
    log_file = "test_whitelist.log"
    create_dummy_log(log_file)
    
    print(f"Created dummy log: {log_file}")
    
    # Initialize analyzer with a whitelist
    whitelist = ['192.168.1.1']
    analyzer = ThreatAnalyzer(whitelist=whitelist)
    
    print(f"Running analyze_log_file with whitelist: {whitelist}...")
    count = analyzer.analyze_log_file(log_file)
    
    print(f"Processed count: {count}")
    
    # We expect only 1 entry to be processed (10.0.0.1), as 192.168.1.1 should be skipped
    if count != 1:
        print(f"FAIL: Expected 1 entry processed, got {count}.")
    else:
        print("PASS: Correct number of entries processed.")

    # Check IP metrics
    ip_metrics = analyzer.ip_metrics
    print(f"IP Metrics keys: {list(ip_metrics.keys())}")
    
    if '192.168.1.1' in ip_metrics:
        print("FAIL: 192.168.1.1 should NOT be in metrics.")
    else:
        print("PASS: 192.168.1.1 correctly excluded.")
        
    if '10.0.0.1' not in ip_metrics:
        print("FAIL: 10.0.0.1 should be in metrics.")
    else:
        print("PASS: 10.0.0.1 correctly included.")

    # Cleanup
    if os.path.exists(log_file):
        os.remove(log_file)
    print("Whitelist Test completed.")

if __name__ == "__main__":
    test_whitelist()
