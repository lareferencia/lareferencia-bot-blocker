import os
import logging
from datetime import datetime, timezone
from threat_analyzer import ThreatAnalyzer

# Setup basic logging
logging.basicConfig(level=logging.INFO)

def create_dummy_log(filename):
    entries = [
        '192.168.1.1 - - [22/Nov/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        '192.168.1.1 - - [22/Nov/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        '192.168.1.2 - - [22/Nov/2025:10:00:02 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"',
        '10.0.0.1 - - [22/Nov/2025:10:00:03 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla"'
    ]
    with open(filename, 'w') as f:
        for e in entries:
            f.write(e + '\n')
    return len(entries)

def test_streaming_analysis():
    log_file = "test_dummy.log"
    create_dummy_log(log_file)
    
    print(f"Created dummy log: {log_file}")
    
    analyzer = ThreatAnalyzer()
    
    print("Running analyze_log_file...")
    count = analyzer.analyze_log_file(log_file)
    
    print(f"Processed count: {count}")
    
    if count != 4:
        print("FAIL: Expected 4 entries processed.")
        return

    # Check IP metrics
    ip_metrics = analyzer.ip_metrics
    print(f"IP Metrics keys: {list(ip_metrics.keys())}")
    
    if '192.168.1.1' not in ip_metrics:
        print("FAIL: 192.168.1.1 not found in metrics.")
        return
        
    if ip_metrics['192.168.1.1']['total_requests'] != 2:
        print(f"FAIL: Expected 2 requests for 192.168.1.1, got {ip_metrics['192.168.1.1']['total_requests']}")
        return

    print("IP Metrics verification passed.")

    # Check Identify Threats
    print("Running identify_threats...")
    # Mock config
    class Config:
        min_rpm_threshold = 10
        min_sustained_percent = 20
        max_cpu_load_threshold = 80
    
    shared_context = {'analysis_duration_seconds': 60}
    
    threats = analyzer.identify_threats(
        strategy_name='unified',
        effective_min_requests=1,
        shared_context_params=shared_context,
        config=Config()
    )
    
    if threats is not None:
        print(f"Threats identified: {len(threats)}")
        print("Identify Threats verification passed.")
    else:
        print("FAIL: identify_threats returned None")

    # Cleanup
    os.remove(log_file)
    print("Test completed successfully.")

if __name__ == "__main__":
    test_streaming_analysis()
