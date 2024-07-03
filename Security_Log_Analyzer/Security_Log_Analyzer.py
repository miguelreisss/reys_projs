import re
import datetime

# Define patterns for common security events
failed_login_pattern = re.compile(r'Failed password for (invalid user\s)?\w+ from ([\d.]+)')
malicious_ips = {'192.168.1.100', '10.0.0.1'}  # Example of known malicious IPs
access_pattern = re.compile(r'Accepted password for \w+ from ([\d.]+)')

# Function to analyze log file
def analyze_log_file(log_file_path):
    security_events = []
    access_times = {}

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Check for failed login attempts
            failed_login_match = failed_login_pattern.search(line)
            if failed_login_match:
                ip_address = failed_login_match.group(2)
                event = f"Failed login attempt from IP: {ip_address}"
                security_events.append(event)
                print(event)
                continue

            # Check for access from known malicious IPs
            access_match = access_pattern.search(line)
            if access_match:
                ip_address = access_match.group(1)
                if ip_address in malicious_ips:
                    event = f"Access from known malicious IP: {ip_address}"
                    security_events.append(event)
                    print(event)
                    continue

                # Record access times for anomaly detection
                timestamp_match = re.search(r'\d{2}:\d{2}:\d{2}', line)
                if timestamp_match:
                    timestamp_str = timestamp_match.group()
                    timestamp = datetime.datetime.strptime(timestamp_str, '%H:%M:%S')
                    if ip_address not in access_times:
                        access_times[ip_address] = []
                    access_times[ip_address].append(timestamp)

    # Detect anomalies
    print("\nAnalyzing for anomalies...")
    for ip_address, times in access_times.items():
        if len(times) > 1:
            time_diffs = [(times[i] - times[i - 1]).seconds for i in range(1, len(times))]
            avg_diff = sum(time_diffs) / len(time_diffs)
            if avg_diff < 60:  # Anomaly if accesses are very close in time
                event = f"Anomalous rapid access detected from IP: {ip_address} with average interval {avg_diff:.2f} seconds"
                security_events.append(event)
                print(event)

    # Return collected security events
    return security_events

# Function to generate report from security events
def generate_report(security_events, report_file_path):
    with open(report_file_path, 'w') as report_file:
        report_file.write("Security Log Analysis Report\n")
        report_file.write("============================\n")
        report_file.write(f"Generated on: {datetime.datetime.now()}\n\n")
        if security_events:
            for event in security_events:
                report_file.write(event + "\n")
        else:
            report_file.write("No significant security events detected.\n")

if __name__ == "__main__":
    log_file_path = input("Enter the path to the log file: ")
    report_file_path = input("Enter the path to save the report: ")

    print(f"\nAnalyzing log file: {log_file_path}\n")
    security_events = analyze_log_file(log_file_path)
    generate_report(security_events, report_file_path)
    print(f"\nReport saved to: {report_file_path}")
