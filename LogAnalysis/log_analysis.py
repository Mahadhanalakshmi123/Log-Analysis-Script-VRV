import re
import csv
from collections import Counter

# Configuration for failed login threshold
FAILED_LOGIN_THRESHOLD = 10

# File names
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    """Parse the log file and extract relevant data."""
    ip_requests = Counter()
    endpoints = Counter()
    failed_logins = Counter()

    with open(file_path, "r") as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1
            
            # Extract endpoint
            endpoint_match = re.search(r"\"(?:GET|POST) (/[\w/]+)", line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoints[endpoint] += 1
            
            # Detect failed login attempts
            if "401" in line or "Invalid credentials" in line:
                if ip_match:
                    failed_logins[ip_address] += 1

    return ip_requests, endpoints, failed_logins

def count_requests_per_ip(ip_requests):
    """Count and sort requests per IP."""
    sorted_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    print("IP Address           Request Count")
    for ip, count in sorted_requests:
        print(f"{ip:<20} {count}")
    return sorted_requests

def find_most_accessed_endpoint(endpoints):
    """Find the most accessed endpoint."""
    most_accessed = endpoints.most_common(1)
    if most_accessed:
        endpoint, count = most_accessed[0]
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{endpoint} (Accessed {count} times)")
        return endpoint, count
    return None, 0

def detect_suspicious_activity(failed_logins):
    """Detect suspicious activity based on failed login attempts."""
    suspicious_ips = [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips:
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")
    return suspicious_ips

def save_to_csv(ip_data, endpoint_data, suspicious_data, output_file):
    """Save analysis results to a CSV file."""
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write IP requests section
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_data)
        writer.writerow([])

        # Write most accessed endpoint section
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(endpoint_data)
        writer.writerow([])

        # Write suspicious activity section
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_data)

    print(f"\nResults saved to {output_file}")

def main():
    print("Processing log file...\n")
    ip_requests, endpoints, failed_logins = parse_log_file(LOG_FILE)

    # Step 1: Count requests per IP
    ip_data = count_requests_per_ip(ip_requests)

    # Step 2: Find most accessed endpoint
    endpoint_data = find_most_accessed_endpoint(endpoints)

    # Step 3: Detect suspicious activity
    suspicious_data = detect_suspicious_activity(failed_logins)

    # Step 4: Save results to CSV
    save_to_csv(ip_data, [endpoint_data], suspicious_data, OUTPUT_FILE)

if __name__ == "__main__":
    main()
