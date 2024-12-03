
import re
import csv
from collections import defaultdict

# Function to parse and analyze the log file in one pass
def analyze_log_file(log_file, threshold=10):
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_attempts = defaultdict(int)

    # Process the file line by line
    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else None

            # Extract endpoint
            endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) (.+?) HTTP/', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None

            # Extract status code
            status_match = re.search(r'" \d{3}', line)
            status_code = int(status_match.group().strip("" ")) if status_match else None

            # Count requests per IP
            if ip:
                ip_counts[ip] += 1

            # Count endpoint accesses
            if endpoint:
                endpoint_counts[endpoint] += 1

            # Track failed login attempts
            if status_code == 401 or 'Invalid credentials' in line:
                if ip:
                    failed_attempts[ip] += 1

    # Identify most accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=("None", 0))

    # Filter suspicious activities
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}

    return ip_counts, most_accessed_endpoint, suspicious_ips

# Function to write results to CSV
def write_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP request counts
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file = "sample.log"  # Input log file
    output_file = "log_analysis_results.csv"  # Output CSV file
    threshold = 10  # Failed login attempt threshold

    # Analyze log file
    ip_counts, most_accessed_endpoint, suspicious_ips = analyze_log_file(log_file, threshold)

    # Display results in terminal
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Write results to CSV
    write_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {output_file}")

# Run the main function
if __name__ == "__main__":
    main()
