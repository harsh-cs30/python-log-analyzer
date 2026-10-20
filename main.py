
from collections import Counter

# Configuration
FAILED_LOGIN_THRESHOLD = 3
LOG_FILE = "logs/sample.log"
REPORT_FILE = "security_report.txt"


# Step 1: Read the security log file
def read_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.readlines()

    except FileNotFoundError:
        print(f"Error: Log file not found: {file_path}")
        return []


# Step 2: Count failed login attempts for each IP
def analyze_failed_logins(logs):
    failed_ips = Counter()

    for log in logs:
        if "LOGIN_FAILED" in log:
            for part in log.split():
                if part.startswith("IP="):
                    ip_address = part.split("=", 1)[1]
                    failed_ips[ip_address] += 1
                    break

    return failed_ips


# Step 3: Display security alerts in the terminal
def generate_alerts(failed_attempts, threshold):
    print("\n====== SECURITY ALERTS ======\n")

    alerts_found = False

    for ip, count in failed_attempts.most_common():
        if count >= threshold:
            alerts_found = True
            print(f"[ALERT] IP: {ip}")
            print(f"        Failed attempts: {count}")
            print(f"        Threshold: {threshold}")
            print("        Action: Investigate this activity.\n")

    if not alerts_found:
        print("No IP addresses reached the alert threshold.")


# Step 4: Save the analysis to a report file
def save_report(failed_attempts, threshold, total_logs):
    total_failed = sum(failed_attempts.values())

    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as report:
            report.write("PYTHON LOG ANALYZER REPORT\n")
            report.write("==========================\n\n")

            report.write(f"Total log entries: {total_logs}\n")
            report.write(f"Total failed login events: {total_failed}\n")
            report.write(f"Alert threshold: {threshold}\n\n")

            report.write("FAILED LOGIN SUMMARY\n")
            report.write("--------------------\n")

            for ip, count in failed_attempts.most_common():
                report.write(f"{ip}: {count} failed attempts\n")

            report.write("\nSECURITY ALERTS\n")
            report.write("---------------\n")

            alerts_found = False

            for ip, count in failed_attempts.most_common():
                if count >= threshold:
                    alerts_found = True
                    report.write(
                        f"ALERT: {ip} has {count} failed login attempts.\n"
                    )

            if not alerts_found:
                report.write("No IP addresses reached the alert threshold.\n")

        print(f"\nReport saved successfully: {REPORT_FILE}")

    except OSError as error:
        print(f"Error saving report: {error}")


# Step 5: Run the complete program
def main():
    log_entries = read_logs(LOG_FILE)

    if not log_entries:
        print("No log entries to analyze. Check your log file.")
        return

    failed_attempts = analyze_failed_logins(log_entries)

    print("\n====== FAILED LOGIN SUMMARY ======\n")

    for ip, count in failed_attempts.most_common():
        print(f"{ip}: {count} failed attempts")

    print(f"\nConfigured threshold: {FAILED_LOGIN_THRESHOLD}")

    generate_alerts(failed_attempts, FAILED_LOGIN_THRESHOLD)

    print(f"Total log entries: {len(log_entries)}")
    print(
        "Total failed login events:",
        sum(failed_attempts.values())
    )

    save_report(
        failed_attempts,
        FAILED_LOGIN_THRESHOLD,
        len(log_entries)
    )


if __name__ == "__main__":
    main()
