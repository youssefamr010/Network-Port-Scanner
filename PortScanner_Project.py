import socket
import argparse
import csv
import re
import sys   
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor 
from tqdm import tqdm 


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
    110: "POP3", 115: "SFTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 
    194: "IRC", 443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy"
}

def get_service_name(port):
    return COMMON_PORTS.get(port, "Unknown")

def scan_single_port(ip, port, protocol, timeout=1):
    try:
        sock_type = socket.SOCK_STREAM if protocol.lower() == 'tcp' else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return port if result == 0 else None
    except socket.error:
        return None

def scan_ports_with_progress(ip, start_port, end_port, protocol, max_workers=50):
    open_ports = []
    total_ports = end_port - start_port + 1

    print(f"\nScanning {protocol.upper()} ports {start_port}-{end_port} on {ip}...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_single_port, ip, port, protocol) 
                  for port in range(start_port, end_port + 1)]
        for future in tqdm(futures, total=total_ports, desc="Scanning", unit="port"):
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports)

def format_results_table(open_ports):
    headers = ["Port", "Protocol", "Service", "Status"]
    rows = []

    for port in open_ports:
        service = get_service_name(port)
        rows.append([port, "TCP", service, "Open"])

    if not rows:
        return "No open ports found."

    col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(len(headers))]
    separator = "+" + "+".join("-" * (width + 2) for width in col_widths) + "+"
    result = [separator]
    header_row = "|" + "|".join(f" {headers[i]:{col_widths[i]}} " for i in range(len(headers))) + "|"
    result.append(header_row)
    result.append(separator)
    for row in rows:
        data_row = "|" + "|".join(f" {str(row[i]):{col_widths[i]}} " for i in range(len(row))) + "|"
        result.append(data_row)
    result.append(separator)
    return "\n".join(result)

def save_results_to_csv(ip, open_ports, filename=None):
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{ip}_ports_{timestamp}.csv"
    try:
        with open(filename, "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Port", "Protocol", "Service", "Status"])
            for port in open_ports:
                writer.writerow([port, "TCP", get_service_name(port), "Open"])
        print(f"\nResults saved to: {filename}")
        return True
    except Exception as e:
        print(f"\nError saving results: {e}")
        return False



def analyze_log_file(log_file):
    print(f"\nAnalyzing log file: {log_file}")

    patterns = {
        'error': r'error|exception|fail|denied|refused|timeout|invalid',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'timestamp': r'\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}',
        'attack': r'attack|exploit|injection|overflow|xss|csrf|malicious|breach|hack'
    }

    issues_found = 0

    try:
        with open(log_file, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_lower = line.lower()
                if re.search(patterns['error'], line_lower):
                    timestamp_match = re.search(patterns['timestamp'], line)
                    timestamp = timestamp_match.group(0) if timestamp_match else "N/A"
                    ip_match = re.search(patterns['ip_address'], line)
                    ip = ip_match.group(0) if ip_match else "N/A"
                    security_issue = "SECURITY ALERT" if re.search(patterns['attack'], line_lower) else ""
                    print(f"[Line {line_num}] [{timestamp}] [{ip}] {security_issue}")
                    print(f"  {line.strip()}")
                    print("-" * 80)
                    issues_found += 1

        if issues_found == 0:
            print("No issues found in the log file.")
        else:
            print(f"Found {issues_found} potential issues in the log file.")

        return issues_found
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        return -1
    except Exception as e:
        print(f"Error analyzing log file: {e}")
        return -1

def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Network Port Scanner with Wireshark Integration",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("ip", help="Target IP address to scan")
    parser.add_argument("start_port", type=int, help="Starting port number")
    parser.add_argument("end_port", type=int, help="Ending port number")
    parser.add_argument("--protocol", "-p", choices=['tcp', 'udp'], default='tcp',
                        help="Protocol to scan (tcp or udp)")
    parser.add_argument("--save", "-s", action="store_true", 
                        help="Save results to a CSV file")
    parser.add_argument("--output", "-o", metavar="FILENAME",
                        help="Specify output filename for CSV results")
    parser.add_argument("--log", "-l", metavar="LOG_FILE",
                        help="Analyze a log file for potential issues")
    parser.add_argument("--threads", "-t", type=int, default=50,
                        help="Number of threads for parallel scanning")

    args = parser.parse_args()

    if not validate_ip(args.ip):
        print(f"Error: '{args.ip}' is not a valid IP address.")
        return 1

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        print("Error: Port range must be between 1-65535 and start_port must be <= end_port")
        return 1

    print(f"\n{'=' * 60}")
    print(f"PORT SCAN STARTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target: {args.ip} | Ports: {args.start_port}-{args.end_port} | Protocol: {args.protocol.upper()}")
    print(f"{'=' * 60}")

    try:
        open_ports = scan_ports_with_progress(
            args.ip, args.start_port, args.end_port, args.protocol, args.threads
        )
        print("\nSCAN RESULTS:")
        print(format_results_table(open_ports))

        if args.save or args.output:
            save_results_to_csv(args.ip, open_ports, args.output)


        if args.log:
            analyze_log_file(args.log)

        print(f"\nScan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        return 0

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Exiting...")
        return 130

if __name__ == "__main__":
    sys.exit(main())