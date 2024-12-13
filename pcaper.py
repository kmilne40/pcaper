import os
import json
import scapy.all as scapy
from scapy.sessions import TCPSession
from tabulate import tabulate
import ebcdic  # belt and braces, even if not directly used

############################
# Configuration / Constants
############################

XSS_PATTERNS = ["<script>", "javascript:"]
SQLI_PATTERNS = ["' or '1'='1", "union select", "drop table", "--"]

CREDENTIAL_FIELDS = ['user ', 'username ', 'PASS ', 'password=', 'logon', 'LOGON ', 'USER ', 'login', 'ENTER USERID IKJ56700A']

# The malicious IPs will be loaded from JSON at runtime
MALICIOUS_IPS = {}

############################
# ANSI Color Codes
############################
GREEN = "\x1b[32m"
RED = "\x1b[31m"
WHITE = "\x1b[37m"
RESET = "\x1b[0m"

############################
# Utility Functions
############################

def ascii_banner():
    print(" @@@@@     @@@@     @@    @@@@@")
    print(" @@   @@  @        @  @   @@   @@")
    print(" @@   @@  @       @@@@@@  @@   @@")
    print(" @@@@@    @       @    @  @@@@@")
    print(" @@       @       @    @  @@")
    print(" @@        @@@@   @    @  @@")
    print("\n        Kev's PCAPER         \n")

def load_malicious_ips(json_file='malicious_ips.json'):
    global MALICIOUS_IPS
    if os.path.exists(json_file):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                MALICIOUS_IPS = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load malicious IP data from {json_file}: {e}")
            MALICIOUS_IPS = {}
    else:
        # No file found, proceed with empty dict
        MALICIOUS_IPS = {}

def paginate_output(lines, page_size=20):
    for i in range(0, len(lines), page_size):
        yield lines[i:i+page_size]

def display_paginated_output(lines, headers=None, page_size=20):
    if not lines and not headers:
        print("No data to display.")
        input("Press Enter to return to menu...")
        return

    # If lines is table data
    if isinstance(lines[0], list):
        table_str = tabulate(lines, headers=headers, tablefmt='grid')
        lines = table_str.split('\n')

    pages = list(paginate_output(lines, page_size=page_size))

    for idx, page in enumerate(pages, start=1):
        clear_screen_above_menu()
        for line in page:
            print(line)
        if idx < len(pages):
            choice = input("\n(N)ext page or (M)ain menu?: ").strip().lower()
            if choice == 'm':
                return
        else:
            input("\nPress Enter to return to main menu...")

def clear_screen_above_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    ascii_banner()
    print("=== Analysis Menu (Output Below) ===")

def read_pcap(file_path, use_ebcdic=False):
    try:
        packets = scapy.sniff(offline=file_path, session=TCPSession)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}.")
        return None, None
    except Exception as e:
        print(f"Error: {str(e)}")
        return None, None

    sessions = {}
    total_packets = 0
    dest_port_count = {}
    dest_ip_count = {}
    src_ip_count = {}

    xss_found = False
    sql_injection_found = False

    encoding = 'CP037' if use_ebcdic else 'utf-8'

    for packet in packets:
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
            total_packets += 1
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

            dest_port_count[dst_port] = dest_port_count.get(dst_port, 0) + 1
            dest_ip_count[dst_ip] = dest_ip_count.get(dst_ip, 0) + 1
            src_ip_count[src_ip] = src_ip_count.get(src_ip, 0) + 1

            session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            if session_key not in sessions:
                sessions[session_key] = {
                    'source_ip': src_ip,
                    'source_port': src_port,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'packets': 0,
                    'transactions': [],
                    'all_payloads': []
                }

            payload = bytes(packet[scapy.TCP].payload)
            decoded_payload = payload.decode(encoding, errors='ignore') if payload else ""

            direction = 'command' if (src_ip == sessions[session_key]['source_ip'] and 
                                      src_port == sessions[session_key]['source_port']) else 'response'

            if decoded_payload:
                lower_payload = decoded_payload.lower()
                if any(xss_pat in lower_payload for xss_pat in XSS_PATTERNS):
                    xss_found = True
                if any(sql_pat in lower_payload for sql_pat in SQLI_PATTERNS):
                    sql_injection_found = True

                sessions[session_key]['all_payloads'].append(decoded_payload)
                if direction == 'command':
                    sessions[session_key]['transactions'].append({'command': decoded_payload, 'response': ''})
                else:
                    if sessions[session_key]['transactions'] and sessions[session_key]['transactions'][-1]['response'] == '':
                        sessions[session_key]['transactions'][-1]['response'] = decoded_payload
                    else:
                        sessions[session_key]['transactions'].append({'command': '', 'response': decoded_payload})

            sessions[session_key]['packets'] += 1

    return {
        'sessions': sessions,
        'total_packets': total_packets,
        'dest_port_count': dest_port_count,
        'dest_ip_count': dest_ip_count,
        'src_ip_count': src_ip_count,
        'xss_found': xss_found,
        'sql_injection_found': sql_injection_found
    }, packets

def get_top_5(data_dict):
    return sorted(data_dict.items(), key=lambda x: x[1], reverse=True)[:5]

def mark_malicious_ip(ip):
    if ip in MALICIOUS_IPS:
        return f"{ip} ({MALICIOUS_IPS[ip]})"
    return ip

def print_summary(parsed_data):
    sessions = parsed_data['sessions']
    total_packets = parsed_data['total_packets']
    lines = []
    lines.append("=== PCAP Summary ===")
    lines.append(f"Total sessions: {len(sessions)}")
    lines.append(f"Total packets: {total_packets}")

    top_ports = get_top_5(parsed_data['dest_port_count'])
    top_dest_ips = get_top_5(parsed_data['dest_ip_count'])
    top_src_ips = get_top_5(parsed_data['src_ip_count'])

    lines.append("\nTop 5 Ports by Packet Count:")
    for port, count in top_ports:
        lines.append(f"Port {port}: {count} packets")

    lines.append("\nTop 5 Destination IPs by Packet Count:")
    for ip, count in top_dest_ips:
        lines.append(f"{mark_malicious_ip(ip)}: {count} packets")

    lines.append("\nTop 5 Source IPs by Packet Count:")
    for ip, count in top_src_ips:
        lines.append(f"{mark_malicious_ip(ip)}: {count} packets")

    display_paginated_output(lines)

def print_sessions_table(sessions):
    data = []
    for session, details in sessions.items():
        s_ip = mark_malicious_ip(details['source_ip'])
        d_ip = mark_malicious_ip(details['destination_ip'])
        for transaction in details['transactions']:
            data.append([
                session,
                s_ip,
                details['source_port'],
                d_ip,
                details['destination_port'],
                details['packets'],
                transaction['command'],
                transaction['response']
            ])
    if data:
        display_paginated_output(data, headers=['Session', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Packets', 'Command', 'Response'])
    else:
        display_paginated_output(["No data to display."])

def search_string_in_sessions(sessions, search_str):
    results = []
    search_lower = search_str.lower()
    for sess_key, details in sessions.items():
        found_in = []
        for i, payload in enumerate(details['all_payloads']):
            if search_lower in payload.lower():
                found_in.append(i)
        if found_in:
            results.append((sess_key, details['source_ip'], details['destination_ip'], found_in))
    return results

def print_search_results(results, search_str):
    if not results:
        display_paginated_output([f"No occurrences of '{search_str}' found."])
    else:
        lines = [["Session", "Source IP", "Destination IP", "Payload Indexes"]]
        for r in results:
            session, sip, dip, indices = r
            sip = mark_malicious_ip(sip)
            dip = mark_malicious_ip(dip)
            lines.append([session, sip, dip, ", ".join(map(str, indices))])
        display_paginated_output(lines[1:], headers=lines[0])

def print_report(parsed_data):
    lines = []
    lines.append("=== Detailed Report ===")
    sessions = parsed_data['sessions']
    total_packets = parsed_data['total_packets']

    lines.append(f"Total sessions: {len(sessions)}")
    lines.append(f"Total packets: {total_packets}")

    if parsed_data['xss_found'] or parsed_data['sql_injection_found']:
        lines.append("\nWARNING: Suspicious payloads detected!")
        if parsed_data['xss_found']:
            lines.append("- Potential XSS patterns found.")
        if parsed_data['sql_injection_found']:
            lines.append("- Potential SQL Injection patterns found.")
    else:
        lines.append("\nNo suspicious payloads detected in this capture.")

    display_paginated_output(lines)

def find_credentials(sessions):
    creds = []
    delimiters = [' ', '&', '\n', '\r', ';', ':']
    for sess_key, details in sessions.items():
        sip = mark_malicious_ip(details['source_ip'])
        dip = mark_malicious_ip(details['destination_ip'])
        for payload in details['all_payloads']:
            low = payload.lower()
            for field in CREDENTIAL_FIELDS:
                if field.lower() in low:
                    start = low.find(field.lower()) + len(field)
                    end_pos = len(low)
                    for c in delimiters:
                        pos = low.find(c, start)
                        if pos != -1 and pos < end_pos:
                            end_pos = pos
                    found_val = payload[start:end_pos].strip()
                    if found_val:
                        creds.append((sess_key, sip, dip, field.strip('='), found_val))
    return creds

def print_credentials(creds):
    if not creds:
        display_paginated_output(["No obvious credentials found."])
    else:
        data = [["Session", "Source IP", "Destination IP", "Field", "Value"]]
        data.extend(creds)
        display_paginated_output(data[1:], headers=data[0])

def merge_pcap_files():
    print("Enter paths to multiple PCAP files to merge (one per line). Enter blank line when done:")
    file_paths = []
    while True:
        fp = input("> ").strip()
        if fp == '':
            break
        if os.path.exists(fp):
            file_paths.append(fp)
        else:
            print(f"File {fp} does not exist. Not adding.")

    if len(file_paths) < 2:
        input("You need at least two files to merge. Press Enter to return to menu.")
        return

    packets = []
    for fp in file_paths:
        pkts = scapy.rdpcap(fp)
        packets.extend(pkts)

    output_file = input("Enter output filename (e.g. merged.pcap): ").strip()
    if not output_file:
        output_file = "merged.pcap"
    scapy.wrpcap(output_file, packets)
    input(f"Merged {len(file_paths)} files into {output_file}. Press Enter to return to menu.")

def reconstruct_streams(sessions):
    lines = []
    for session, details in sessions.items():
        lines.append(f"=== Session: {session} ===")
        for idx, t in enumerate(details['transactions']):
            lines.append(f"Transaction {idx+1}:")
            if t['command']:
                lines.append("  Command:")
                for line in t['command'].splitlines():
                    lines.append(f"    {line}")
            if t['response']:
                lines.append("  Response:")
                for line in t['response'].splitlines():
                    lines.append(f"    {line}")
        lines.append("")
    if not lines:
        lines = ["No streams to reconstruct."]
    display_paginated_output(lines)

def analyze_malicious_actors(parsed_data):
    sessions = parsed_data['sessions']
    malicious_sessions = []
    for session, details in sessions.items():
        sip = details['source_ip']
        dip = details['destination_ip']
        s_label = mark_malicious_ip(sip)
        d_label = mark_malicious_ip(dip)
        if sip in MALICIOUS_IPS or dip in MALICIOUS_IPS:
            malicious_sessions.append([session, s_label, details['source_port'], d_label, details['destination_port'], details['packets']])

    if not malicious_sessions:
        display_paginated_output(["No known malicious actors found in this capture."])
    else:
        display_paginated_output(malicious_sessions, headers=["Session", "Source IP", "Source Port", "Destination IP", "Destination Port", "Packets"])

def print_colored_menu():
    menu_items = [
        "Print summary of the capture",
        "Show sessions and transactions",
        "Search for a specific string in payloads",
        "Print detailed report (XSS/SQLi warnings)",
        "Analyze against known malicious actors",
        "Passwords we think were captured",
        "Merge multiple PCAP files into one",
        "Reconstruct TCP streams",
        "Start a new analysis",
        "Exit"
    ]
    colored_menu = []
    for i, item in enumerate(menu_items, start=1):
        color = GREEN if i % 2 != 0 else RED
        colored_menu.append(f"{color}{i}. {item}{RESET}")
    return "\n".join(colored_menu)

def main_menu(parsed_data):
    while True:
        ascii_banner()
        menu_str = print_colored_menu()
        print(menu_str)
        choice = input(f"{WHITE}Choose an option: {RESET}").strip()

        if choice == '1':
            print_summary(parsed_data)
        elif choice == '2':
            print_sessions_table(parsed_data['sessions'])
        elif choice == '3':
            search_str = input("Enter the string to search for: ").strip()
            results = search_string_in_sessions(parsed_data['sessions'], search_str)
            print_search_results(results, search_str)
        elif choice == '4':
            print_report(parsed_data)
        elif choice == '5':
            analyze_malicious_actors(parsed_data)
        elif choice == '6':
            creds = find_credentials(parsed_data['sessions'])
            print_credentials(creds)
        elif choice == '7':
            merge_pcap_files()
        elif choice == '8':
            reconstruct_streams(parsed_data['sessions'])
        elif choice == '9':
            run_analysis()
            return
        elif choice == '10':
            print("Exiting analysis menu.")
            return
        else:
            input("Invalid choice. Press Enter to continue...")

def run_analysis():
    ascii_banner()
    # Load malicious IPs from JSON before analysis
    load_malicious_ips()
    file_path = input("Please enter the path to the .pcap file to be analyzed: ")
    encoding_choice = input("Do you want to decode the .pcap file using EBCDIC (y/n)?: ")
    use_ebcdic = True if encoding_choice.lower() == 'y' else False

    if not os.path.exists(file_path):
        input("File does not exist. Press Enter to return.")
        return

    parsed_data, packets = read_pcap(file_path, use_ebcdic=use_ebcdic)
    if parsed_data is None:
        input("Error reading PCAP. Press Enter to return.")
        return

    main_menu(parsed_data)

def main():
    run_analysis()

if __name__ == "__main__":
    main()
