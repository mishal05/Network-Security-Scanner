import tkinter as tk
from tkinter import messagebox, scrolledtext
import nmap
import csv
import re

# Function to scan target
def scan_network():
    target = target_entry.get()
    print(f"Scanning Target: {target}")  # Debugging line

    if not target:
        text_output.insert(tk.END, "Please enter a target IP or domain.\n")
        return

    # Specify the path to Nmap executable
    scanner = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap\\nmap.exe',))

    try:
        # Enhanced scan command with OS detection & vulnerability scan
        scanner.scan(hosts=target, arguments="-A -sV --script vuln --version-intensity 5")
        print(f"Scan Output: {scanner.all_hosts()}")  # Debugging line

        if not scanner.all_hosts():
            text_output.insert(tk.END, "No hosts found.\n")
            return

        report = []
        for host in scanner.all_hosts():
            text_output.insert(tk.END, f"Host: {host}\n")
            os_match = scanner[host].get('osmatch', [])
            os_info = os_match[0]['name'] if os_match else "Unknown"
            text_output.insert(tk.END, f"Detected OS: {os_info}\n")
            
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port].get('name', 'N/A')
                    version = scanner[host][proto][port].get('version', 'N/A')
                    vuln_info = scanner[host][proto][port].get('script', {}).get('vuln', "No known vulnerabilities")
                    
                    text_output.insert(tk.END, f"Port {port}: {state} (Service: {service}, Version: {version})\n")
                    text_output.insert(tk.END, f"Vulnerabilities: {vuln_info}\n\n")
                    
                    # Append results to CSV report
                    report.append([host, os_info, port, state, service, version, vuln_info])

        # Save results to CSV
        filename = re.sub(r'\W+', '_', target) + "_scan_report.csv"
        with open(filename, "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Host", "OS", "Port", "State", "Service", "Version", "Vulnerabilities"])
            writer.writerows(report)

        text_output.insert(tk.END, f"\nScan complete! Report saved as {filename}.\n")
        messagebox.showinfo("Success", f"Scan complete! Report saved as {filename}")

    except Exception as e:
        text_output.insert(tk.END, f"\nError: {e}")
        messagebox.showerror("Error", f"Scan failed: {e}")

# GUI Setup
root = tk.Tk()
root.title("Network Security & Vulnerability Scanner")
root.geometry("600x400")

tk.Label(root, text="Enter Target IP or Domain:", font=("Arial", 12)).pack(pady=5)
target_entry = tk.Entry(root, width=40, font=("Arial", 12))
target_entry.pack(pady=5)

btn_scan = tk.Button(root, text="Scan Now", command=scan_network, font=("Arial", 12), bg="blue", fg="white")
btn_scan.pack(pady=10)

text_output = scrolledtext.ScrolledText(root, width=70, height=15, font=("Arial", 10))
text_output.pack(pady=5)

root.mainloop()
