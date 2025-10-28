"""4d4MP's AbuseIPDB Bulk Checker GUI application."""

from __future__ import annotations

import concurrent.futures
import csv
import json
import os
from typing import Dict, Iterable, List, Sequence, Tuple

import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


IP_HEADERS: Tuple[str, ...] = ("SrcIpAddr", "SourceIP")
API_RESPONSE_FIELDS: Tuple[str, ...] = (
    "ipAddress",
    "abuseConfidenceScore",
    "isp",
    "domain",
    "countryCode",
    "totalReports",
    "lastReportedAt",
)


def read_csv(file_path: str) -> List[List[str]]:
    """Return a list of rows from a CSV file."""

    with open(file_path, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        return [row for row in reader]


def _resolve_ip_header(header: Sequence[str]) -> str:
    """Return the header name used for IP addresses."""

    for candidate in IP_HEADERS:
        if candidate in header:
            return candidate
    raise ValueError("Neither 'SrcIpAddr' nor 'SourceIP' found in CSV header")


def extract_ip_list(csv_data: Sequence[Sequence[str]]) -> List[str]:
    """Extract a list of IP addresses from the provided CSV data."""

    if not csv_data:
        return []

    header = csv_data[0]
    column_name = _resolve_ip_header(header)
    print("Extracting: " + str(len(csv_data)) + " - " + str(column_name))
    column_index = header.index(column_name)
    return [row[column_index].strip() for row in csv_data[1:] if len(row) > column_index]


def get_unique_ips_custom(csv1: Sequence[Sequence[str]], csv2: Sequence[Sequence[str]]) -> Iterable[str]:
    ip_list1 = extract_ip_list(csv1)
    ip_list2 = extract_ip_list(csv2)
    print("ip_list1: " + str(len(ip_list1)))
    print("ip_list2: " + str(len(ip_list2)))
    print(len(set(ip_list1).symmetric_difference(set(ip_list2))))
    return set(ip_list1).symmetric_difference(set(ip_list2))


def get_unique_ips(csv1: Sequence[Sequence[str]], csv2: Sequence[Sequence[str]]) -> List[str]:
    """Return IPs from both CSVs, preserving the first occurrence order."""

    ip_list1 = extract_ip_list(csv1)
    ip_list2 = extract_ip_list(csv2)
    combined_ips = ip_list1 + ip_list2
    seen = set()
    unique_ips: List[str] = []
    for ip in combined_ips:
        if ip and ip not in seen:
            unique_ips.append(ip)
            seen.add(ip)
    print("Number of unique IPs: " + str(len(unique_ips)))
    return unique_ips


def clear_output(data_list: Iterable[Dict[str, object]], min_entry: str, whitelist_entry: str) -> List[Dict[str, object]]:
    """Filter API responses by minimum reports and ISP whitelist."""

    whitelist = [w.strip() for w in whitelist_entry.split(",") if w.strip()]
    threshold = int(min_entry)
    return_list = []
    for line in data_list:
        isp = (line.get("isp") if isinstance(line, dict) else None) or ""
        total_reports = int(line.get("totalReports", 0)) if isinstance(line, dict) else 0
        if total_reports > threshold and not any(whitelisted in isp for whitelisted in whitelist):
            return_list.append(line)

    print("Number of malicious IPs: " + str(len(return_list)))

    return return_list


def write_output_file(cleared_list: Sequence[Dict[str, object]], export_path: str) -> None:
    """Write the processed results to a CSV file."""

    with open(export_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=API_RESPONSE_FIELDS)
        writer.writeheader()
        writer.writerows(cleared_list)


def _update_output_box(output_box: tk.Text, message: str) -> None:
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, message)
    output_box.update_idletasks()


def bulk_check(
    csv_path: str,
    csv_path2: str,
    api_key: str,
    export_path: str,
    min_entry: str,
    whitelist_entry: str,
    progress: ttk.Progressbar,
    output_box: tk.Text,
) -> List[Dict[str, object]]:
    csv1 = read_csv(csv_path)
    csv2 = read_csv(csv_path2)
    ip_list = get_unique_ips(csv1, csv2)

    json_temp_path = os.path.join(os.path.dirname(export_path), "aipdbulkchecktempfile.json")
    total_rows = max(len(ip_list), 1)
    api_return_list: List[Dict[str, object]] = []

    def fetch_ip_data(ip: str) -> Tuple[str, Dict[str, object] | None, str | None]:
        """Helper function to fetch data for a single IP."""

        try:
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                headers={"Accept": "application/json", "Key": api_key},
                timeout=10,
            )
            if response.status_code == 200:
                return ip, response.json(), None
            return ip, None, f"API error: {response.status_code}"
        except Exception as exc:  # pragma: no cover - best effort logging
            return ip, None, str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_ip_data, ip): ip for ip in ip_list}

        completed_count = 0
        successful_responses: List[Dict[str, object]] = []

        with open(json_temp_path, "w", encoding="utf-8") as json_file:
            for future in concurrent.futures.as_completed(futures):
                ip, data, error = future.result()
                completed_count += 1

                if data:
                    json_file.write(json.dumps(data) + "\n")
                    successful_responses.append(data)
                    print(f"\rNumber of successful API calls: {len(successful_responses)}", end="", flush=True)
                else:
                    _update_output_box(output_box, f"{ip} error: {error}")

                progress["value"] = completed_count / total_rows * 100
                _update_output_box(output_box, f"Processing {completed_count} of {len(ip_list)}")

    with open(json_temp_path, "r", encoding="utf-8") as json_file:
        for line in json_file:
            data = json.loads(line)["data"]
            api_return_list.append({key: data.get(key) for key in API_RESPONSE_FIELDS})

    cleared_list = clear_output(api_return_list, min_entry, whitelist_entry)
    write_output_file(cleared_list, export_path)

    return api_return_list


def browse_file(entry: ttk.Entry) -> None:
    """Open a dialog to select a file and populate the entry widget."""

    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)


def browse_save_file(entry: ttk.Entry) -> None:
    """Open a dialog to select an output file and populate the entry widget."""

    filename = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
    )
    if filename:
        if os.path.exists(filename):
            if messagebox.askokcancel("Warning", "The file already exists. Do you want to overwrite it?"):
                entry.delete(0, tk.END)
                entry.insert(0, filename)
        else:
            entry.delete(0, tk.END)
            entry.insert(0, filename)


def main() -> None:
    global root
    root = tk.Tk()
    root.title("4d4MP's AbuseIPDB Bulk Checker")
    root.geometry("620x600")

    frame = ttk.Frame(root, padding="10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Create and place two title labels
    title_label1 = ttk.Label(frame, text="4d4MP's", font=("Sylfaen", 14, "italic"))
    title_label1.grid(row=0, column=0, columnspan=3)
    title_label2 = ttk.Label(frame, text="AbuseIPDB Bulk Checker", font=("Sylfaen", 18, "bold"))
    title_label2.grid(row=1, column=0, columnspan=3)

    # Create and place the API key label and entry box
    api_label = ttk.Label(frame, text="API Key:")
    api_label.grid(row=2, column=0, sticky=tk.W)
    api_default_value = tk.StringVar()
    api_default_value.set("")
    api_entry = ttk.Entry(frame, width=30, show="*", textvariable=api_default_value)
    api_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))

    # Create and place the CSV input file path label, entry box, and browse button
    csv_label = ttk.Label(frame, text="CSV Input File Path / Name:")
    csv1_default_value = tk.StringVar()
    csv1_default_value.set("")
    csv_entry = ttk.Entry(frame, width=30, textvariable=csv1_default_value)
    csv_label.grid(row=3, column=0, sticky=tk.W)
    csv_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))

    csv_button = ttk.Button(frame, text="Browse", command=lambda: browse_file(csv_entry))
    csv_button.grid(row=3, column=2, sticky=tk.W)

    csv_label2 = ttk.Label(frame, text="CSV2 Input File Paths / Names:")
    csv2_default_value = tk.StringVar()
    csv2_default_value.set("")
    csv_entry2 = ttk.Entry(frame, width=30, textvariable=csv2_default_value)
    csv_label2.grid(row=4, column=1, sticky=tk.W)
    csv_entry2.grid(row=4, column=1, sticky=(tk.W, tk.E))

    csv_button2 = ttk.Button(frame, text="Browse", command=lambda: browse_file(csv_entry2))
    csv_button2.grid(row=4, column=2, sticky=tk.W)

    # Create and place the CSV export file path label, entry box, and browse button
    export_label = ttk.Label(frame, text="CSV Export File Paths / Names:")
    export_default_value = tk.StringVar()
    export_default_value.set("")
    export_entry = ttk.Entry(frame, width=30, textvariable=export_default_value)
    export_label.grid(row=5, column=0, sticky=tk.W)
    export_entry.grid(row=5, column=1, sticky=(tk.W, tk.E))

    export_button = ttk.Button(frame, text="Browse", command=lambda: browse_save_file(export_entry))
    export_button.grid(row=5, column=2, sticky=tk.W)

    #Create and place the minimal score value input field
    min_label = ttk.Label(frame, text="Minimum totalReports Score:")
    min_label.grid(row=6, column=0, sticky=tk.W)
    default_score = tk.StringVar()
    default_score.set("100")
    min_entry = ttk.Entry(frame, width=5, textvariable=default_score)
    min_entry.grid(row=6, column=1, sticky=(tk.W, tk.E))

    whitelist_label = ttk.Label(frame, text="Whitelisted ISPs")
    whitelist_label.grid(row=7, column=0, sticky=tk.W)
    default_whitelist = tk.StringVar()
    default_whitelist.set("Akamai Technologies, Google, Palo Alto Networks, The Shadow Server Foundation, The Shadowserver Foundation, Censys, Contabo")
    whitelist_entry = ttk.Entry(frame, width=5, textvariable=default_whitelist)
    whitelist_entry.grid(row=7, column=1, sticky=(tk.W, tk.E))

    # Create and place the submit button
    style = ttk.Style()
    style.configure('Engage.TButton', font=("Sylfaen", 14, "bold"))
    style.configure('Engage.TButton', background='red')
    submit_button = ttk.Button(frame, text="ENGAGE", command=lambda: bulk_check(csv_entry.get(), csv_entry2.get(), api_entry.get(), export_entry.get(), min_entry.get(), whitelist_entry.get(), progress, output_box), style='Engage.TButton')
    submit_button.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E))

    # Create and place the output label, progress bar, and output box
    output_label = ttk.Label(frame, text="Output:", font=("Sylfaen", 14, "bold"))
    output_label.grid(row=9, column=0, sticky=tk.W)
    progress = ttk.Progressbar(frame, orient='horizontal', length=300, mode='determinate')
    progress.grid(row=10, column=0, columnspan=3, sticky=(tk.W, tk.E))
    output_box = tk.Text(frame, width=50, height=9)
    output_box.grid(row=11, column=0, columnspan=3, sticky=(tk.W, tk.E))

    # Create and place the quit button
    style.configure('RunAway.TButton', font=("Sylfaen", 14, "bold"))
    style.configure('RunAway.TButton', background='blue')
    quit_button = ttk.Button(frame, text="RUN AWAY", command=root.destroy, style='RunAway.TButton')
    quit_button.grid(row=12, column=0, columnspan=3, sticky=(tk.W, tk.E))

    # Add padding to all child widgets of the frame
    for child in frame.winfo_children(): 
        child.grid_configure(padx=5, pady=5)

    root.mainloop()  # Start the Tkinter event loop

if __name__ == "__main__":
    main()  # Call the main function if the script is being run directly
