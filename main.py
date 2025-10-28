# 4d4MP's AbuseIPDB Bulk Checker

import csv          #implements classes to read and write tabular data in CSV format
import requests     #allows sending/receiving HTTP requests
import json         #parse JSON strings
import os           #provides functions for interacting with the operating system
import tkinter as tk    #GUI toolkit
from tkinter import filedialog, ttk, messagebox #filedialog: open/save files; ttk: themed widgets; messagebox: display message boxes
import time        #time-related functions
import concurrent.futures #for parallel computing

def read_csv(file_path):
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        return [row for row in reader]

def extract_ip_list(csv_data):
    header = csv_data[0]
    column_name = "SrcIpAddr" if "SrcIpAddr" in header else "SourceIP" if "SourceIP" in header else None
    print("Extracting: " + str(len(csv_data)) + " - " + str(column_name))
    if column_name is None:
        raise ValueError("Neither 'SrcIpAddr' nor 'SourceIP' found in CSV header")
    column_index = header.index(column_name)
#    return {row[column_index].strip() for row in csv_data[1:]}
    return [row[column_index].strip() for row in csv_data[1:]]

def get_unique_ips_custom(csv1, csv2):
    ip_list1 = extract_ip_list(csv1)
    ip_list2 = extract_ip_list(csv2)
    print("ip_list1: " + str(len(ip_list1)))
    print("ip_list2: " + str(len(ip_list2)))
    print(len(set(ip_list1).symmetric_difference(set(ip_list2))))
    return set(ip_list1).symmetric_difference(set(ip_list2))

def get_unique_ips(csv1, csv2):
    ip_list1 = extract_ip_list(csv1)
    ip_list2 = extract_ip_list(csv2)
    combined_ips = ip_list1 + ip_list2
    # Remove duplicates while preserving the order
    seen = set()
    unique_ips = []
    for ip in combined_ips:
        if ip not in seen:
            unique_ips.append(ip)
            seen.add(ip)
    print("Number of unique IPs: " + str(len(unique_ips)))
    return unique_ips

def clear_output(data_list, min_entry, whitelist_entry):
    return_list = []
    whitelist = [w.strip() for w in whitelist_entry.split(",")]
    for line in data_list:
        isp = line['isp'] if line['isp'] is not None else ""
        if line['totalReports'] > int(min_entry) and not any(whitelisted in isp for whitelisted in whitelist):
            return_list.append(line)

    print("Number of malicious IPs: " + str(len(return_list)))

    return return_list

def write_output_file(cleared_list, export_path):
    # Define the header keys that we expect in each dictionary
    keys = ['ipAddress', 'abuseConfidenceScore', 'isp', 'domain', 'countryCode', 'totalReports', 'lastReportedAt']
    
    # Open the export file in write mode
    with open(export_path, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=keys)
        writer.writeheader()  # Write the header row
        writer.writerows(cleared_list)

def bulk_check(csv_path, csv_path2, api_key, export_path, min_entry, whitelist_entry, progress, output_box):
    csv1 = read_csv(csv_path)
    csv2 = read_csv(csv_path2)
    ip_list = get_unique_ips(csv1, csv2)

    start_time = time.time()
    json_temp_path = os.path.join(os.path.dirname(export_path), 'aipdbulkchecktempfile.json')
    total_rows = len(ip_list)
    api_return_list = []

    def fetch_ip_data(ip):
        """Helper function to fetch data for a single IP"""
        try:
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", 
                headers={'Accept': 'application/json', 'Key': api_key},
                timeout=10  # Add timeout to prevent hanging requests
            )
            if response.status_code == 200:
                return ip, response.json(), None
            else:
                return ip, None, f"API error: {response.status_code}"
        except Exception as e:
            return ip, None, str(e)

    # Use ThreadPoolExecutor for parallel requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all requests
        futures = {executor.submit(fetch_ip_data, ip): ip for ip in ip_list}
        
        completed_count = 0
        successful_responses = []

        with open(json_temp_path, 'w') as json_file:
            for future in concurrent.futures.as_completed(futures):
                ip, data, error = future.result()
                completed_count += 1
                
                if data:
                    json_file.write(json.dumps(data) + "\n")
                    successful_responses.append(data)
                    print(f"\rNumber of successful API calls: {len(successful_responses)}", end="", flush=True)
                else:
                    # Handle errors
                    output_box.delete('1.0', tk.END)
                    output_box.insert(tk.END, f"{ip} error: {error}")

                # Update progress
                progress['value'] = completed_count / total_rows * 100
                output_box.delete('1.0', tk.END)
                output_box.insert(tk.END, f"Processing {completed_count} of {total_rows}")
                output_box.update_idletasks()

    # Process the results
    with open(json_temp_path, 'r') as json_file:
        keys = ['ipAddress', 'abuseConfidenceScore', 'isp', 'domain', 'countryCode', 'totalReports', 'lastReportedAt']
        
        for line in json_file:
            data = json.loads(line)["data"]
            api_return_list.append({key: data.get(key) for key in keys})

    cleared_list = clear_output(api_return_list, min_entry, whitelist_entry)
    write_output_file(cleared_list, export_path)        

    return api_return_list

def browse_file(entry):     # Define a function to browse for a file
    filename = filedialog.askopenfilename() # Open a file dialog and get the selected filename
    entry.delete(0, tk.END) # Clear the entry box
    entry.insert(0, filename) # Insert the filename into the entry box

def browse_save_file(entry):  # Define a function to browse for a file save
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])  # Open a save file dialog and get the selected filename
    if filename:  # If a filename was selected
        if os.path.exists(filename):  # If the file already exists
            if messagebox.askokcancel("Warning", "The file already exists. Do you want to overwrite it?"):  # Ask the user if they want to overwrite the existing file
                entry.delete(0, tk.END)  # Clear the entry box
                entry.insert(0, filename)  # Insert the filename into the entry box
        else:  # If the file does not exist
            entry.delete(0, tk.END)  # Clear the entry box
            entry.insert(0, filename)  # Insert the filename into the entry box

def main():
    global root
    root = tk.Tk()  # Create the main window
    root.title("4d4MP's AbuseIPDB Bulk Checker")  # Set the title of the window
    root.geometry("620x600")  # Set the size of the window

    frame = ttk.Frame(root, padding="10")  # Create a frame widget
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))  # Place the frame on the grid

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
