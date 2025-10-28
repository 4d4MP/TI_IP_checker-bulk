from __future__ import annotations

import concurrent.futures
import csv
import json
import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Sequence

import requests
import ttkbootstrap as ttkb
from ttkbootstrap.constants import BOTH, BOTTOM, CENTER, END, LEFT, TOP, W
from ttkbootstrap.dialogs import Messagebox
from ttkbootstrap.scrolled import ScrolledText

try:  # Python 3.11
    from tkinter import filedialog
except ImportError:  # pragma: no cover - fallback for very old versions
    import tkinter.filedialog as filedialog

# Standalone processing helpers derived from the original single-day tool.

IP_HEADERS: tuple[str, ...] = ("SrcIpAddr", "SourceIP")
API_RESPONSE_FIELDS: tuple[str, ...] = (
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
    for candidate in IP_HEADERS:
        if candidate in header:
            return candidate
    raise ValueError("Neither 'SrcIpAddr' nor 'SourceIP' found in CSV header")


def _extract_ip_list(csv_data: Sequence[Sequence[str]]) -> List[str]:
    if not csv_data:
        return []

    header = csv_data[0]
    column_name = _resolve_ip_header(header)
    column_index = header.index(column_name)
    return [row[column_index].strip() for row in csv_data[1:] if len(row) > column_index]


def get_unique_ips(csv1: Sequence[Sequence[str]], csv2: Sequence[Sequence[str]]) -> List[str]:
    """Return IPs from both CSVs, preserving the first occurrence order."""

    ip_list1 = _extract_ip_list(csv1)
    ip_list2 = _extract_ip_list(csv2)
    combined_ips = ip_list1 + ip_list2
    seen = set()
    unique_ips: List[str] = []
    for ip in combined_ips:
        if ip and ip not in seen:
            unique_ips.append(ip)
            seen.add(ip)
    return unique_ips


def clear_output(
    data_list: Iterable[Dict[str, object]],
    min_entry: str,
    whitelist_entry: str,
) -> List[Dict[str, object]]:
    """Filter API responses by minimum reports and ISP whitelist."""

    whitelist = [w.strip() for w in whitelist_entry.split(",") if w.strip()]
    threshold = int(min_entry)
    return_list = []
    for line in data_list:
        isp = (line.get("isp") if isinstance(line, dict) else None) or ""
        total_reports = int(line.get("totalReports", 0)) if isinstance(line, dict) else 0
        if total_reports > threshold and not any(whitelisted in isp for whitelisted in whitelist):
            return_list.append(line)
    return return_list


def write_output_file(cleared_list: Sequence[Dict[str, object]], export_path: str) -> None:
    """Write the processed results to a CSV file."""

    with open(export_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=API_RESPONSE_FIELDS)
        writer.writeheader()
        writer.writerows(cleared_list)


# A lock that protects simultaneous writes to export files.
FILE_WRITE_LOCK = threading.Lock()


class UIEventQueue(queue.Queue[tuple[str, dict]]):
    """Thread-safe queue dedicated to UI events."""

    def post(self, event: str, **payload: object) -> None:
        self.put((event, dict(payload)))


@dataclass
class DayRow:
    """A single row of CSV input/output controls."""

    container: ttkb.Frame
    csv1_entry: ttkb.Entry
    csv2_entry: ttkb.Entry
    export_entry: ttkb.Entry
    progress: ttkb.Progressbar
    status_label: ttkb.Label

    def values(self) -> tuple[str, str, str]:
        return (
            self.csv1_entry.get().strip(),
            self.csv2_entry.get().strip(),
            self.export_entry.get().strip(),
        )

    def has_all_values(self) -> bool:
        csv1, csv2, export = self.values()
        return bool(csv1 and csv2 and export)

    def clear_progress(self) -> None:
        self.progress.configure(value=0)
        self.status_label.configure(text="Waiting")


def _ask_open_file() -> str:
    return filedialog.askopenfilename()


def _ask_save_file() -> str:
    return filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
    )


def _update_status(
    queue_: UIEventQueue,
    row_index: int,
    *,
    message: str | None = None,
    progress: float | None = None,
    append_log: str | None = None,
) -> None:
    queue_.post(
        "update_row",
        index=row_index,
        message=message,
        progress=progress,
        append_log=append_log,
    )


def _fetch_ip_data(api_key: str, ip: str) -> tuple[str, Dict[str, object] | None, str | None]:
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


def _process_single_day(
    row_index: int,
    api_key: str,
    csv_path: str,
    csv_path2: str,
    export_path: str,
    min_entry: str,
    whitelist_entry: str,
    queue_: UIEventQueue,
) -> None:
    try:
        _update_status(queue_, row_index, message="Loading input files...")
        csv1 = read_csv(csv_path)
        csv2 = read_csv(csv_path2)
        ip_list = list(get_unique_ips(csv1, csv2))
    except Exception as exc:
        _update_status(
            queue_,
            row_index,
            message="Failed to read CSV files",
            append_log=f"Row {row_index + 1}: {exc}",
        )
        return

    total_rows = max(len(ip_list), 1)
    successful_responses: List[Dict[str, object]] = []
    export_path_obj = Path(export_path)
    temp_path = export_path_obj.with_suffix(".jsonl")

    if not ip_list:
        _update_status(queue_, row_index, message="No IPs found, writing empty output...")
    else:
        _update_status(
            queue_,
            row_index,
            message=f"Checking {len(ip_list)} IPs...",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_fetch_ip_data, api_key, ip): ip for ip in ip_list}

        completed_count = 0
        try:
            with temp_path.open("w", encoding="utf-8") as temp_file:
                for future in concurrent.futures.as_completed(futures):
                    ip, data, error = future.result()
                    completed_count += 1

                    if data:
                        temp_file.write(json.dumps(data) + "\n")
                        successful_responses.append(data)
                    else:
                        _update_status(
                            queue_,
                            row_index,
                            append_log=f"Row {row_index + 1} - {ip}: {error}",
                        )

                    _update_status(
                        queue_,
                        row_index,
                        progress=completed_count / total_rows * 100,
                        message=f"Processed {completed_count}/{len(ip_list)} IPs",
                    )
        finally:
            for future in futures:
                future.cancel()

    api_return_list: List[Dict[str, object]] = []
    if temp_path.exists():
        with temp_path.open("r", encoding="utf-8") as temp_file:
            for line in temp_file:
                data = json.loads(line)["data"]
                api_return_list.append({key: data.get(key) for key in API_RESPONSE_FIELDS})
        temp_path.unlink(missing_ok=True)

    try:
        cleared_list = clear_output(api_return_list, min_entry, whitelist_entry)
        export_path_obj.parent.mkdir(parents=True, exist_ok=True)
        with FILE_WRITE_LOCK:
            write_output_file(cleared_list, str(export_path_obj))
        _update_status(
            queue_,
            row_index,
            progress=100.0,
            message=f"Completed ({len(cleared_list)} suspicious IPs)",
            append_log=f"Row {row_index + 1}: wrote {len(cleared_list)} entries to {export_path}",
        )
    except Exception as exc:  # pragma: no cover - best effort logging
        _update_status(
            queue_,
            row_index,
            message="Failed to write output",
            append_log=f"Row {row_index + 1}: {exc}",
        )


class MultiDayApp:
    """GUI application that orchestrates the multi-day AbuseIPDB checks."""

    def __init__(self) -> None:
        self.window = ttkb.Window(themename="superhero")
        self.window.title("AbuseIPDB Multi-day Bulk Checker")
        self.window.geometry("940x720")

        self.event_queue: UIEventQueue = UIEventQueue()
        self.day_rows: List[DayRow] = []

        self._build_ui()
        self.window.after(100, self._process_events)

    def _build_ui(self) -> None:
        header = ttkb.Label(
            self.window,
            text="AbuseIPDB Multi-day Bulk Checker",
            font=("Segoe UI", 20, "bold"),
            bootstyle="inverse",
            anchor=CENTER,
            padding=20,
        )
        header.pack(side=TOP, fill=BOTH)

        config_frame = ttkb.Frame(self.window, padding=20)
        config_frame.pack(side=TOP, fill=BOTH)

        self.api_var = ttkb.StringVar()
        api_label = ttkb.Label(config_frame, text="API Key", font=("Segoe UI", 11, "bold"))
        api_label.grid(row=0, column=0, sticky=W)
        self.api_entry = ttkb.Entry(config_frame, textvariable=self.api_var, show="*")
        self.api_entry.grid(row=1, column=0, sticky="ew", padx=(0, 12))

        reveal_button = ttkb.Button(
            config_frame,
            text="Show",
            bootstyle="secondary-outline",
            command=self._toggle_api_visibility,
            width=8,
        )
        reveal_button.grid(row=1, column=1, sticky=W)

        min_label = ttkb.Label(config_frame, text="Minimum totalReports", font=("Segoe UI", 11, "bold"))
        min_label.grid(row=0, column=2, padx=(20, 0), sticky=W)
        self.min_var = ttkb.StringVar(value="100")
        self.min_entry = ttkb.Entry(config_frame, textvariable=self.min_var, width=10)
        self.min_entry.grid(row=1, column=2, sticky=W)

        whitelist_label = ttkb.Label(config_frame, text="Whitelisted ISPs (comma separated)")
        whitelist_label.grid(row=0, column=3, padx=(20, 0), sticky=W)
        self.whitelist_var = ttkb.StringVar(
            value=(
                "Akamai Technologies, Google, Palo Alto Networks, "
                "The Shadowserver Foundation, Censys, Contabo"
            )
        )
        self.whitelist_entry = ttkb.Entry(config_frame, textvariable=self.whitelist_var, width=35)
        self.whitelist_entry.grid(row=1, column=3, sticky="ew")

        config_frame.columnconfigure(0, weight=2)
        config_frame.columnconfigure(3, weight=2)

        add_button = ttkb.Button(
            self.window,
            text="Add Day",
            bootstyle="success-outline",
            command=self.add_row,
        )
        add_button.pack(side=TOP, pady=10)

        self.rows_container = ttkb.Frame(self.window, padding=(20, 10))
        self.rows_container.pack(side=TOP, fill=BOTH, expand=True)

        headings = ttkb.Frame(self.rows_container)
        headings.pack(side=TOP, fill="x")
        ttkb.Label(headings, text="CSV Day A", width=25, anchor=W).pack(side=LEFT, padx=5)
        ttkb.Label(headings, text="CSV Day B", width=25, anchor=W).pack(side=LEFT, padx=5)
        ttkb.Label(headings, text="Export File", width=25, anchor=W).pack(side=LEFT, padx=5)

        self.rows_frame = ttkb.Frame(self.rows_container)
        self.rows_frame.pack(side=TOP, fill=BOTH, expand=True)

        self.log_output = ScrolledText(self.window, height=10, autohide=True)
        self.log_output.pack(side=TOP, fill=BOTH, padx=20, pady=10)

        run_button = ttkb.Button(
            self.window,
            text="Run Bulk Checks",
            bootstyle="danger",
            command=self.run_checks,
        )
        run_button.pack(side=TOP, pady=10)

        self.add_row()

    def _toggle_api_visibility(self) -> None:
        show_char = self.api_entry.cget("show")
        self.api_entry.configure(show="" if show_char else "*")

    def add_row(self) -> None:
        row_frame = ttkb.Frame(self.rows_frame, padding=10, bootstyle="secondary")
        row_frame.pack(side=TOP, fill="x", pady=6)

        csv1_entry = ttkb.Entry(row_frame, width=30)
        csv1_entry.pack(side=LEFT, padx=5, fill="x", expand=True)
        csv1_button = ttkb.Button(
            row_frame,
            text="Browse",
            bootstyle="info-outline",
            command=lambda e=csv1_entry: self._browse_into_entry(e, _ask_open_file),
        )
        csv1_button.pack(side=LEFT, padx=(0, 10))

        csv2_entry = ttkb.Entry(row_frame, width=30)
        csv2_entry.pack(side=LEFT, padx=5, fill="x", expand=True)
        csv2_button = ttkb.Button(
            row_frame,
            text="Browse",
            bootstyle="info-outline",
            command=lambda e=csv2_entry: self._browse_into_entry(e, _ask_open_file),
        )
        csv2_button.pack(side=LEFT, padx=(0, 10))

        export_entry = ttkb.Entry(row_frame, width=30)
        export_entry.pack(side=LEFT, padx=5, fill="x", expand=True)
        export_button = ttkb.Button(
            row_frame,
            text="Save As",
            bootstyle="warning-outline",
            command=lambda e=export_entry: self._browse_into_entry(e, _ask_save_file),
        )
        export_button.pack(side=LEFT, padx=(0, 10))

        remove_button = ttkb.Button(
            row_frame,
            text="Remove",
            bootstyle="secondary-link",
            command=lambda rf=row_frame: self._remove_row(rf),
        )
        remove_button.pack(side=LEFT)

        progress = ttkb.Progressbar(row_frame, bootstyle="info-striped", length=180)
        progress.pack(side=BOTTOM, fill="x", expand=True, pady=(12, 0))

        status_label = ttkb.Label(row_frame, text="Waiting", bootstyle="secondary")
        status_label.pack(side=BOTTOM, anchor=W)

        self.day_rows.append(
            DayRow(
                container=row_frame,
                csv1_entry=csv1_entry,
                csv2_entry=csv2_entry,
                export_entry=export_entry,
                progress=progress,
                status_label=status_label,
            )
        )

    def _remove_row(self, frame: ttkb.Frame) -> None:
        if len(self.day_rows) == 1:
            Messagebox.show_info("At least one row is required.")
            return

        for index, row in enumerate(self.day_rows):
            if row.container is frame:
                frame.destroy()
                del self.day_rows[index]
                break

    def _browse_into_entry(self, entry: ttkb.Entry, chooser: Callable[[], str]) -> None:
        path = chooser()
        if path:
            entry.delete(0, END)
            entry.insert(0, path)

    def run_checks(self) -> None:
        api_key = self.api_var.get().strip()
        if not api_key:
            Messagebox.show_error("API key is required.")
            return

        min_entry = self.min_var.get().strip()
        whitelist_entry = self.whitelist_var.get().strip()

        valid_rows = [row for row in self.day_rows if row.has_all_values()]
        if not valid_rows:
            Messagebox.show_warning("Please provide all three paths for at least one row.")
            return

        for row in valid_rows:
            row.clear_progress()

        self.log_output.delete("1.0", END)

        worker_thread = threading.Thread(
            target=self._execute_checks,
            args=(valid_rows, api_key, min_entry, whitelist_entry),
            daemon=True,
        )
        worker_thread.start()

    def _execute_checks(
        self,
        rows: Sequence[DayRow],
        api_key: str,
        min_entry: str,
        whitelist_entry: str,
    ) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(rows)) as executor:
            tasks = []
            for index, row in enumerate(rows):
                csv1, csv2, export_path = row.values()
                tasks.append(
                    executor.submit(
                        _process_single_day,
                        index,
                        api_key,
                        csv1,
                        csv2,
                        export_path,
                        min_entry,
                        whitelist_entry,
                        self.event_queue,
                    )
                )

            for future in concurrent.futures.as_completed(tasks):
                try:
                    future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.event_queue.post("log", message=f"Worker crashed: {exc}")

        self.event_queue.post("log", message="All checks complete.")

    def _process_events(self) -> None:
        try:
            while True:
                event, payload = self.event_queue.get_nowait()
                if event == "update_row":
                    self._handle_row_update(payload)
                elif event == "log":
                    message = payload.get("message", "")
                    if message:
                        self.log_output.insert(END, message + "\n")
                        self.log_output.see(END)
                else:
                    message = payload.get("message", "")
                    if message:
                        self.log_output.insert(END, message + "\n")
                        self.log_output.see(END)
        except queue.Empty:
            pass

        self.window.after(100, self._process_events)

    def _handle_row_update(self, payload: dict) -> None:
        index = payload.get("index")
        if index is None or not (0 <= index < len(self.day_rows)):
            return

        row = self.day_rows[index]
        message = payload.get("message")
        if message:
            row.status_label.configure(text=message)

        progress = payload.get("progress")
        if progress is not None:
            row.progress.configure(value=progress)

        append_log = payload.get("append_log")
        if append_log:
            self.log_output.insert(END, append_log + "\n")
            self.log_output.see(END)

    def run(self) -> None:
        self.window.mainloop()


def main() -> None:
    app = MultiDayApp()
    app.run()


if __name__ == "__main__":
    main()
