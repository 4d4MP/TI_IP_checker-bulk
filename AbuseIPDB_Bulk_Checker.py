from __future__ import annotations

import concurrent.futures
import csv
import json
import os
import platform
import queue
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Sequence, Set

import requests
import ttkbootstrap as ttkb
from ttkbootstrap.constants import BOTH, CENTER, END, TOP, W
from ttkbootstrap.dialogs import Messagebox
from ttkbootstrap.scrolled import ScrolledText

try:  # Python 3.11
    from tkinter import filedialog, Menu, TclError
except ImportError:  # pragma: no cover - fallback for very old versions
    import tkinter.filedialog as filedialog
    from tkinter import Menu, TclError

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


def write_output_file(
    cleared_list: Sequence[Dict[str, object]], export_path: str, *, append: bool = False
) -> None:
    """Write the processed results to a CSV file."""

    export_path_obj = Path(export_path)
    mode = "a" if append else "w"
    write_header = not append or not export_path_obj.exists()

    with open(export_path, mode, newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=API_RESPONSE_FIELDS)
        if write_header:
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
    export_button: ttkb.Button
    options_button: ttkb.Button
    options_menu: Menu
    open_file_menu_index: int
    progress: ttkb.Progressbar
    status_label: ttkb.Label
    saved_export_path: str | None = field(default=None)

    def values(self) -> tuple[str, str, str]:
        return (
            self.csv1_entry.get().strip(),
            self.csv2_entry.get().strip(),
            self.export_entry.get().strip(),
        )

    def has_all_values(self, *, require_export: bool = True) -> bool:
        csv1, csv2, export = self.values()
        if require_export:
            return bool(csv1 and csv2 and export)
        return bool(csv1 and csv2)

    def clear_progress(self) -> None:
        self.progress.configure(value=0)
        self.status_label.configure(text="Waiting")

    def set_export_visible(self, visible: bool) -> None:
        if visible:
            self.export_entry.grid()
            self.export_button.grid()
            self.options_button.grid()
        else:
            self.export_entry.grid_remove()
            self.export_button.grid_remove()
            self.options_button.grid_remove()

    def set_open_file_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.options_menu.entryconfigure(self.open_file_menu_index, state=state)


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
    *,
    merge_files: bool = False,
    merged_seen_ips: Set[str] | None = None,
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
    if merge_files:
        temp_path = (
            export_path_obj.parent
            / f"{export_path_obj.stem}_{row_index}.jsonl"
        )
    else:
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
        if merge_files and merged_seen_ips is not None:
            with FILE_WRITE_LOCK:
                unique_entries: List[Dict[str, object]] = []
                for entry in cleared_list:
                    ip = str(entry.get("ipAddress") or "")
                    if not ip or ip in merged_seen_ips:
                        continue
                    merged_seen_ips.add(ip)
                    unique_entries.append(entry)

                write_output_file(
                    unique_entries,
                    str(export_path_obj),
                    append=True,
                )
                cleared_list = unique_entries
        else:
            with FILE_WRITE_LOCK:
                write_output_file(
                    cleared_list,
                    str(export_path_obj),
                    append=merge_files,
                )
        queue_.post(
            "file_saved",
            index=row_index,
            export_path=str(export_path_obj),
            merge=merge_files,
        )
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
        try:
            self.window.state("zoomed")
        except TclError:
            self.window.attributes("-zoomed", True)

        self.event_queue: UIEventQueue = UIEventQueue()
        self.day_rows: List[DayRow] = []
        self.general_options_button: ttkb.Button | None = None
        self.general_options_menu: Menu | None = None
        self.general_open_file_index: int | None = None
        self.saved_merged_path: str | None = None

        self._build_ui()
        self.window.after(100, self._process_events)

    def _build_ui(self) -> None:
        header = ttkb.Label(
            self.window,
            text="AbuseIPDB Multi-day Bulk Checker",
            font=("Segoe UI", 16, "bold"),
            anchor=CENTER,
            padding=12,
        )
        header.pack(side=TOP, fill=BOTH)

        config_frame = ttkb.Frame(self.window, padding=20)
        config_frame.pack(side=TOP, fill=BOTH)

        self.api_var = ttkb.StringVar()
        api_label = ttkb.Label(config_frame, text="API Key", font=("Segoe UI", 11, "bold"))
        api_label.grid(row=0, column=0, columnspan=2, sticky=W)
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

        min_label = ttkb.Label(
            config_frame,
            text="Minimum totalReports",
            font=("Segoe UI", 11, "bold"),
        )
        min_label.grid(row=0, column=2, padx=(24, 0), sticky=W)
        self.min_var = ttkb.StringVar(value="100")
        self.min_entry = ttkb.Entry(config_frame, textvariable=self.min_var, width=10)
        self.min_entry.grid(row=1, column=2, sticky=W, padx=(24, 0))

        whitelist_label = ttkb.Label(config_frame, text="Whitelisted ISPs")
        whitelist_label.grid(row=0, column=3, sticky=W)
        self.whitelist_var = ttkb.StringVar(
            value=(
                "Akamai Technologies, Google, Palo Alto Networks, "
                "The Shadowserver Foundation, Censys"
            )
        )
        self.whitelist_entry = ttkb.Entry(config_frame, textvariable=self.whitelist_var, width=35)
        self.whitelist_entry.grid(row=1, column=3, sticky="ew")

        config_frame.columnconfigure(0, weight=2)
        config_frame.columnconfigure(1, weight=0)
        config_frame.columnconfigure(2, weight=1)
        config_frame.columnconfigure(3, weight=2)

        merge_frame = ttkb.Frame(self.window, padding=(20, 0))
        merge_frame.pack(side=TOP, fill=BOTH)
        merge_frame.columnconfigure(2, weight=1)
        merge_frame.columnconfigure(4, weight=0)

        self.merge_var = ttkb.BooleanVar(value=True)
        merge_check = ttkb.Checkbutton(
            merge_frame,
            text="Merge files into single output",
            variable=self.merge_var,
            bootstyle="round-toggle",
            command=self._on_merge_toggle,
        )
        merge_check.grid(row=0, column=0, sticky=W)

        self.general_output_label = ttkb.Label(merge_frame, text="Output file")
        self.general_output_label.grid(row=0, column=1, padx=(20, 5), sticky=W)
        self.general_output_entry = ttkb.Entry(merge_frame, width=40)
        self.general_output_entry.grid(row=0, column=2, sticky="ew", padx=5)
        self.general_output_button = ttkb.Button(
            merge_frame,
            text="Save As",
            bootstyle="warning-outline",
            command=lambda: self._browse_into_entry(self.general_output_entry, _ask_save_file),
        )
        self.general_output_button.grid(row=0, column=3, padx=(0, 10))

        self.general_options_button = ttkb.Button(
            merge_frame,
            text="...",
            bootstyle="secondary-outline",
            width=2,
            command=self._show_general_options_menu,
        )
        self.general_options_button.grid(row=0, column=4, padx=(0, 10))
        self.general_options_menu = Menu(self.general_options_button, tearoff=False)
        self.general_options_menu.add_command(
            label="Open Save Folder",
            command=self._open_general_save_folder,
        )
        self.general_options_menu.add_command(
            label="Open Finished File",
            state="disabled",
            command=self._open_general_export_file,
        )
        self.general_open_file_index = self.general_options_menu.index("end")

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
        for col in range(8):
            weight = 1 if col in (0, 2, 4) else 0
            headings.columnconfigure(col, weight=weight)
        ttkb.Label(headings, text="Input CSV 1", anchor=W).grid(
            row=0, column=0, columnspan=2, sticky=W, padx=5
        )
        ttkb.Label(headings, text="Input CSV 2", anchor=W).grid(
            row=0, column=2, columnspan=2, sticky=W, padx=5
        )
        self.export_heading = ttkb.Label(headings, text="Export File", anchor=W)
        self.export_heading.grid(row=0, column=4, columnspan=2, sticky=W, padx=5)

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
        self._on_merge_toggle()

    def _toggle_api_visibility(self) -> None:
        show_char = self.api_entry.cget("show")
        self.api_entry.configure(show="" if show_char else "*")

    def _show_general_options_menu(self) -> None:
        if self.general_options_menu and self.general_options_button:
            self._show_menu(self.general_options_menu, self.general_options_button)

    def _show_menu(self, menu: Menu, widget: ttkb.Button) -> None:
        try:
            menu.tk_popup(
                widget.winfo_rootx(),
                widget.winfo_rooty() + widget.winfo_height(),
            )
        finally:  # pragma: no branch - tk quirk
            menu.grab_release()

    def _open_general_save_folder(self) -> None:
        self._open_export_folder(self.general_output_entry.get().strip())

    def _open_general_export_file(self) -> None:
        self._open_saved_file(self.saved_merged_path)

    def _open_row_export_folder(self, row: DayRow) -> None:
        self._open_export_folder(row.export_entry.get().strip())

    def _open_row_export_file(self, row: DayRow) -> None:
        self._open_saved_file(row.saved_export_path)

    def _open_export_folder(self, raw_path: str) -> None:
        if not raw_path:
            Messagebox.show_warning("Please choose an export location first.")
            return

        candidate = Path(raw_path).expanduser()
        folder = candidate if candidate.is_dir() else candidate.parent
        if not folder.exists():
            Messagebox.show_warning("The folder does not exist yet.")
            return

        self._open_with_system(folder)

    def _open_saved_file(self, path: str | None) -> None:
        if not path:
            Messagebox.show_warning("There is no saved file to open yet.")
            return

        file_path = Path(path)
        if not file_path.exists():
            Messagebox.show_warning("The saved file is not available on disk.")
            return

        self._open_with_system(file_path)

    def _open_with_system(self, target: Path) -> None:
        try:
            system = platform.system()
            target_str = str(target)
            if system == "Windows":
                os.startfile(target_str)  # type: ignore[attr-defined]
            elif system == "Darwin":
                subprocess.Popen(["open", target_str])
            else:
                subprocess.Popen(["xdg-open", target_str])
        except Exception as exc:  # pragma: no cover - OS interaction
            Messagebox.show_error(f"Unable to open {target}: {exc}")

    def _set_general_open_file_enabled(self, enabled: bool) -> None:
        if self.general_options_menu is None or self.general_open_file_index is None:
            return
        state = "normal" if enabled else "disabled"
        self.general_options_menu.entryconfigure(self.general_open_file_index, state=state)

    def _show_general_output_controls(self) -> None:
        self.general_output_label.grid()
        self.general_output_entry.grid()
        self.general_output_button.grid()
        if self.general_options_button is not None:
            self.general_options_button.grid()
            self._set_general_open_file_enabled(self.saved_merged_path is not None)

    def _hide_general_output_controls(self) -> None:
        self.general_output_label.grid_remove()
        self.general_output_entry.grid_remove()
        self.general_output_button.grid_remove()
        if self.general_options_button is not None:
            self.general_options_button.grid_remove()

    def _on_merge_toggle(self) -> None:
        merge_files = self.merge_var.get()
        if merge_files:
            self._show_general_output_controls()
            if hasattr(self, "export_heading"):
                self.export_heading.grid_remove()
        else:
            self._hide_general_output_controls()
            if hasattr(self, "export_heading"):
                self.export_heading.grid()

        for row in self.day_rows:
            row.set_export_visible(not merge_files)

    def add_row(self) -> None:
        row_frame = ttkb.Frame(self.rows_frame, padding=10, bootstyle="secondary")
        row_frame.pack(side=TOP, fill="x", pady=6)
        for col in range(8):
            weight = 1 if col in (0, 2, 4) else 0
            row_frame.columnconfigure(col, weight=weight)

        csv1_entry = ttkb.Entry(row_frame, width=30)
        csv1_entry.grid(row=0, column=0, sticky="ew", padx=5)
        csv1_button = ttkb.Button(
            row_frame,
            text="Browse",
            bootstyle="info-outline",
            command=lambda e=csv1_entry: self._browse_into_entry(e, _ask_open_file),
        )
        csv1_button.grid(row=0, column=1, padx=(0, 10))

        csv2_entry = ttkb.Entry(row_frame, width=30)
        csv2_entry.grid(row=0, column=2, sticky="ew", padx=5)
        csv2_button = ttkb.Button(
            row_frame,
            text="Browse",
            bootstyle="info-outline",
            command=lambda e=csv2_entry: self._browse_into_entry(e, _ask_open_file),
        )
        csv2_button.grid(row=0, column=3, padx=(0, 10))

        export_entry = ttkb.Entry(row_frame, width=30)
        export_entry.grid(row=0, column=4, sticky="ew", padx=5)
        export_button = ttkb.Button(
            row_frame,
            text="Save As",
            bootstyle="warning-outline",
            command=lambda e=export_entry: self._browse_into_entry(e, _ask_save_file),
        )
        export_button.grid(row=0, column=5, padx=(0, 10))

        options_menu = Menu(row_frame, tearoff=False)
        options_menu.add_command(label="Open Save Folder")
        options_menu.add_command(label="Open Finished File", state="disabled")
        open_file_index = options_menu.index("end")
        options_button = ttkb.Button(
            row_frame,
            text="...",
            bootstyle="secondary-outline",
            width=2,
            command=lambda: None,
        )
        options_button.grid(row=0, column=6, padx=(0, 10))

        remove_button = ttkb.Button(
            row_frame,
            text="Remove",
            bootstyle="secondary-link",
            command=lambda rf=row_frame: self._remove_row(rf),
        )
        remove_button.grid(row=0, column=7, padx=(0, 5))

        progress = ttkb.Progressbar(row_frame, bootstyle="info-striped", length=180)
        progress.grid(row=1, column=0, columnspan=8, sticky="ew", pady=(12, 0))

        status_label = ttkb.Label(row_frame, text="Waiting", bootstyle="secondary")
        status_label.grid(row=2, column=0, columnspan=8, sticky=W, pady=(4, 0))

        new_row = DayRow(
            container=row_frame,
            csv1_entry=csv1_entry,
            csv2_entry=csv2_entry,
            export_entry=export_entry,
            export_button=export_button,
            options_button=options_button,
            options_menu=options_menu,
            open_file_menu_index=open_file_index,
            progress=progress,
            status_label=status_label,
        )

        self.day_rows.append(new_row)

        options_button.configure(
            command=lambda m=options_menu, b=options_button: self._show_menu(m, b)
        )
        options_menu.entryconfigure(
            0, command=lambda r=new_row: self._open_row_export_folder(r)
        )
        options_menu.entryconfigure(
            new_row.open_file_menu_index,
            command=lambda r=new_row: self._open_row_export_file(r),
        )

        new_row.set_open_file_enabled(False)
        new_row.set_export_visible(not self.merge_var.get())

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

        merge_files = self.merge_var.get()
        merged_export_path = self.general_output_entry.get().strip()

        if merge_files and not merged_export_path:
            Messagebox.show_warning(
                "Please provide an output file path for the merged results."
            )
            return

        valid_rows = [
            row
            for row in self.day_rows
            if row.has_all_values(require_export=not merge_files)
        ]
        if not valid_rows:
            if merge_files:
                Messagebox.show_warning(
                    "Please provide both input CSV paths for at least one row."
                )
            else:
                Messagebox.show_warning(
                    "Please provide all three paths for at least one row."
                )
            return

        for row in valid_rows:
            row.clear_progress()

        self.saved_merged_path = None
        self._set_general_open_file_enabled(False)
        for row in self.day_rows:
            row.saved_export_path = None
            row.set_open_file_enabled(False)

        self.log_output.delete("1.0", END)

        worker_thread = threading.Thread(
            target=self._execute_checks,
            args=(
                valid_rows,
                api_key,
                min_entry,
                whitelist_entry,
                merge_files,
                merged_export_path,
            ),
            daemon=True,
        )
        worker_thread.start()

    def _execute_checks(
        self,
        rows: Sequence[DayRow],
        api_key: str,
        min_entry: str,
        whitelist_entry: str,
        merge_files: bool,
        merged_export_path: str,
    ) -> None:
        combined_path: Path | None = None
        merged_seen_ips: Set[str] | None = None
        if merge_files:
            combined_path = Path(merged_export_path)
            combined_path.parent.mkdir(parents=True, exist_ok=True)
            combined_path.unlink(missing_ok=True)
            merged_seen_ips = set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(rows)) as executor:
            tasks = []
            for index, row in enumerate(rows):
                csv1, csv2, export_path = row.values()
                if merge_files:
                    export_path = merged_export_path
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
                        merge_files=merge_files,
                        merged_seen_ips=merged_seen_ips,
                    )
                )

            for future in concurrent.futures.as_completed(tasks):
                try:
                    future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.event_queue.post("log", message=f"Worker crashed: {exc}")

        if merge_files and combined_path is not None:
            message = f"All checks complete. Output saved to {combined_path}."
        else:
            message = "All checks complete."
        self.event_queue.post("log", message=message)

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
                elif event == "file_saved":
                    self._handle_file_saved(payload)
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

    def _handle_file_saved(self, payload: dict) -> None:
        index = payload.get("index")
        export_path = payload.get("export_path")
        merge = payload.get("merge")

        if merge:
            self.saved_merged_path = export_path
            self._set_general_open_file_enabled(bool(export_path))

        if index is None or not (0 <= index < len(self.day_rows)):
            return

        row = self.day_rows[index]
        row.saved_export_path = export_path
        row.set_open_file_enabled(bool(export_path))

    def run(self) -> None:
        self.window.mainloop()


def main() -> None:
    app = MultiDayApp()
    app.run()


if __name__ == "__main__":
    main()
