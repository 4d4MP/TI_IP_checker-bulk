# AbuseIPDB Bulk Checker

A Tkinter-based GUI utility for comparing two CSV exports and checking the resulting IP list against the [AbuseIPDB](https://www.abuseipdb.com/) API. The tool removes whitelist matches, filters by the number of reports, and exports a CSV containing the remaining high-risk IP addresses.

## Features

- Loads two CSV files and merges their unique IP addresses while preserving order.
- Executes AbuseIPDB lookups in parallel to reduce overall runtime.
- Filters results by minimum `totalReports` value and ISP whitelist entries.
- Writes a CSV export containing the curated results.

## Requirements

- Python 3.9+
- An AbuseIPDB API key
- Python packages listed in [`requirements.txt`](requirements.txt)

The original GUI uses the standard library `tkinter` module. On some Linux distributions, you may need to install the `python3-tk` package separately. The multi-day interface leverages [`ttkbootstrap`](https://ttkbootstrap.readthedocs.io/) for a more modern widget set.

## Usage

1. Install the dependencies listed in `requirements.txt`:

   ```bash
   pip install -r requirements.txt
   ```

2. Run the classic single-day application:

   ```bash
   python main.py
   ```

   Or launch the modern multi-day interface:

   ```bash
   python multi_day_ui.py
   ```

3. Provide your API key and select the CSV input and output paths via either GUI. Adjust the minimum report threshold and ISP whitelist as needed, then start the scan to generate the output CSV file(s).

## Output

The application writes a CSV file with the following columns:

- `ipAddress`
- `abuseConfidenceScore`
- `isp`
- `domain`
- `countryCode`
- `totalReports`
- `lastReportedAt`

## License

This project is distributed under the terms of the [MIT License](LICENSE).
