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

The GUI uses the standard library `tkinter` module. On some Linux distributions, you may need to install the `python3-tk` package separately.

## Usage

1. Install the dependencies listed in `requirements.txt` if present, or simply ensure `requests` is installed:

   ```bash
   pip install requests
   ```

2. Run the application:

   ```bash
   python main.py
   ```

3. Provide your API key and select the CSV input and output paths via the GUI. Adjust the minimum report threshold and ISP whitelist as needed, then click **ENGAGE** to start the scan.

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
