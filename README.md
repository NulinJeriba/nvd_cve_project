NVD CVE SQLite Database & Flask Web App

OVERVIEW

This project downloads the National Vulnerability Database (NVD) CVE dataset via the official NVD API and stores it locally in a SQLite database. It includes a Flask web application that allows browsing, searching, and detailed viewing of vulnerability CVEs with full CVSS V2 metrics and CPE information.

Setup Instructions:
Prerequisites
1. Python 3.8+
2. Virtual environment recommended
3. Internet access to fetch from NVD API

Database Initialization & Data Fetching
Run the fetch script to create tables and start importing CVE data into SQLite:

-------------------> python fetch_all_cves_parallel.py

1. The script automatically resumes fetching from where it left off based on your existing database content.
2. This allows restarting if interrupted without fetching data from the beginning again.
3. Fetching the full dataset can take several hours depending on network and machine speed.

Running the Flask Web Application
Start the Flask app:
-------------------> python app.py
Open your web browser at:
http://localhost:5000/cves/list
Browse and search CVEs, and click to view detailed metrics and CPE info.

Database Schema
1. cves: Stores CVE details and CVSS V2 metrics including sub-metrics.
2. cpe_matches: Stores the vulnerable CPE criteria associated with each CVE.

SQLite Write Ahead Logging (WAL) mode is enabled to improve database concurrency.

*Code Highlights*
1. fetch_all_cves_parallel.py:
---> Concurrently fetches and parses CVE data from the NVD API with a dedicated database writer thread to improve performance and avoid locking issues.

2. app.py:
---> Flask web server serving CVE list and detail pages powered by the SQLite database.

3. templates/detail.html:
---> Displays CVE description alongside detailed CVSS V2 metric tables and associated CPE information.

Notes:
* The fetch script will start from the last fetched offset automatically, so you don't need to fetch all the data every time.
* If you want to start fresh, delete your database file before running the fetch script.
* The fetch process handles API rate limiting and network interruptions gracefully.