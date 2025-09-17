# NVD CVE SQLite Database & Flask Web App

## Overview
This project downloads the National Vulnerability Database (NVD) CVE dataset via the official NVD API and stores it locally in a SQLite database. It includes a Flask web application that allows browsing, searching, and detailed viewing of vulnerability CVEs with full CVSS V2 metrics and CPE information.

## Setup Instructions

### Prerequisites
- Python 3.8+
- Virtual environment recommended
- Internet access to fetch data from NVD API

## Database Initialization & Data Fetching

To initialize the local database and import CVE data from the external API, run:

"python fetch_all_cves_parallel.py"

- The script automatically creates the database tables if not present.
- It resumes fetching from the last saved offset to avoid duplicate data.
- Fetching the full dataset may take several hours depending on network speed.
- To start fresh, delete the existing database file located at `./database/nvd_cve.db` before running the script.

## Running the Flask Web Application

After data fetching is complete, start the Flask server with:

python app.py

Open your browser and navigate to:

http://localhost:5000/cves/list

- Browse the list of CVEs with pagination and filtering options.
- Click on any CVE row in the table to view detailed CVE information.
- Please verify URLs and functionality as shown in the screenshots below.

## URL and Screenshots

Ensure your URLs and links match the following patterns for proper navigation and filtering capabilities:

- [CVE Listwith limit 10 ](http://127.0.0.1:5000/cves/list)
- [CVE list filtered by limit 50](http://127.0.0.1:5000/cves/list?limit=50&page=1)
- [CVE detail for ID 1](http://127.0.0.1:5000/cves/CVE-2011-0467)
- [CVE detail for ID 2](http://127.0.0.1:5000/cves/CVE-2018-12042)
- [CVE List with year filter page 1](http://127.0.0.1:5000/cves/list?year=2000)
- [CVE list with year filter page 2](http://127.0.0.1:5000/cves/list?year=2000&page=2)
- [CVE list filtered by score of 7](http://127.0.0.1:5000/cves/list?score=7)
- [CVE list filtered by last modified days](http://127.0.0.1:5000/cves/list?last_modified_days=30)
- [CVE list filtered by year and last modified days](http://127.0.0.1:5000/cves/list?year=1999&last_modified_days=30)
- [CVE list filtered by year and score](http://127.0.0.1:5000/cves/list?year=2000&score=7)
- [CVE list with min and max score filter](http://127.0.0.1:5000/cves/list?score_min=5&score_max=9)


### Screenshots

![1. CVE List (limit = 10)](screenshots/1.%20cve%20list%20(limit%20=%2010).png)
![2. CVE List (limit = 50)](screenshots/2.%20cve%20list%20(limit%20=%2050).png)
![3. CVE Detail ID 1](screenshots/3.%20cve%20detail%20id%201.png)
![4. CVE Detail ID 2](screenshots/4.%20cve%20detail%20id%202.png)
![5. By Year Filter (page=1)](screenshots/5.%20by%20year%20filter%20(page=1).png)
![6. By Year Filter (page=2)](screenshots/6.%20by%20year%20filter%20(page=2).png)
![7. By Score Filter](screenshots/7.%20by%20score%20filter.png)
![8. By Last Modified Days Filter](screenshots/8.%20by%20last_%20modified_%20days%20filter.png)
![9. By Year and Last Modified Days Filter](screenshots/9.%20by%20year%20and%20last_%20modified_%20days%20filter.png)
![10. By Year and Score Filter](screenshots/10.%20by%20year%20and%20score%20filter.png)
![11. By Min and Max Score Filter](screenshots/11.%20by%20min%20and%20max%20score%20filter.png)

## Database Schema

- **cves**: Stores CVE details and CVSS V2 metrics including sub-metrics.
- **cpe_matches**: Stores the vulnerable CPE criteria associated with each CVE.

## Code Highlights

- **fetch_all_cves_parallel.py**  
  Concurrently fetches CVE data from the NVD API and writes to SQLite with retry logic to handle API limits and database locks.

- **app.py**  
  Flask server rendering CVE list and detail pages powered by local SQLite database.

- **templates/detail.html**  
  Displays detailed CVE description, CVSS V2 metrics table, and associated CPE entries.

## Notes

- The fetch script resumes from the last saved index; no need to re-fetch all data unless you delete the database.
- API rate limiting and network errors are handled with exponential backoff.
- Always verify navigation and filters by comparing with the provided screenshots.


