import requests
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

DATABASE = './database/nvd_cve.db'
API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 200  # Max per API docs
MAX_WORKERS = 5  # Number of concurrent threads

def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=30)  # increased timeout
    return conn

def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            identifier TEXT,
            published_date TEXT,
            last_modified_date TEXT,
            status TEXT,
            description TEXT,
            cvss_v2_score REAL,
            cvss_v2_severity TEXT,
            cvss_v2_vector TEXT,
            exploitability_score REAL,
            impact_score REAL,
            cvss_v2_access_vector TEXT,
            cvss_v2_access_complexity TEXT,
            cvss_v2_authentication TEXT,
            cvss_v2_confidentiality_impact TEXT,
            cvss_v2_integrity_impact TEXT,
            cvss_v2_availability_impact TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cpe_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            criteria TEXT,
            match_criteria_id TEXT,
            vulnerable TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_or_update_cve(conn, cve):
    max_retries = 5
    wait_time = 0.1  # seconds

    for attempt in range(max_retries):
        try:
            cursor = conn.cursor()
            cve_id = cve.get('id', '')
            identifier = cve.get('sourceIdentifier', '')
            published_date = cve.get('published', '')
            last_modified_date = cve.get('lastModified', '')
            status = cve.get('vulnStatus', '')

            description = ''
            desc_data = cve.get('descriptions', [])
            if desc_data:
                for desc in desc_data:
                    if desc.get('lang', '').lower() == 'en':
                        description = desc.get('value', '')
                        break

            cvss_v2_score = None
            cvss_v2_severity = None
            cvss_v2_vector = None
            exploitability_score = None
            impact_score = None

            cvss_v2_access_vector = None
            cvss_v2_access_complexity = None
            cvss_v2_authentication = None
            cvss_v2_confidentiality_impact = None
            cvss_v2_integrity_impact = None
            cvss_v2_availability_impact = None

            metrics = cve.get('metrics', {})
            cvss_v2_metrics = metrics.get('cvssMetricV2', [])
            if cvss_v2_metrics:
                metric = cvss_v2_metrics[0]
                base_data = metric.get('cvssData', {})
                cvss_v2_score = base_data.get('baseScore')
                cvss_v2_vector = base_data.get('vectorString')
                cvss_v2_severity = metric.get('baseSeverity')
                exploitability_score = metric.get('exploitabilityScore')
                impact_score = metric.get('impactScore')

                cvss_v2_access_vector = base_data.get('accessVector')
                cvss_v2_access_complexity = base_data.get('accessComplexity')
                cvss_v2_authentication = base_data.get('authentication')
                cvss_v2_confidentiality_impact = base_data.get('confidentialityImpact')
                cvss_v2_integrity_impact = base_data.get('integrityImpact')
                cvss_v2_availability_impact = base_data.get('availabilityImpact')

            cursor.execute('''
                INSERT INTO cves (
                    cve_id, identifier, published_date, last_modified_date, status,
                    description, cvss_v2_score, cvss_v2_severity, cvss_v2_vector,
                    exploitability_score, impact_score,
                    cvss_v2_access_vector, cvss_v2_access_complexity, cvss_v2_authentication,
                    cvss_v2_confidentiality_impact, cvss_v2_integrity_impact, cvss_v2_availability_impact
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    identifier=excluded.identifier,
                    published_date=excluded.published_date,
                    last_modified_date=excluded.last_modified_date,
                    status=excluded.status,
                    description=excluded.description,
                    cvss_v2_score=excluded.cvss_v2_score,
                    cvss_v2_severity=excluded.cvss_v2_severity,
                    cvss_v2_vector=excluded.cvss_v2_vector,
                    exploitability_score=excluded.exploitability_score,
                    impact_score=excluded.impact_score,
                    cvss_v2_access_vector=excluded.cvss_v2_access_vector,
                    cvss_v2_access_complexity=excluded.cvss_v2_access_complexity,
                    cvss_v2_authentication=excluded.cvss_v2_authentication,
                    cvss_v2_confidentiality_impact=excluded.cvss_v2_confidentiality_impact,
                    cvss_v2_integrity_impact=excluded.cvss_v2_integrity_impact,
                    cvss_v2_availability_impact=excluded.cvss_v2_availability_impact
            ''', (cve_id, identifier, published_date, last_modified_date, status,
                  description, cvss_v2_score, cvss_v2_severity, cvss_v2_vector,
                  exploitability_score, impact_score,
                  cvss_v2_access_vector, cvss_v2_access_complexity, cvss_v2_authentication,
                  cvss_v2_confidentiality_impact, cvss_v2_integrity_impact, cvss_v2_availability_impact))

            cursor.execute("DELETE FROM cpe_matches WHERE cve_id = ?", (cve_id,))
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cursor.execute('''
                            INSERT INTO cpe_matches
                            (cve_id, criteria, match_criteria_id, vulnerable)
                            VALUES (?, ?, ?, ?)
                        ''', (
                            cve_id,
                            cpe_match.get("criteria", ""),
                            cpe_match.get("matchCriteriaId", ""),
                            "Yes" if cpe_match.get("vulnerable", False) else "No"
                        ))
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e):
                print(f"DB locked during insert of {cve.get('id','')}, retry {attempt+1}/{max_retries}")
                time.sleep(wait_time)
                wait_time *= 2
            else:
                raise
    print(f"Failed to insert CVE {cve.get('id','')} after {max_retries} retries due to DB lock.")

def fetch_cve_page(start_index, page_size):
    params = {
        'startIndex': start_index,
        'resultsPerPage': page_size
    }

    retries = 5
    backoff = 10
    for attempt in range(retries):
        resp = requests.get(API_BASE_URL, params=params)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 429:
            print(f"Rate limited at startIndex {start_index}, backing off {backoff}s...")
            time.sleep(backoff)
            backoff *= 2
        else:
            print(f"Error {resp.status_code} at startIndex {start_index}, attempt {attempt+1}")
            time.sleep(backoff)
            backoff *= 2
    print(f"Failed to fetch page at startIndex {start_index} after {retries} retries.")
    return None

def process_page(start_index, page_size):
    data = fetch_cve_page(start_index, page_size)
    if not data:
        return 0
    vuln_items = data.get('vulnerabilities', [])
    conn = get_db_connection()
    inserted_count = 0
    for item in vuln_items:
        cve = item.get('cve', {})
        try:
            insert_or_update_cve(conn, cve)
            inserted_count += 1
        except Exception as e:
            print(f"DB insert error for CVE {cve.get('id', '')}: {e}")
    conn.close()
    return inserted_count

def main():
    create_tables()
    # Count how many CVEs are already in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cves;")
    current_count = cursor.fetchone()[0]
    conn.close()

    PAGE_SIZE = 200
    # Calculate offset to resume fetching
    start_offset = (current_count // PAGE_SIZE) * PAGE_SIZE

    first_response = fetch_cve_page(0, PAGE_SIZE)
    if not first_response:
        print("Failed to fetch initial data. Exiting.")
        return
    total_results = first_response.get('totalResults')
    if not total_results:
        print("Could not determine total results. Exiting.")
        return

    print(f"Currently have {current_count} CVEs. Resuming fetch from offset {start_offset} of {total_results} total CVEs.")

    all_start_indices = [i for i in range(start_offset, total_results, PAGE_SIZE)]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_page, start, PAGE_SIZE): start for start in all_start_indices}
        total_inserted = 0
        for future in as_completed(futures):
            start_idx = futures[future]
            try:
                inserted = future.result()
                total_inserted += inserted
                print(f"Inserted {inserted} CVEs from startIndex {start_idx}. Total inserted this run: {total_inserted}")
            except Exception as e:
                print(f"Exception fetching startIndex {start_idx}: {e}")

    print(f"Completed fetching all CVEs. Total inserted this run: {total_inserted}")
if __name__ == "__main__":
    main()
