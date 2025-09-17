from flask import Flask, render_template, request, redirect, url_for
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)

DATABASE = './database/nvd_cve.db'
RESULTS_PER_PAGE_OPTIONS = [10, 50, 100]

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def root_redirect():
    return redirect(url_for('list_cves'))

@app.route('/cves/list')
def list_cves():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('limit', 10))
    if per_page not in RESULTS_PER_PAGE_OPTIONS:
        per_page = 10
    offset = (page - 1) * per_page

    year = request.args.get('year')
    min_score = request.args.get('score')
    last_modified_days = request.args.get('last_modified_days')

    conn = get_db_connection()
    cursor = conn.cursor()
    base_query = "SELECT * FROM cves WHERE 1=1 "
    params = []

    if year:
        base_query += "AND substr(published_date,1,4) = ? "
        params.append(str(year))
    if min_score:
        base_query += "AND cvss_v2_score >= ? "
        params.append(float(min_score))
    if last_modified_days:
        cutoff_date = datetime.now() - timedelta(days=int(last_modified_days))
        base_query += "AND datetime(last_modified_date) >= datetime(?) "
        params.append(cutoff_date.strftime("%Y-%m-%dT%H:%M:%S"))

    count_query = "SELECT COUNT(*) FROM (" + base_query + ")"
    cursor.execute(count_query, tuple(params))
    total_records = cursor.fetchone()[0]

    base_query += "ORDER BY published_date DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    cursor.execute(base_query, tuple(params))

    cve_list = cursor.fetchall()
    conn.close()

    return render_template('list.html',
                       cves=cve_list,
                       total=total_records,
                       page=page,
                       per_page=per_page,
                       results_per_page_options=RESULTS_PER_PAGE_OPTIONS,
                       query_params=request.args)

@app.route('/cves/<cve_id>')
def cve_detail(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    cve = cursor.fetchone()
    cursor.execute("SELECT criteria, match_criteria_id, vulnerable FROM cpe_matches WHERE cve_id = ?", (cve_id,))
    cpe_rows = cursor.fetchall()
    conn.close()

    if not cve:
        return "CVE not found", 404

    return render_template('detail.html', cve=cve, cpe_rows=cpe_rows)

if __name__ == '__main__':
    app.run(debug=True)
