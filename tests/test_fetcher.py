import unittest
from unittest.mock import patch, MagicMock
import sqlite3
import fetch_all_cves_parallel as fetcher

class TestFetcher(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        patcher = patch('fetch_all_cves_parallel.get_db_connection', return_value=self.conn)
        patcher.start()
        self.addCleanup(patcher.stop)
        fetcher.create_tables()

    def tearDown(self):
        self.conn.close()

    def test_tables_and_insert(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cursor.fetchall()}
        self.assertTrue({'cves', 'cpe_matches'}.issubset(tables))

        dummy_cve = {
            'id': 'CVE-123',
            'sourceIdentifier': 'src',
            'published': '2023-01-01T10:00:00',
            'lastModified': '2023-01-02T11:00:00',
            'vulnStatus': 'Active',
            'descriptions': [{'lang': 'en', 'value': 'desc'}],
            'metrics': {'cvssMetricV2': [{
                'cvssData': {
                    'baseScore': 5,
                    'vectorString': 'AV:N/AC:L/Au:N/C:N/I:N/A:C',
                    'accessVector': 'NETWORK',
                    'accessComplexity': 'LOW',
                    'authentication': 'NONE',
                    'confidentialityImpact': 'NONE',
                    'integrityImpact': 'NONE',
                    'availabilityImpact': 'PARTIAL',
                },
                'baseSeverity': 'MEDIUM', 'exploitabilityScore': 2, 'impactScore': 4
            }]},
            'configurations': [{
                'nodes': [{'cpeMatch': [{
                    'criteria': 'cpe:/a:test:test:1',
                    'matchCriteriaId': 'mcid',
                    'vulnerable': True
                }]}]
            }]
        }
        fetcher.insert_or_update_cve(self.conn, dummy_cve)
        cursor.execute("SELECT cve_id, description, cvss_v2_score FROM cves WHERE cve_id='CVE-123'")
        cve = cursor.fetchone()
        self.assertEqual(cve['description'], 'desc')
        self.assertEqual(cve['cvss_v2_score'], 5)
        cursor.execute("SELECT * FROM cpe_matches WHERE cve_id='CVE-123'")
        self.assertEqual(len(cursor.fetchall()), 1)

    @patch('fetch_all_cves_parallel.requests.get')
    def test_fetch_cve_page_handling(self, mock_get):
        # Success scenario & rate limiting in one test
        responses = [
            MagicMock(status_code=429),
            MagicMock(status_code=200, json=lambda: {'vulnerabilities': [], 'totalResults': 0})
        ]
        mock_get.side_effect = responses
        result = fetcher.fetch_cve_page(0, 1)
        self.assertIn('vulnerabilities', result)

    @patch('fetch_all_cves_parallel.fetch_cve_page')
    def test_process_page(self, mock_fetch):
        mock_fetch.return_value = {'vulnerabilities': [{'cve': {'id': 'CVE-999'}}]}
        count = fetcher.process_page(0, 1)
        self.assertEqual(count, 1)

if __name__ == '__main__':
    unittest.main()
