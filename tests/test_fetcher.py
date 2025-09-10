import unittest
from unittest.mock import patch, MagicMock
import sqlite3
import queue
import threading
import fetch_all_cves_parallel  # your fetcher python file without .py

class TestFetcher(unittest.TestCase):

    def setUp(self):
        # Setup in-memory DB for tests
        self.conn = sqlite3.connect(':memory:')
        # Override get_db_connection to return this connection
        fetch_all_cves_parallel.get_db_connection = lambda: self.conn
        fetch_all_cves_parallel.create_tables()

    def tearDown(self):
        self.conn.close()

    def test_create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        self.assertIn('cves', tables)
        self.assertIn('cpe_matches', tables)

    @patch('fetch_all_cves_parallel.requests.get')
    def test_fetch_cve_page_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'totalResults': 10, 'vulnerabilities': []}
        mock_get.return_value = mock_response

        data = fetch_all_cves_parallel.fetch_cve_page(0, 20)
        self.assertIn('totalResults', data)
        self.assertIsInstance(data['vulnerabilities'], list)

    @patch('fetch_all_cves_parallel.requests.get')
    def test_fetch_cve_page_rate_limit(self, mock_get):
        # First call 429, second call 200
        mock_response_429 = MagicMock(status_code=429)
        mock_response_200 = MagicMock(status_code=200)
        mock_response_200.json.return_value = {'totalResults': 0, 'vulnerabilities': []}
        mock_get.side_effect = [mock_response_429, mock_response_200]

        data = fetch_all_cves_parallel.fetch_cve_page(0, 10)
        self.assertIn('totalResults', data)

    def test_parse_cve_to_tuple_basic(self):
        sample_cve = {
            'id': 'CVE-1234-5678',
            'sourceIdentifier': 'test@source',
            'published': '2025-01-01T00:00:00',
            'lastModified': '2025-01-02T00:00:00',
            'vulnStatus': 'Analyzed',
            'descriptions': [{'lang': 'en', 'value': 'Sample description'}],
            'metrics': {
                'cvssMetricV2': [{
                    'baseSeverity': 'HIGH',
                    'exploitabilityScore': 5.0,
                    'impactScore': 7.5,
                    'cvssData': {
                        'baseScore': 7.5,
                        'vectorString': 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
                        'accessVector': 'NETWORK',
                        'accessComplexity': 'LOW',
                        'authentication': 'NONE',
                        'confidentialityImpact': 'COMPLETE',
                        'integrityImpact': 'COMPLETE',
                        'availabilityImpact': 'COMPLETE'
                    }
                }]
            },
            'configurations': [{
                'nodes': [{
                    'cpeMatch': [{
                        'criteria': 'cpe:2.3:a:example',
                        'matchCriteriaId': 'abc-123',
                        'vulnerable': True
                    }]
                }]
            }]
        }
        cve_tuple, cpe_tuples = fetch_all_cves_parallel.parse_cve_to_tuple(sample_cve)
        self.assertEqual(cve_tuple[0], 'CVE-1234-5678')
        self.assertEqual(cve_tuple[6], 7.5)  # cvss_v2_score
        self.assertEqual(len(cpe_tuples), 1)
        self.assertEqual(cpe_tuples[0][0], 'CVE-1234-5678')
        self.assertEqual(cpe_tuples[0][3], 'Yes')

    def test_insert_or_update_cve_and_cpe(self):
        # Prepare sample data same as previous test
        sample_cve = {
            'id': 'CVE-0001',
            'sourceIdentifier': 'test',
            'published': '2025-01-01T00:00:00',
            'lastModified': '2025-01-01T00:00:00',
            'vulnStatus': 'Analyzed',
            'descriptions': [{'lang': 'en', 'value': 'Desc'}],
            'metrics': {},
            'configurations': [{
                'nodes': [{
                    'cpeMatch': [{
                        'criteria': 'criteria-1',
                        'matchCriteriaId': 'id-1',
                        'vulnerable': True
                    }]
                }]
            }]
        }
        fetch_all_cves_parallel.insert_or_update_cve(self.conn, sample_cve)

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cves WHERE cve_id='CVE-0001'")
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'CVE-0001')
        self.assertEqual(row[5], 'Desc')  # description column

        cursor.execute("SELECT * FROM cpe_matches WHERE cve_id='CVE-0001'")
        cpe_row = cursor.fetchone()
        self.assertIsNotNone(cpe_row)
        self.assertEqual(cpe_row[1], 'criteria-1')

    def test_process_page_queues_data(self):
        test_queue = queue.Queue()
        sample_response = {
            'vulnerabilities': [
                {'cve': {
                    'id': 'CVE-9999',
                    'sourceIdentifier': 'test',
                    'published': '2025-01-01T00:00:00',
                    'lastModified': '2025-01-01T00:00:00',
                    'vulnStatus': 'Analyzed',
                    'descriptions': [{'lang': 'en', 'value': 'Desc'}],
                    'metrics': {},
                    'configurations': []
                }}
            ]
        }
        with patch('fetch_all_cves_parallel.fetch_cve_page', return_value=sample_response):
            inserted = fetch_all_cves_parallel.process_page(0, 200, test_queue)
            self.assertEqual(inserted, 1)
            self.assertFalse(test_queue.empty())

if __name__ == '__main__':
    unittest.main()
