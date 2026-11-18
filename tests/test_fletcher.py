import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

import fletcher


class FletcherTest(unittest.TestCase):
    @patch('fletcher.time.sleep')
    @patch('fletcher.fetch')
    def test_nvd_pages_and_ignores_rejected(self, fetch, sleep):
        fetch.side_effect = [
            {'totalResults': 2, 'vulnerabilities': [{'cve': {'id': 'CVE-2020-1234', 'vulnStatus': 'Analyzed'}}]},
            {'totalResults': 2, 'vulnerabilities': [{'cve': {'id': 'CVE-2020-1235', 'vulnStatus': 'Rejected'}}]},
        ]
        self.assertEqual([row['id'] for row in fletcher.nvd(7)], ['CVE-2020-1234'])
        self.assertIn('startIndex=1', fetch.call_args.args[0])
        sleep.assert_called_once()

    @patch('fletcher.subprocess.run')
    def test_scanner_findings_are_not_errors_but_missing_results_are(self, run):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'bom.json'
            path.write_text(json.dumps({'bomFormat': 'CycloneDX', 'components': [{'purl': 'pkg:maven/example/test@1.0'}]}))
            run.return_value = CompletedProcess([], 1, '{"results":[{"packages":[{"vulnerabilities":[{"id":"test"}]}]}]}', '')
            self.assertEqual(fletcher.scan(path, 'osv-scanner')['findings'], 1)
            self.assertIn('--offline', run.call_args.args[0])
            run.return_value = CompletedProcess([], 0, '{"results":[]}', '')
            with self.assertRaisesRegex(ValueError, 'did not report'):
                fletcher.scan(path, 'osv-scanner')

    @patch('fletcher.news', side_effect=OSError)
    @patch('fletcher.kev', return_value=[])
    @patch('fletcher.nvd', return_value=iter([]))
    def test_digest_retains_results_from_healthy_sources(self, *_):
        result = fletcher.digest(1)
        self.assertEqual(result['nvd'], [])
        self.assertEqual(result['errors'], {'cert_eu': 'OSError'})


if __name__ == '__main__':
    unittest.main()
