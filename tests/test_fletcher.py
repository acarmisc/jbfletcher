import json
from pathlib import Path
import os
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

import fletcher


class FletcherTest(unittest.TestCase):
    @staticmethod
    def sample_scan(version='1'):
        package = {'package': {'name': 'example:lib', 'version': version, 'ecosystem': 'Maven'},
                   'vulnerabilities': [{'id': 'GHSA-example', 'aliases': ['CVE-2020-1234']}]}
        return {'packages': 1, 'osv': {'results': [{'packages': [package]}]}}

    def test_triage_requires_matching_runtime_and_kev_for_urgent(self):
        scan = self.sample_scan()
        kev = [{'cveID': 'CVE-2020-1234'}]
        confirmed = fletcher.triage(scan, kev, scan, 'release@digest')['findings'][0]
        unverified = fletcher.triage(scan, kev, self.sample_scan('2'), 'release@digest')['findings'][0]
        self.assertEqual(confirmed['priority'], 'urgent-review')
        self.assertEqual((unverified['priority'], unverified['runtime']), ('priority-review', 'unverified'))
        self.assertEqual(fletcher.triage(self.sample_scan('2'), [])['findings'][0]['key'], confirmed['key'])

    @patch.dict(os.environ, {'CI_PROJECT_ID': '42', 'CI_PIPELINE_ID': '3', 'CI_COMMIT_SHA': 'abcdef',
                             'CI_SERVER_URL': 'https://git.example', 'CI_API_V4_URL': 'https://git.example/api/v4'})
    @patch('fletcher.urllib.request.build_opener')
    def test_issue_is_confidential_and_reuses_existing(self, opener):
        report = fletcher.triage(self.sample_scan(), [])
        key = report['findings'][0]['key']
        existing = {'iid': 7, 'web_url': 'https://git.example/issues/7', 'confidential': True,
                    'description': f'<!-- FLETCHER-TRIAGE-{key} -->'}
        response = opener.return_value.open.return_value.__enter__.return_value
        response.headers = {}
        response.read.side_effect = [b'[]', json.dumps(existing), json.dumps([existing])]
        self.assertEqual(fletcher.gitlab_issue(report, key, 'test')['status'], 'created')
        self.assertTrue(json.loads(opener.return_value.open.call_args.args[0].data)['confidential'])
        self.assertEqual(fletcher.gitlab_issue(report, key, 'test')['status'], 'existing')
        self.assertEqual(opener.return_value.open.call_count, 3)
        report['context']['CI_PIPELINE_ID'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'does not belong'):
            fletcher.gitlab_issue(report, key, 'test')

    def test_markdown_deduplicates_by_package_version_and_cve(self):
        advisory = {'id': 'GHSA-example', 'aliases': ['CVE-2020-1234']}
        package = {'package': {'name': 'example:lib', 'version': '1', 'ecosystem': 'Maven'},
                   'vulnerabilities': [advisory, {**advisory, 'id': 'OSV-example'}]}
        result = {'packages': 1, 'findings': 2, 'osv': {'results': [{'packages': [package]}]}}
        report = fletcher.markdown_report(result, {'CVE-2020-1234'})
        self.assertEqual(report.count('| example:lib |'), 1)
        self.assertIn('- example:lib — CVE-2020-1234', report)
        self.assertIn('simulazione sospesa', fletcher.markdown_report(result, None))

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
