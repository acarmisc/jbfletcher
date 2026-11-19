"""Read-only CVE intelligence and Maven SBOM scanning."""
import argparse
import concurrent.futures
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def fetch(url, headers=None, xml=False):
    request = urllib.request.Request(url, headers={'User-Agent': 'JBFletcher/1.0', **(headers or {})})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return ET.parse(response).getroot() if xml else json.load(response)
        except urllib.error.HTTPError as exc:
            if attempt == 2 or exc.code not in (429, 500, 502, 503, 504):
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(6 * (attempt + 1))


def nvd(days):
    end = dt.datetime.now(dt.timezone.utc)
    params = {
        'lastModStartDate': (end - dt.timedelta(days=days)).isoformat(timespec='seconds'),
        'lastModEndDate': end.isoformat(timespec='seconds'),
        'resultsPerPage': 2000, 'startIndex': 0,
    }
    token = os.getenv('NVD_API_KEY')
    while True:
        page = fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?' + urllib.parse.urlencode(params),
                     {'apiKey': token} if token else None)
        rows = page['vulnerabilities']
        for row in rows:
            cve = row['cve']
            if cve['vulnStatus'] != 'Rejected':
                yield {key: cve[key] for key in ('id', 'published', 'lastModified', 'vulnStatus', 'descriptions', 'references', 'metrics') if key in cve}
        params['startIndex'] += len(rows)
        if params['startIndex'] >= page['totalResults']:
            break
        if not rows:
            raise ValueError('NVD returned an incomplete page')
        time.sleep(6 if not token else 1)


def kev():
    return fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')['vulnerabilities']


def news(days):
    from email.utils import parsedate_to_datetime
    root = fetch('https://cert.europa.eu/publications/security-advisories-rss', xml=True)
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    if root.find('channel') is None:
        raise ValueError('Unexpected CERT-EU RSS format')
    items = []
    for item in root.findall('./channel/item'):
        date = parsedate_to_datetime(item.findtext('pubDate'))
        if date.tzinfo is None:
            date = date.replace(tzinfo=dt.timezone.utc)
        if date >= cutoff:
            items.append({key: item.findtext(key) for key in ('title', 'link', 'pubDate')})
    return items


def digest(days):
    result = {'days': days, 'errors': {}}
    sources = {'nvd': lambda: list(nvd(days)), 'kev': kev, 'cert_eu': lambda: news(days)}
    with concurrent.futures.ThreadPoolExecutor() as pool:
        jobs = {name: pool.submit(source) for name, source in sources.items()}
        for name, job in jobs.items():
            try:
                result[name] = job.result()
            except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as exc:
                result['errors'][name] = type(exc).__name__
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).date().isoformat()
    ids = {row['id'] for row in result.get('nvd', [])}
    if 'kev' in result:
        result['kev'] = [row for row in result['kev'] if row['cveID'] in ids or row['dateAdded'] >= cutoff]
    return result


def scan(sbom, scanner):
    inventory = json.loads(sbom.read_text())
    components = inventory.get('components', [])
    if inventory.get('bomFormat') != 'CycloneDX' or not any(c.get('purl', '').startswith('pkg:maven/') for c in components):
        raise ValueError('Expected a CycloneDX SBOM with resolved Maven components')
    run = subprocess.run([scanner, 'scan', 'source', '--offline', '--download-offline-databases',
                          '--format=json', '--all-packages', '-L', str(sbom.resolve())],
                         capture_output=True, text=True, timeout=900)
    if run.returncode not in (0, 1):
        raise ValueError(f'OSV-Scanner failed ({run.returncode}): {run.stderr.strip()}')
    data = json.loads(run.stdout)
    packages = [package for row in data['results'] for package in row.get('packages', [])]
    if not packages:
        raise ValueError('OSV-Scanner did not report any scanned packages')
    findings = sum(len(package.get('vulnerabilities', [])) for package in packages)
    if bool(findings) != bool(run.returncode):
        raise ValueError('OSV-Scanner exit status disagrees with the report')
    return {'packages': len(packages), 'findings': findings, 'osv': data}


def summarize(result, model):
    from strands import Agent
    # Pass only counts and public identifiers, never repository or feed prose.
    ids = {item['id'] for item in result.get('nvd', [])}
    for row in result.get('osv', {}).get('results', []):
        for package in row.get('packages', []):
            for advisory in package.get('vulnerabilities', []):
                ids.update(advisory.get('aliases', []))
                ids.add(advisory['id'])
    import re
    evidence = {'cves': sorted(i for i in ids if re.fullmatch(r'CVE-\d{4}-\d{4,}', i))[:100],
                'counts': {key: result[key] for key in ('packages', 'findings') if key in result}}
    agent = Agent(model=model, tools=[], system_prompt='Summarize only the JSON supplied. Do not infer exploitability or propose versions.')
    return str(agent(json.dumps(evidence)))


def markdown_report(result, known_exploited):
    import html
    import re

    def cell(value):
        return re.sub(r'([\\`*_\[\]|])', r'\\\1', html.escape(' '.join(value.split())))

    rows = {}
    for source in result['osv']['results']:
        for item in source.get('packages', []):
            package = item['package']
            for advisory in item.get('vulnerabilities', []):
                identifiers = [advisory['id'], *advisory.get('aliases', [])]
                cves = {value for value in identifiers if re.fullmatch(r'CVE-\d{4}-\d{4,}', value)}
                fixes = {event['fixed'] for affected in advisory.get('affected', [])
                         if affected.get('package', {}).get('name') == package['name']
                         and affected['package'].get('ecosystem') == package.get('ecosystem')
                         for interval in affected.get('ranges', []) for event in interval.get('events', [])
                         if 'fixed' in event}
                for identifier in cves or {advisory['id']}:
                    rows.setdefault((package['name'], package['version'], identifier), set()).update(fixes)
    lines = ['# Fletcher — scansione Maven', '', f"Pacchetti analizzati: **{result['packages']}**. "
             f"Occorrenze scanner: **{result['findings']}**. Righe deduplicate: **{len(rows)}**.", '',
             '| Pacchetto | Versione | Advisory | CISA KEV | Fix dichiarati¹ |', '|---|---|---|---|---|']
    candidates = set()
    for (name, version, advisory), fixes in sorted(rows.items(), key=lambda row: (row[0][2] not in (known_exploited or ()), row[0])):
        status = 'Sì' if advisory in (known_exploited or ()) else 'N/D' if known_exploited is None or not advisory.startswith('CVE-') else 'No'
        fields = name, version, advisory, status, ', '.join(sorted(fixes)) or '—'
        lines.append('| ' + ' | '.join(map(cell, fields)) + ' |')
        if status == 'Sì':
            candidates.add((name, advisory))
    lines += ['', '¹ Versioni dichiarate negli intervalli OSV: non sono raccomandazioni né fix verificati.', '',
              '## Issue GitLab — simulazione', '', 'Nessuna scrittura. Candidati KEV preliminari; non è ancora verificata la presenza di una MR.']
    lines += [f'- {cell(name)} — {advisory}' for name, advisory in sorted(candidates)]
    if not candidates:
        lines.append('- KEV non disponibile: simulazione sospesa.' if known_exploited is None else '- Nessun candidato KEV.')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--bedrock-model', default=os.getenv('FLETCHER_BEDROCK_MODEL'))
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('digest').add_argument('--days', type=int, default=7, choices=range(1, 121), metavar='1..120')
    scanner = commands.add_parser('scan')
    scanner.add_argument('sbom', type=Path)
    scanner.add_argument('--scanner', default='osv-scanner')
    scanner.add_argument('--summary', type=Path)
    args = parser.parse_args()
    try:
        result = digest(args.days) if args.command == 'digest' else scan(args.sbom, args.scanner)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        parser.exit(2, f'fletcher: {exc}\n')
    result['generated_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
    if args.command == 'scan' and args.summary:
        try:
            known_exploited = {row['cveID'] for row in kev()}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f'KEV unavailable; issue simulation suspended: {type(exc).__name__}', file=sys.stderr)
            known_exploited = None
        args.summary.write_text(markdown_report(result, known_exploited), encoding='utf-8')
    if args.bedrock_model and not result.get('errors'):
        try:
            from strands.models import BedrockModel
            result['model_summary_unverified'] = summarize(result, BedrockModel(model_id=args.bedrock_model))
        except Exception as exc:
            print(f'Optional Strands summary unavailable: {type(exc).__name__}', file=sys.stderr)
    output = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(output)
    else:
        print(output, end='')
    return 2 if result.get('errors') else 0


if __name__ == '__main__':
    raise SystemExit(main())
