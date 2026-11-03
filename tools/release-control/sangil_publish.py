"""Prepared publisher for the existing Sangil update repository.

Reuses an approved signed APK. Never builds, runs or installs app code. No live
workflow or repository setting is changed by this file. Failures after a draft
claim require manual reconciliation, never a rerun or overwrite.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path

REPO = 'gy7604/HikingAndroid-Updates'
PREFIX = 'repos/' + REPO
TITLE = 'SANGIL-PUBLICATION-CONTROL-v1'
PACKAGE = 'com.gy7604.hiking.dev'
CERT = '9b76be478ce899ab17caba5282606b08d7f6feba074a94e9790017db2b77a69d'
MAX = 512 * 1024 * 1024


def file_url(url):
    u = urllib.parse.urlsplit(url)
    if (len(url) > 12000 or u.scheme != 'https' or not u.hostname
            or not u.hostname.endswith('.oaiusercontent.com') or u.username or u.password
            or u.port not in (None, 443) or u.fragment or not u.path.startswith('/files/')
            or re.search(r'[\s\x00-\x1f]', url)):
        raise ValueError('Approved file reference required')
    return url


def validate_event(event, now, issue_number):
    i, c = event.get('issue', {}), event.get('comment', {})
    if (type(issue_number) is not int or issue_number < 1 or event.get('action') != 'created'
            or event.get('repository', {}).get('full_name') != REPO
            or event.get('sender', {}).get('login') != 'gy7604'
            or i.get('number') != issue_number or i.get('title') != TITLE
            or i.get('user', {}).get('login') != 'gy7604' or 'pull_request' in i
            or c.get('user', {}).get('login') != 'gy7604'
            or type(c.get('id')) is not int or c['id'] < 1
            or c.get('created_at') != c.get('updated_at')):
        raise ValueError('Dedicated original owner approval required')
    stamp = int(datetime.fromisoformat(c['created_at'].replace('Z', '+00:00')).timestamp())
    if not 0 <= now - stamp <= 900:
        raise ValueError('Approval expired or in the future')
    m = re.fullmatch(r'/sangil-publish approve ([A-Za-z0-9_-]{1,100}) ([a-f0-9]{40}) ([1-9][0-9]{0,8}) ([a-f0-9]{64}) ([a-f0-9]{40}) ([a-f0-9]{64}) (https://[^\s]+)\n\n([^\x00-\x08\x0b\x0c\x0e-\x1f]{1,3000})', c.get('body', ''))
    if not m:
        raise ValueError('Exact candidate, baseline and release notes approval required')
    file_url(m[7])
    return dict(requestId=m[1], snapshotSha=m[2], versionCode=int(m[3]), apkSha256=m[4],
                baselineBlobSha=m[5], outerSha256=m[6], url=m[7], notes=m[8], commentId=c['id'])


def verify_native_apk(path, sdk):
    if not sdk or not Path(sdk).is_absolute():
        raise ValueError('Explicit trusted Android SDK path required')
    tools = Path(sdk).resolve() / 'build-tools/35.0.0'
    signer = tools / ('apksigner.bat' if os.name == 'nt' else 'apksigner')
    aapt = tools / ('aapt.exe' if os.name == 'nt' else 'aapt')
    if not signer.is_file() or not aapt.is_file():
        raise ValueError('Trusted pinned Android build tools 35.0.0 required')
    def run(args):
        p = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=120)
        if p.returncode:
            raise ValueError('APK verification failed; no app code was executed')
        return p.stdout
    output = run([signer, 'verify', '--verbose', '--print-certs', '--print-certs-pem', path])
    pems = re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----', output)
    if len(pems) != 1 or re.findall(r'^Number of signers: (\d+)\s*$', output, re.M) != ['1']:
        raise ValueError('Exactly one verified original signer required')
    cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pems[0])).hexdigest()
    metadata = run([aapt, 'dump', 'badging', path])
    m = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", metadata, re.M)
    if not m:
        raise ValueError('Verified APK metadata missing')
    abis = re.findall(r"'([^']+)'", next((line for line in metadata.splitlines() if line.startswith('native-code:')), ''))
    if abis != ['arm64-v8a']:
        raise ValueError('Only the existing ARM64 update channel is supported')
    return dict(package=m[1], versionCode=int(m[2]), versionName=m[3], certificateSha256=cert)


def inspect_bundle(path, request, destination, apk_verifier):
    source, out = Path(path), Path(destination)
    if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size <= MAX:
        raise ValueError('Bounded approved bundle required')
    if hashlib.sha256(source.read_bytes()).hexdigest() != request['outerSha256']:
        raise ValueError('Approved bundle digest mismatch')
    with zipfile.ZipFile(source) as z:
        entries = z.infolist()
        if (len(entries) != 2 or {e.filename for e in entries} != {'candidate.apk', 'receipt.json'}
                or sum(e.file_size for e in entries) > MAX
                or any(stat.S_ISLNK(e.external_attr >> 16) or e.flag_bits & 1 or e.is_dir() for e in entries)
                or z.getinfo('receipt.json').file_size > 30000):
            raise ValueError('Only a candidate APK and non-secret receipt are permitted')
        receipt = json.loads(z.read('receipt.json'))
        expected = dict(schema=1, appId='sangil', requestId=request['requestId'],
                        snapshotSha=request['snapshotSha'], mode='build', compiled=True,
                        checksPassed=True, signed=True, apkBuilt=True, installed=False,
                        publication='NOT_APPROVED', package=PACKAGE, versionCode=request['versionCode'],
                        certificateSha256=CERT, signer='ORIGINAL_OWNER_ENROLLED_KEY')
        if any(type(receipt.get(k)) is not type(v) or receipt.get(k) != v for k, v in expected.items()):
            raise ValueError('Candidate receipt identity or verification mismatch')
        if not re.fullmatch(r'\d+\.\d+\.\d+-dev', receipt.get('versionName', '')):
            raise ValueError('Existing development update channel version required')
        assets = receipt.get('artifacts')
        if not isinstance(assets, list) or len(assets) != 1 or assets[0].get('name') != 'candidate.apk':
            raise ValueError('Exactly one verified APK asset required')
        asset = assets[0]
        if (asset.get('sha256') != request['apkSha256'] or type(asset.get('bytes')) is not int
                or asset['bytes'] != z.getinfo('candidate.apk').file_size or not 0 < asset['bytes'] <= MAX):
            raise ValueError('Candidate asset receipt mismatch')
        target = out / 'candidate.apk'
        if not out.is_dir() or target.exists() or target.is_symlink():
            raise ValueError('New isolated candidate destination required')
        with z.open('candidate.apk') as src, target.open('xb') as dest:
            shutil.copyfileobj(src, dest)
    if hashlib.sha256(target.read_bytes()).hexdigest() != request['apkSha256']:
        raise ValueError('APK byte digest mismatch')
    actual = apk_verifier(target)
    if any(actual.get(k) != receipt[k] for k in ('package', 'versionCode', 'versionName', 'certificateSha256')):
        raise ValueError('APK bytes disagree with the approved receipt')
    return {k: receipt[k] for k in ('requestId', 'snapshotSha', 'package', 'versionCode', 'versionName', 'certificateSha256')} | dict(sha256=asset['sha256'], sizeBytes=asset['bytes'])


def manifest(candidate, request, baseline):
    if (baseline.get('packageName') != PACKAGE or baseline.get('signingCertSha256') != CERT
            or type(baseline.get('versionCode')) is not int
            or baseline['versionCode'] >= candidate['versionCode']):
        raise ValueError('Existing feed changed, wrong signer or duplicate/downgrade')
    tag = 'v' + candidate['versionName']
    name = 'HikingAndroid-' + candidate['versionName'] + '.apk'
    return dict(packageName=PACKAGE, versionCode=candidate['versionCode'], versionName=candidate['versionName'],
                apkUrl=f'https://github.com/{REPO}/releases/download/{tag}/{name}', sha256=candidate['sha256'],
                sizeBytes=candidate['sizeBytes'], signingCertSha256=CERT, notes=request['notes'])


def verify_public_baseline(feed, release):
    version = feed.get('versionName', '')
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+-dev', version):
        raise ValueError('Existing public feed version required')
    expected_url = f'https://github.com/{REPO}/releases/download/v{version}/HikingAndroid-{version}.apk'
    assets = release.get('assets', [])
    if (release.get('draft') is not False or release.get('prerelease') is not False
            or release.get('tag_name') != 'v' + version or feed.get('apkUrl') != expected_url
            or len(assets) != 1 or assets[0].get('browser_download_url') != expected_url
            or assets[0].get('size') != feed.get('sizeBytes')
            or assets[0].get('digest') != 'sha256:' + str(feed.get('sha256'))):
        raise ValueError('Current public release and feed disagree; review before publication')


def gh(args, body=None):
    p = subprocess.run(['gh', *args], input=json.dumps(body) if body is not None else None,
                       capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120,
                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if p.returncode:
        raise RuntimeError('Publication step stopped; inspect the exact draft/feed before any retry')
    return p.stdout


def api(path, method='GET', body=None):
    reads = (path in (PREFIX, PREFIX + '/contents/latest.json?ref=main', PREFIX + '/git/ref/heads/main', PREFIX + '/releases/latest')
             or re.fullmatch(re.escape(PREFIX) + r'/issues/comments/[1-9][0-9]*', path)
             or re.fullmatch(re.escape(PREFIX) + r'/releases/[1-9][0-9]*', path)
             or re.fullmatch(re.escape(PREFIX) + r'/releases\?per_page=100&page=[1-5]', path)
             or re.fullmatch(re.escape(PREFIX) + r'/git/matching-refs/tags/v[0-9.]+-dev', path))
    writes = ((method == 'POST' and path == PREFIX + '/releases')
              or (method == 'PATCH' and re.fullmatch(re.escape(PREFIX) + r'/releases/[1-9][0-9]*', path))
              or (method == 'PUT' and path == PREFIX + '/contents/latest.json'))
    if not (method == 'GET' and reads or writes):
        raise ValueError('Endpoint outside the existing update repository and feed')
    return json.loads(gh(['api', '--method', method, path, *(['--input', '-'] if body is not None else [])], body))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def publish(event, request, issue_number, root, verify_apk, read=api, run_gh=gh, clock=time.time):
    """Only called by the disabled-until-approved native workflow entry point."""
    def guard(*, verify_baseline=True):
        fresh = validate_event(event, int(clock()), issue_number)
        if fresh != request:
            raise ValueError('Approval identity changed')
        repo = read(PREFIX)
        if repo.get('full_name') != REPO or repo.get('private') is not False or repo.get('archived') is not False or repo.get('default_branch') != 'main':
            raise ValueError('Existing public update-only repository required')
        c = read(PREFIX + '/issues/comments/' + str(request['commentId']))
        if (c.get('body') != event['comment']['body'] or c.get('user', {}).get('login') != 'gy7604'
                or c.get('created_at') != event['comment']['created_at'] or c.get('updated_at') != c.get('created_at')
                or c.get('issue_url') != f'https://api.github.com/repos/{REPO}/issues/{issue_number}'):
            raise ValueError('Native owner approval edited or revoked')
        feed = read(PREFIX + '/contents/latest.json?ref=main')
        if feed.get('sha') != request['baselineBlobSha'] or feed.get('encoding') != 'base64' or feed.get('size', MAX) > 30000:
            raise ValueError('Exact previously approved feed baseline required')
        baseline = json.loads(base64.b64decode(feed['content'], validate=False))
        if verify_baseline:
            verify_public_baseline(baseline, read(PREFIX + '/releases/latest'))
        return baseline
    baseline = guard()
    candidate = inspect_bundle(root / 'approved.zip', request, root, verify_apk)
    feed = manifest(candidate, request, baseline)
    tag, name = 'v' + candidate['versionName'], 'HikingAndroid-' + candidate['versionName'] + '.apk'
    if any(r.get('ref') == 'refs/tags/' + tag for r in read(PREFIX + '/git/matching-refs/tags/' + tag)):
        raise ValueError('Version already claimed; inspect without retry')
    for page in range(1, 6):
        rows = read(PREFIX + f'/releases?per_page=100&page={page}')
        if any(r.get('tag_name') == tag for r in rows):
            raise ValueError('Existing draft/release; inspect without overwriting')
        if len(rows) < 100:
            break
    else:
        raise ValueError('Release retention review required')
    guard()
    head = read(PREFIX + '/git/ref/heads/main')['object']['sha']
    # The source is private; the public tag points at this update repository's
    # own reviewed baseline, never at an unrelated or private source commit.
    release = read(PREFIX + '/releases', 'POST', dict(tag_name=tag, target_commitish=head, name=tag,
                   draft=True, prerelease=False, body=request['notes'] + '\n\nSHA256: ' + candidate['sha256']))
    rid = release['id']
    asset = root / name
    (root / 'candidate.apk').rename(asset)
    run_gh(['release', 'upload', tag, str(asset), '--repo', REPO])
    draft = read(PREFIX + '/releases/' + str(rid))
    assets = draft.get('assets', [])
    if (draft.get('draft') is not True or draft.get('tag_name') != tag or len(assets) != 1
            or assets[0].get('name') != name or assets[0].get('size') != candidate['sizeBytes']
            or assets[0].get('digest') != 'sha256:' + candidate['sha256']):
        raise ValueError('Draft APK server digest mismatch; manual review required')
    guard()
    read(PREFIX + '/releases/' + str(rid), 'PATCH', dict(draft=False, make_latest='true'))
    public = read(PREFIX + '/releases/' + str(rid))
    public_assets = public.get('assets', [])
    if (public.get('draft') is not False or public.get('tag_name') != tag or len(public_assets) != 1
            or any(public_assets[0].get(k) != assets[0].get(k) for k in ('id', 'name', 'size', 'digest'))
            or public_assets[0].get('browser_download_url') != feed['apkUrl']):
        raise ValueError('Public release outcome needs review; never repeat automatically')
    guard(verify_baseline=False)
    if read(PREFIX + '/releases/latest').get('id') != rid:
        raise ValueError('Another release became latest; reconcile without overwriting the feed')
    data = json.dumps(feed, ensure_ascii=False, indent=2) + '\n'
    read(PREFIX + '/contents/latest.json', 'PUT', dict(message='Publish approved Sangil update [skip ci]',
         branch='main', sha=request['baselineBlobSha'], content=base64.b64encode(data.encode()).decode()))
    result = read(PREFIX + '/contents/latest.json?ref=main')
    if json.loads(base64.b64decode(result['content'])) != feed:
        raise RuntimeError('Feed publication outcome needs review; do not retry')
    return dict(requestId=request['requestId'], releaseId=rid, versionCode=candidate['versionCode'],
                sha256=candidate['sha256'], published=True, installed=False, rebuilt=False)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--event', required=True)
    a = p.parse_args()
    if (os.environ.get('GITHUB_REPOSITORY') != REPO or os.environ.get('GITHUB_ACTOR') != 'gy7604'
            or os.environ.get('GITHUB_EVENT_NAME') != 'issue_comment' or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'
            or os.environ.get('SANGIL_PUBLICATION_ENABLED') != 'true'):
        raise ValueError('Separately enabled native first owner approval required')
    number = int(os.environ.get('SANGIL_PUBLICATION_ISSUE', '0'))
    event = json.loads(Path(a.event).read_text(encoding='utf-8'))
    request = validate_event(event, int(time.time()), number)
    with tempfile.TemporaryDirectory(prefix='approved-sangil-publication-') as folder:
        root = Path(folder)
        with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(file_url(request['url']),
             headers={'User-Agent': 'OwnerApprovedSangilPublisher/1'}), timeout=60) as response, (root / 'approved.zip').open('xb') as out:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > MAX:
                    raise ValueError('Bounded approved download required')
                out.write(chunk)
        print(json.dumps(publish(event, request, number, root,
              lambda path: verify_native_apk(path, os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT', '')))))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        import sys
        sys.stderr.write('Approved Sangil publication stopped. Inspect the exact request/draft/feed; no automatic retry.\n')
        sys.exit(1)
