"""Watch-only approved publisher. Reuses signed bytes; never builds or installs.
Separate from the phone feed. Disabled until a separate owner setting approval.
Any partial release needs manual reconciliation; no overwrite, delete or rerun.
"""
import argparse, base64, hashlib, json, os, re, shutil, ssl, stat, subprocess, tempfile, time, urllib.request, zipfile
from datetime import datetime
from pathlib import Path
from sangil_publish import file_url, gh, NoRedirect

REPO='gy7604/HikingAndroid-Updates'
PREFIX='repos/'+REPO
TITLE='SANGIL-WATCH-PUBLICATION-CONTROL-v1'
PACKAGE='com.gy7604.hiking.dev'
ACTIVITY='com.gy7604.hiking.wearlink.LinkActivity'
CERT='9b76be478ce899ab17caba5282606b08d7f6feba074a94e9790017db2b77a69d'
MAX=512*1024*1024
MARKER='SANGIL_WATCH_MANIFEST_V1'

def canonical_lines(value):
    if not isinstance(value, str):
        raise ValueError('Exact text metadata required')
    return value.replace('\r\n', '\n')

def validate_event(event, now, issue_number):
    i, c = event.get('issue', {}), event.get('comment', {})
    if (type(issue_number) is not int or issue_number != 4 or event.get('action') != 'created'
            or event.get('repository', {}).get('full_name') != REPO
            or event.get('sender', {}).get('login') != 'gy7604'
            or i.get('number') != issue_number or i.get('title') != TITLE
            or i.get('user', {}).get('login') != 'gy7604' or 'pull_request' in i
            or c.get('user', {}).get('login') != 'gy7604'
            or type(c.get('id')) is not int or c['id'] < 1
            or c.get('created_at') != c.get('updated_at')):
        raise ValueError('Dedicated original owner approval required')
    if 'oaiusercontent.com' in c.get('body', '').lower():
        raise ValueError('Private file addresses are never accepted in public approval text')
    stamp = int(datetime.fromisoformat(c['created_at'].replace('Z', '+00:00')).timestamp())
    if not 0 <= now - stamp <= 900:
        raise ValueError('Approval expired or in the future')
    m = re.fullmatch(r'/sangil-watch-publish approve ([A-Za-z0-9_-]{1,100}) ([a-f0-9]{40}) ([1-9][0-9]{0,8}) ([a-f0-9]{64}) ([a-f0-9]{40}) ([a-f0-9]{64}) ([a-f0-9]{64}) (sealed-v1|github-draft-v1:[1-9][0-9]{0,19}:[1-9][0-9]{0,19})\n\n([^\x00-\x08\x0b\x0c\x0e-\x1f]{1,3000})', canonical_lines(c.get('body', '')))
    if not m or 'SANGIL_WATCH_MANIFEST_V1' in m[9]:
        raise ValueError('Exact candidate, baseline and release notes approval required')
    return dict(requestId=m[1], snapshotSha=m[2], versionCode=int(m[3]), apkSha256=m[4],
                baselineBlobSha=m[5], watchBaselineSha256=m[6], outerSha256=m[7], delivery=m[8], notes=m[9], commentId=c['id'])


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
    required_watch = re.search(r"^[ \t]*uses-feature: name='android.hardware.type.watch'[ \t]*\r?$", metadata, re.M)
    launch = re.search(r"^launchable-activity: name='([^']+)'", metadata, re.M)
    if not required_watch or not launch or launch[1] != ACTIVITY:
        raise ValueError('Required watch hardware and exact watch launcher required')
    allowed = {'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'}
    if len(abis) != len(set(abis)) or not set(abis) <= allowed or (abis and 'armeabi-v7a' not in abis):
        raise ValueError('Watch native ABI compatibility, including 32-bit ARM, required')
    return dict(package=m[1], versionCode=int(m[2]), versionName=m[3], certificateSha256=cert,
                watchHardwareFeature=True, watchActivity=ACTIVITY, nativeAbis=sorted(abis))


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
        expected = dict(schema=1, appId='sangil-wear', requestId=request['requestId'],
                        snapshotSha=request['snapshotSha'], mode='build', compiled=True,
                        checksPassed=True, signed=True, apkBuilt=True, installed=False,
                        publication='NOT_APPROVED', package=PACKAGE, versionCode=request['versionCode'],
                        certificateSha256=CERT, signer='ORIGINAL_OWNER_ENROLLED_KEY', component='watch', sourceModule='wear-link',
                         sourceAppId='sangil', signerAppId='sangil', watchHardwareFeature=True,
                         watchActivity=ACTIVITY)
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
    if (not isinstance(receipt.get('nativeAbis'), list) or actual.get('nativeAbis') != receipt['nativeAbis']
            or actual.get('watchActivity') != ACTIVITY or actual.get('watchHardwareFeature') is not True):
        raise ValueError('Native watch identity disagrees with the watch receipt')
    return {k: receipt[k] for k in ('requestId', 'snapshotSha', 'package', 'versionCode', 'versionName', 'certificateSha256')} | dict(sha256=asset['sha256'], sizeBytes=asset['bytes'])


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


def watch_manifest(candidate, request):
    version=candidate['versionName']
    return dict(schema=1, appId='sangil-wear', component='watch', sourceModule='wear-link',
        packageName=PACKAGE, versionName=version, versionCode=candidate['versionCode'],
        sha256=candidate['sha256'], sizeBytes=candidate['sizeBytes'], signingCertSha256=CERT,
        sourceSha=candidate['snapshotSha'], requestId=candidate['requestId'],
        apkUrl=f'https://github.com/{REPO}/releases/download/wear-v{version}/HikingWear-{version}.apk')

def release_body(candidate, request):
    return request['notes']+'\n\n<!-- '+MARKER+'\n'+json.dumps(watch_manifest(candidate,request),sort_keys=True)+'\n-->'

def watch_inventory(rows):
    """Digest all existing watch publications; no draft or ambiguous metadata."""
    records=[]; maximum=0; versions=set()
    for r in rows:
        tag=r.get('tag_name','')
        if not isinstance(tag,str): raise ValueError('Malformed release tag')
        if not tag.startswith('wear-'): continue
        if r.get('draft') is not False or r.get('prerelease') is not True:
            raise ValueError('Existing watch draft/release needs manual reconciliation')
        version=tag.removeprefix('wear-v')
        if not re.fullmatch(r'\d+\.\d+\.\d+-dev',version): raise ValueError('Watch tag rejected')
        blocks=re.findall(r'<!-- '+MARKER+r'\n([^\n]+)\n-->',canonical_lines(r.get('body','')))
        if len(blocks)!=1: raise ValueError('Exactly one watch manifest required')
        m=json.loads(blocks[0]); assets=r.get('assets',[])
        if (not isinstance(m,dict) or m.get('schema')!=1 or m.get('appId')!='sangil-wear'
            or m.get('component')!='watch' or m.get('sourceModule')!='wear-link'
            or m.get('packageName')!=PACKAGE or m.get('signingCertSha256')!=CERT
            or m.get('versionName')!=version or type(m.get('versionCode')) is not int
            or m['versionCode']<1 or m['versionCode'] in versions
            or not re.fullmatch(r'[a-f0-9]{64}',str(m.get('sha256','')))
            or type(m.get('sizeBytes')) is not int or not 0<m['sizeBytes']<=MAX
            or len(assets)!=1 or assets[0].get('name')!='HikingWear-'+version+'.apk'
            or assets[0].get('size')!=m['sizeBytes'] or assets[0].get('digest')!='sha256:'+m['sha256']
            or m.get('apkUrl')!=f'https://github.com/{REPO}/releases/download/{tag}/HikingWear-{version}.apk'
            or assets[0].get('browser_download_url')!=m['apkUrl']):
            raise ValueError('Watch release identity mismatch')
        versions.add(m['versionCode']); maximum=max(maximum,m['versionCode'])
        records.append(dict(id=r['id'],tag=tag,body=r['body'],assets=[
            {k:assets[0].get(k) for k in ('id','name','size','digest','browser_download_url')}]))
    records.sort(key=lambda r:r['id'])
    digest=hashlib.sha256(json.dumps(records,sort_keys=True,separators=(',',':')).encode()).hexdigest() if records else '0'*64
    return digest,maximum

def api(path, method='GET', body=None):
    reads=(path in (PREFIX,PREFIX+'/contents/latest.json?ref=main',PREFIX+'/git/ref/heads/main',PREFIX+'/releases/latest')
        or re.fullmatch(re.escape(PREFIX)+r'/issues/comments/[1-9][0-9]*',path)
        or re.fullmatch(re.escape(PREFIX)+r'/releases/[1-9][0-9]*',path)
        or re.fullmatch(re.escape(PREFIX)+r'/releases\?per_page=100&page=[1-5]',path)
        or re.fullmatch(re.escape(PREFIX)+r'/git/matching-refs/tags/wear-v[0-9.]+-dev',path))
    writes=(method=='POST' and path==PREFIX+'/releases' and isinstance(body,dict)
        and re.fullmatch(r'wear-v\d+\.\d+\.\d+-dev',str(body.get('tag_name','')))
        and body.get('draft') is True and body.get('prerelease') is True and body.get('make_latest')=='false')
    writes=writes or (method=='PATCH' and re.fullmatch(re.escape(PREFIX)+r'/releases/[1-9][0-9]*',path)
        and body==dict(draft=False,prerelease=True,make_latest='false'))
    if not (method=='GET' and reads or writes): raise ValueError('Watch-only endpoint rejected')
    return json.loads(gh(['api','--method',method,path,*(['--input','-'] if body is not None else [])],body))

def publish(event, request, issue_number, root, verify_apk, read=api, run_gh=gh, clock=time.time):
    phone_identity=None
    def guard():
        nonlocal phone_identity
        if validate_event(event,int(clock()),issue_number)!=request: raise ValueError('Approval changed')
        repo=read(PREFIX)
        if (repo.get('full_name')!=REPO or repo.get('private') is not False
            or repo.get('archived') is not False or repo.get('default_branch')!='main'):
            raise ValueError('Existing public update-only repository required')
        c=read(PREFIX+'/issues/comments/'+str(request['commentId']))
        if (c.get('body')!=event['comment']['body'] or c.get('user',{}).get('login')!='gy7604'
            or c.get('created_at')!=event['comment']['created_at'] or c.get('updated_at')!=c.get('created_at')
            or c.get('issue_url')!=f'https://api.github.com/repos/{REPO}/issues/4'):
            raise ValueError('Owner approval edited or revoked')
        f=read(PREFIX+'/contents/latest.json?ref=main')
        if f.get('sha')!=request['baselineBlobSha'] or f.get('encoding')!='base64' or f.get('size',MAX)>30000:
            raise ValueError('Phone feed changed')
        release=read(PREFIX+'/releases/latest')
        verify_public_baseline(json.loads(base64.b64decode(f['content'])),release)
        identity=json.dumps(release,sort_keys=True,separators=(',',':'))
        if phone_identity is None: phone_identity=identity
        elif phone_identity!=identity: raise ValueError('Phone latest release changed')
    def inventory():
        rows=[]
        for page in range(1,6):
            part=read(PREFIX+f'/releases?per_page=100&page={page}')
            if not isinstance(part,list): raise ValueError('Release collection rejected')
            rows+=part
            if len(part)<100: return rows
        raise ValueError('Release history bounds; manual review required')
    def baseline():
        digest,maximum=watch_inventory(inventory())
        if digest!=request['watchBaselineSha256'] or request['versionCode']<=maximum:
            raise ValueError('Exact watch baseline and increasing version required')
    guard(); baseline()
    candidate=inspect_bundle(root/'approved.zip',request,root,verify_apk)
    tag='wear-v'+candidate['versionName']; name='HikingWear-'+candidate['versionName']+'.apk'
    if read(PREFIX+'/git/matching-refs/tags/'+tag): raise ValueError('Watch tag already claimed')
    if any(r.get('tag_name')==tag for r in inventory()): raise ValueError('Watch release already claimed')
    guard(); baseline()
    head=read(PREFIX+'/git/ref/heads/main')['object']['sha']
    body=release_body(candidate,request)
    created=read(PREFIX+'/releases','POST',dict(tag_name=tag,target_commitish=head,name=tag,
        draft=True,prerelease=True,make_latest='false',body=body))
    rid=created['id']
    asset=root/name;(root/'candidate.apk').rename(asset)
    # No --clobber: an existing asset or an interrupted attempt requires review.
    guard()
    run_gh(['release','upload',tag,str(asset),'--repo',REPO])
    draft=read(PREFIX+'/releases/'+str(rid))
    assets=draft.get('assets',[])
    if (draft.get('draft') is not True or draft.get('prerelease') is not True or draft.get('tag_name')!=tag
        or canonical_lines(draft.get('body'))!=body or len(assets)!=1 or assets[0].get('name')!=name
        or assets[0].get('size')!=candidate['sizeBytes'] or assets[0].get('digest')!='sha256:'+candidate['sha256']):
        raise ValueError('Watch draft asset mismatch; no retry')
    guard()
    remaining=[r for r in inventory() if r.get('id')!=rid]
    if watch_inventory(remaining)[0]!=request['watchBaselineSha256']: raise ValueError('Other watch state changed')
    read(PREFIX+'/releases/'+str(rid),'PATCH',dict(draft=False,prerelease=True,make_latest='false'))
    public=read(PREFIX+'/releases/'+str(rid))
    # Also verifies the published watch body, APK identity and public asset URL.
    watch_inventory([public])
    if (public.get('tag_name')!=tag or canonical_lines(public.get('body'))!=body or
        any(public['assets'][0].get(k)!=assets[0].get(k) for k in ('id','name','size','digest'))):
        raise ValueError('Watch publication outcome requires review')
    guard()  # Phone latest.json and /releases/latest must still be unchanged.
    return dict(requestId=request['requestId'],appId='sangil-wear',releaseId=rid,
        versionCode=candidate['versionCode'],sha256=candidate['sha256'],
        published=True,prerelease=True,phoneFeedChanged=False,installed=False,rebuilt=False)

def receive_file_url(event, request, issue_number):
    if issue_number != 4:
        raise ValueError('Dedicated Sangil watch publication issue required')
    helper = Path(__file__).with_name('watch_sealed_file_transfer.mjs')
    result = subprocess.run(['node', str(helper), '--receive-private-pipe'],
        input=json.dumps(dict(appId='sangil-wear', event=event, requestId=request['requestId'])),
        capture_output=True, text=True, encoding='utf-8', errors='strict', timeout=205)
    if result.returncode or len(result.stdout) > 13000:
        raise ValueError('Private file transfer stopped; no automatic retry')
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or set(payload) != {'url'}:
        raise ValueError('Private file transfer payload rejected')
    return file_url(payload['url'])


def private_bundle_body(request):
    """Non-secret metadata for one owner-staged PC bundle in this same repository."""
    return 'SANGIL_PRIVATE_WATCH_BUNDLE_V1\n' + json.dumps(dict(
        appId='sangil-wear', buildOrigin='OWNER_APPROVED_WINDOWS_PC',
        requestId=request['requestId'], sourceSha=request['snapshotSha'],
        apkSha256=request['apkSha256'], outerSha256=request['outerSha256']), sort_keys=True)


def download_github_asset(asset_id, target):
    """Authenticated same-repository asset read; never accepts an arbitrary URL."""
    if type(asset_id) is not int or asset_id < 1:
        raise ValueError('Exact native asset ID required')
    with target.open('xb') as output:
        result = subprocess.run(['gh', 'api', '--method', 'GET',
            PREFIX+'/releases/assets/'+str(asset_id), '-H', 'Accept: application/octet-stream'],
            stdout=output, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise ValueError('Private same-repository asset download stopped; no retry')


def receive_github_draft(request, root, read=api, download=download_github_asset):
    """Read only an exact owner-staged private draft, bound to the original approval."""
    match = re.fullmatch(r'github-draft-v1:([1-9][0-9]{0,19}):([1-9][0-9]{0,19})', request['delivery'])
    if not match:
        raise ValueError('Exact private draft delivery required')
    release_id, asset_id = map(int, match.groups())
    release = read(PREFIX+'/releases/'+str(release_id))
    assets = release.get('assets', [])
    if (type(release.get('id')) is not int or release['id'] != release_id or release.get('draft') is not True
            or release.get('prerelease') is not True
            or release.get('tag_name') != 'private-watch-candidate-'+request['requestId']
            or release.get('author', {}).get('login') != 'gy7604'
            or canonical_lines(release.get('body')) != private_bundle_body(request)
            or not isinstance(assets, list) or len(assets) != 1):
        raise ValueError('Private candidate draft identity mismatch')
    asset = assets[0]
    if (type(asset.get('id')) is not int or asset['id'] != asset_id
            or asset.get('name') != 'approved.zip' or asset.get('state') != 'uploaded'
            or type(asset.get('size')) is not int or not 0 < asset['size'] <= MAX
            or asset.get('digest') != 'sha256:'+request['outerSha256']
            or asset.get('url') != 'https://api.github.com/'+PREFIX+'/releases/assets/'+str(asset_id)):
        raise ValueError('Private candidate asset mismatch')
    target = Path(root)/'approved.zip'
    if not Path(root).is_dir() or target.exists() or target.is_symlink():
        raise ValueError('New isolated candidate destination required')
    download(asset_id, target)
    if (not target.is_file() or target.is_symlink() or target.stat().st_size != asset['size']
            or hashlib.sha256(target.read_bytes()).hexdigest() != request['outerSha256']):
        raise ValueError('Private candidate bytes mismatch')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--event', required=True)
    a = p.parse_args()
    if (os.environ.get('GITHUB_REPOSITORY') != REPO or os.environ.get('GITHUB_ACTOR') != 'gy7604'
            or os.environ.get('GITHUB_EVENT_NAME') != 'issue_comment' or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'
            or os.environ.get('SANGIL_WATCH_PUBLICATION_ENABLED') != 'true'):
        raise ValueError('Separately enabled native first owner approval required')
    number = int(os.environ.get('SANGIL_WATCH_PUBLICATION_ISSUE', '0'))
    event = json.loads(Path(a.event).read_text(encoding='utf-8'))
    request = validate_event(event, int(time.time()), number)
    with tempfile.TemporaryDirectory(prefix='approved-sangil-watch-publication-') as folder:
        root = Path(folder)
        if request['delivery'].startswith('github-draft-v1:'):
            receive_github_draft(request, root)
        else:
            private_file_url = receive_file_url(event, request, number)
            with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(private_file_url,
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
        sys.stderr.write('Approved Sangil watch publication stopped. Inspect the exact request/draft/feed; no automatic retry.\n')
        sys.exit(1)
