import base64
import copy
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock
import sangil_publish as sp


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.now=1793664000
        self.apk=b'APK bytes used only with the synthetic verifier'
        self.digest=hashlib.sha256(self.apk).hexdigest()
        self.receipt=dict(schema=1,appId='sangil',requestId='build-1',snapshotSha='a'*40,mode='build',
            compiled=True,checksPassed=True,signed=True,apkBuilt=True,installed=False,publication='NOT_APPROVED',
            package=sp.PACKAGE,versionCode=28,versionName='0.1.27-dev',certificateSha256=sp.CERT,
            signer='ORIGINAL_OWNER_ENROLLED_KEY',artifacts=[dict(name='candidate.apk',bytes=len(self.apk),sha256=self.digest)])
        self.bundle(self.receipt)
        self.event=dict(action='created',repository=dict(full_name=sp.REPO),sender=dict(login='gy7604'),
            issue=dict(number=42,title=sp.TITLE,user=dict(login='gy7604')),
            comment=dict(id=123,user=dict(login='gy7604'),created_at='2026-11-03T00:00:00Z',updated_at='2026-11-03T00:00:00Z'))
        self.refresh_request()
        self.baseline=dict(packageName=sp.PACKAGE,signingCertSha256=sp.CERT,versionCode=27,
            versionName='0.1.26-dev',sha256='f'*64,sizeBytes=1000,
            apkUrl=f'https://github.com/{sp.REPO}/releases/download/v0.1.26-dev/HikingAndroid-0.1.26-dev.apk')
        self.release=None; self.saved=None; self.calls=[]; self.bad_digest=False; self.existing=False
    def tearDown(self): self.temp.cleanup()
    def bundle(self,receipt,extras=None):
        with zipfile.ZipFile(self.root/'approved.zip','w') as z:
            z.writestr('candidate.apk',self.apk); z.writestr('receipt.json',json.dumps(receipt))
            for name,data in (extras or {}).items(): z.writestr(name,data)
    def refresh_request(self):
        self.outer=hashlib.sha256((self.root/'approved.zip').read_bytes()).hexdigest()
        self.event['comment']['body']=f'/sangil-publish approve build-1 {"a"*40} 28 {self.digest} {"c"*40} {self.outer} https://download.oaiusercontent.com/files/example\n\n승인한 변경 내용'
        self.request=sp.validate_event(self.event,self.now,42)
    def verify(self,path):
        self.assertEqual(path.read_bytes(),self.apk)
        return {k:self.receipt[k] for k in ('package','versionCode','versionName','certificateSha256')}
    def read(self,path,method='GET',body=None):
        self.calls.append((method,path,copy.deepcopy(body)))
        prefix=sp.PREFIX
        if path==prefix: return dict(full_name=sp.REPO,private=False,archived=False,default_branch='main')
        if '/issues/comments/' in path:
            return self.event['comment'] | {'issue_url':f'https://api.github.com/repos/{sp.REPO}/issues/42'}
        if path==prefix+'/contents/latest.json?ref=main':
            data=self.saved if self.saved is not None else self.baseline
            return dict(sha='d'*40 if self.saved is not None else 'c'*40,encoding='base64',size=100,
                        content=base64.b64encode(json.dumps(data).encode()).decode())
        if '/git/matching-refs/' in path: return []
        if '/releases?' in path: return [{'tag_name':'v0.1.27-dev'}] if self.existing else []
        if path==prefix+'/releases/latest':
            if self.release is not None and self.release['draft'] is False:return copy.deepcopy(self.release)
            return dict(id=8,tag_name='v0.1.26-dev',draft=False,prerelease=False,
                assets=[dict(browser_download_url=self.baseline['apkUrl'],size=1000,digest='sha256:'+'f'*64)])
        if path.endswith('/git/ref/heads/main'): return dict(object=dict(sha='e'*40))
        if path==prefix+'/releases' and method=='POST':
            self.release=body | dict(id=9,assets=[]); return copy.deepcopy(self.release)
        if path==prefix+'/releases/9':
            if method=='PATCH': self.release.update(body)
            return copy.deepcopy(self.release)
        if path==prefix+'/contents/latest.json' and method=='PUT':
            self.assertEqual(body['sha'],'c'*40); self.saved=json.loads(base64.b64decode(body['content'])); return {'content':{'sha':'d'*40}}
        raise AssertionError('Unexpected endpoint '+path)
    def upload(self,args):
        self.assertEqual(args[0:3],['release','upload','v0.1.27-dev'])
        self.assertEqual(args[-2:],['--repo',sp.REPO])
        self.assertEqual(Path(args[3]).read_bytes(),self.apk)
        self.release['assets']=[dict(id=10,name='HikingAndroid-0.1.27-dev.apk',size=len(self.apk),
            digest='sha256:'+('0'*64 if self.bad_digest else self.digest),
            browser_download_url=f'https://github.com/{sp.REPO}/releases/download/v0.1.27-dev/HikingAndroid-0.1.27-dev.apk')]
    def publish(self,**changes):
        args=dict(event=self.event,request=self.request,issue_number=42,root=self.root,
            verify_apk=self.verify,read=self.read,run_gh=self.upload,clock=lambda:self.now)
        args.update(changes); return sp.publish(**args)
    def writes(self): return [c for c in self.calls if c[0]!='GET']
    def test_native_owner_exact_version_baseline_and_notes_are_required(self):
        for part,key,value in [('sender','login','other'),('issue','number',43),
            ('comment','updated_at','edited'),('comment','body',self.event['comment']['body']+'\x00')]:
            e=copy.deepcopy(self.event);e[part][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):sp.validate_event(e,self.now,42)
        for now in (self.now-1,self.now+901):
            with self.assertRaises(ValueError):sp.validate_event(self.event,now,42)
    def test_external_and_redirect_like_download_urls_are_rejected(self):
        for url in ('http://download.oaiusercontent.com/files/x','https://evil.test/files/x',
                    'https://download.oaiusercontent.com.evil.test/files/x',
                    'https://user:pass@download.oaiusercontent.com/files/x',
                    'https://download.oaiusercontent.com/files/x#fragment'):
            with self.subTest(url=url),self.assertRaises(ValueError):sp.file_url(url)
    def test_only_two_bounded_non_secret_files_are_allowed(self):
        for extra in ({'check-log.txt':'private'}, {'../key.pem':'private'}):
            self.bundle(self.receipt,extra); self.refresh_request()
            with self.assertRaises(ValueError):self.publish()
            self.assertEqual(self.writes(),[])
    def test_wrong_signer_source_boolean_schema_or_install_claim_never_writes(self):
        for change in (dict(certificateSha256='f'*64),dict(snapshotSha='b'*40),dict(schema=True),
                       dict(installed=True),dict(publication='PUBLISHED'),dict(package='other')):
            self.bundle(self.receipt | change); self.refresh_request()
            with self.subTest(change=change),self.assertRaises(ValueError):self.publish()
            self.assertEqual(self.writes(),[])
    def test_actual_apk_metadata_must_agree_with_receipt(self):
        with self.assertRaises(ValueError):self.publish(verify_apk=lambda p:self.verify(p)|dict(versionCode=29))
        self.assertEqual(self.writes(),[])
    def test_wrong_bundle_hash_never_extracts_or_writes(self):
        self.request['outerSha256']='0'*64
        with self.assertRaises(ValueError):sp.inspect_bundle(self.root/'approved.zip',self.request,self.root,self.verify)
        self.assertFalse((self.root/'candidate.apk').exists())
    def test_existing_version_or_changed_feed_cannot_be_overwritten(self):
        self.existing=True
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.writes(),[])
    def test_feed_rejects_downgrade_and_wrong_original_signer(self):
        c={k:self.receipt[k] for k in ('versionCode','versionName')}; c.update(sha256=self.digest,sizeBytes=10)
        for baseline in (self.baseline | {'versionCode':28},self.baseline | {'signingCertSha256':'0'*64}):
            with self.assertRaises(ValueError):sp.manifest(c,self.request,baseline)
    def test_verified_prebuilt_apk_updates_only_existing_feed(self):
        result=self.publish()
        self.assertTrue(result['published']);self.assertFalse(result['rebuilt']);self.assertFalse(result['installed'])
        self.assertEqual(self.saved['sha256'],self.digest)
        self.assertEqual(self.saved['notes'],'승인한 변경 내용')
        self.assertEqual([w[0] for w in self.writes()],['POST','PATCH','PUT'])
        self.assertEqual(self.writes()[0][2]['target_commitish'],'e'*40)
    def test_bad_uploaded_digest_leaves_draft_and_does_not_publish_feed(self):
        self.bad_digest=True
        with self.assertRaises(ValueError):self.publish()
        self.assertTrue(self.release['draft']);self.assertIsNone(self.saved)
        self.assertEqual([w[0] for w in self.writes()],['POST'])
    def test_approval_revoked_after_upload_prevents_publication(self):
        read=self.read
        def revoked(path,method='GET',body=None):
            value=read(path,method,body)
            if '/issues/comments/' in path and self.release is not None:return value | {'body':'revoked'}
            return value
        with self.assertRaises(ValueError):self.publish(read=revoked)
        self.assertTrue(self.release['draft']);self.assertIsNone(self.saved)
        self.assertEqual([w[0] for w in self.writes()],['POST'])
    def test_api_guard_never_reaches_protected_app_or_source_endpoints(self):
        for path,method in (('repos/gy7604/worktable/releases','POST'),
                            (sp.PREFIX+'/contents/app/build.gradle.kts','PUT'),
                            ('repos/gy7604/gy7604.github.io/contents/latest.json','PUT')):
            with self.subTest(path=path),self.assertRaises(ValueError):sp.api(path,method,{})
    def test_disagreement_between_feed_and_public_release_stops_before_writes(self):
        read=self.read
        def changed(path,method='GET',body=None):
            value=read(path,method,body)
            return value | {'tag_name':'v0.1.29-dev'} if path.endswith('/releases/latest') else value
        with self.assertRaises(ValueError):self.publish(read=changed)
        self.assertEqual(self.writes(),[])
    def test_feed_change_after_draft_stops_before_publication(self):
        read=self.read
        def changed(path,method='GET',body=None):
            value=read(path,method,body)
            if '/contents/latest.json?' in path and self.release is not None:return value | {'sha':'d'*40}
            return value
        with self.assertRaises(ValueError):self.publish(read=changed)
        self.assertTrue(self.release['draft']);self.assertIsNone(self.saved)
        self.assertEqual([w[0] for w in self.writes()],['POST'])
    def test_unknown_feed_commit_outcome_is_not_reported_as_success(self):
        read=self.read
        def unknown(path,method='GET',body=None):
            if method=='PUT':raise RuntimeError('Unknown commit result')
            return read(path,method,body)
        with self.assertRaises(RuntimeError):self.publish(read=unknown)
        self.assertFalse(self.release['draft']);self.assertIsNone(self.saved)


if __name__=='__main__':unittest.main()
