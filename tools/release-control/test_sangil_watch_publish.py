"""Synthetic API/archive tests only. Never run APKs or connect to a service."""
import base64, copy, hashlib, json, tempfile, unittest, zipfile, subprocess
from pathlib import Path
from unittest.mock import patch
import sangil_watch_publish as w

class WatchPublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); self.now=1793664000
        self.apk=b'synthetic watch bytes; not executable'; self.sha=hashlib.sha256(self.apk).hexdigest()
        self.receipt=dict(schema=1,appId='sangil-wear',requestId='watch-test',snapshotSha='a'*40,mode='build',
            compiled=True,checksPassed=True,signed=True,apkBuilt=True,installed=False,publication='NOT_APPROVED',
            package=w.PACKAGE,versionCode=32,versionName='0.1.31-dev',certificateSha256=w.CERT,
            signer='ORIGINAL_OWNER_ENROLLED_KEY',sourceAppId='sangil',signerAppId='sangil',component='watch',
            sourceModule='wear-link',watchHardwareFeature=True,watchActivity=w.ACTIVITY,nativeAbis=['arm64-v8a','armeabi-v7a'],
            artifacts=[dict(name='candidate.apk',bytes=len(self.apk),sha256=self.sha)])
        self.event=dict(action='created',repository=dict(full_name=w.REPO),sender=dict(login='gy7604'),
            issue=dict(number=4,title=w.TITLE,user=dict(login='gy7604')),
            comment=dict(id=123,user=dict(login='gy7604'),created_at='2026-11-03T00:00:00Z',updated_at='2026-11-03T00:00:00Z'))
        self.feed=dict(packageName=w.PACKAGE,signingCertSha256=w.CERT,versionCode=27,versionName='0.1.26-dev',
            sha256='f'*64,sizeBytes=1000,apkUrl=f'https://github.com/{w.REPO}/releases/download/v0.1.26-dev/HikingAndroid-0.1.26-dev.apk')
        self.phone=dict(id=8,tag_name='v0.1.26-dev',draft=False,prerelease=False,assets=[
            dict(browser_download_url=self.feed['apkUrl'],size=1000,digest='sha256:'+'f'*64)])
        self.release=None;self.calls=[];self.existing=[];self.revoked=False;self.changed_feed=False
        self.bad_digest=False;self.phone_changed=False;self.bundle()
    def tearDown(self):self.tmp.cleanup()
    def bundle(self,change=None,extras=None):
        self.payload=self.receipt|(change or {})
        with zipfile.ZipFile(self.root/'approved.zip','w') as z:
            z.writestr('candidate.apk',self.apk);z.writestr('receipt.json',json.dumps(self.payload))
            for name,data in (extras or {}).items():z.writestr(name,data)
        outer=hashlib.sha256((self.root/'approved.zip').read_bytes()).hexdigest()
        self.event['comment']['body']=f'/sangil-watch-publish approve watch-test {"a"*40} 32 {self.sha} {"c"*40} {"0"*64} {outer} sealed-v1\n\n워치 글자색 보완'
        self.request=w.validate_event(self.event,self.now,4)
    def native(self,p):
        self.assertEqual(p.read_bytes(),self.apk)
        return {k:self.receipt[k] for k in ('package','versionCode','versionName','certificateSha256','nativeAbis','watchHardwareFeature','watchActivity')}
    def api(self,path,method='GET',body=None):
        self.calls.append((method,path,copy.deepcopy(body)))
        p=w.PREFIX
        if path==p:return dict(full_name=w.REPO,private=False,archived=False,default_branch='main')
        if '/issues/comments/' in path:
            return self.event['comment']|dict(body='revoked' if self.revoked else self.event['comment']['body'],issue_url=f'https://api.github.com/repos/{w.REPO}/issues/4')
        if path==p+'/contents/latest.json?ref=main':
            return dict(sha=('d' if self.changed_feed else 'c')*40,encoding='base64',size=100,content=base64.b64encode(json.dumps(self.feed).encode()).decode())
        if path==p+'/releases/latest':return copy.deepcopy(self.phone|dict(id=100 if self.phone_changed else 8))
        if '/git/matching-refs/' in path:return []
        if '/releases?' in path:return copy.deepcopy(self.existing+([self.release] if self.release else []))
        if path.endswith('/git/ref/heads/main'):return dict(object=dict(sha='e'*40))
        if path==p+'/releases' and method=='POST':
            self.release=body|dict(id=9,assets=[]);return copy.deepcopy(self.release)
        if path==p+'/releases/9':
            if method=='PATCH':self.release.update(body)
            return copy.deepcopy(self.release)
        raise AssertionError('Forbidden endpoint '+method+' '+path)
    def upload(self,args):
        self.assertEqual(args[:3],['release','upload','wear-v0.1.31-dev'])
        self.assertNotIn('--clobber',args);self.assertEqual(Path(args[3]).read_bytes(),self.apk)
        self.release['assets']=[dict(id=10,name='HikingWear-0.1.31-dev.apk',size=len(self.apk),
            digest='sha256:'+('0'*64 if self.bad_digest else self.sha),
            browser_download_url=f'https://github.com/{w.REPO}/releases/download/wear-v0.1.31-dev/HikingWear-0.1.31-dev.apk')]
    def publish(self,**changes):
        kw=dict(event=self.event,request=self.request,issue_number=4,root=self.root,verify_apk=self.native,
            read=self.api,run_gh=self.upload,clock=lambda:self.now);kw.update(changes);return w.publish(**kw)
    def writes(self):return [c for c in self.calls if c[0]!='GET']
    def test_separate_watch_release_never_writes_phone_feed_or_selects_latest(self):
        result=self.publish()
        self.assertTrue(result['published']);self.assertFalse(result['phoneFeedChanged'])
        self.assertFalse(result['rebuilt']);self.assertFalse(result['installed'])
        self.assertEqual([x[0] for x in self.writes()],['POST','PATCH'])
        self.assertTrue(all(x[2]['make_latest']=='false' and x[2]['prerelease'] is True for x in self.writes()))
        self.assertFalse(any(x[0]=='PUT' for x in self.calls))
        self.assertEqual(w.watch_inventory([self.release])[1],32)
    def test_github_crlf_release_bodies_keep_original_inventory_binding(self):
        original=self.api
        def api(path,method='GET',body=None):
            value=original(path,method,body)
            if method=='POST' and self.release:
                self.release['body']=self.release['body'].replace('\n','\r\n')
                value=copy.deepcopy(self.release)
            return value
        self.assertTrue(self.publish(read=api)['published'])
        self.assertEqual(w.watch_inventory([self.release])[1],32)
        self.assertIn('\r\n',self.release['body'])
    def test_phone_issue_or_command_and_edited_approval_are_rejected(self):
        for edit in [lambda e:e['issue'].update(number=1),lambda e:e['issue'].update(title='SANGIL-PUBLICATION-CONTROL-v1'),
            lambda e:e['comment'].update(body=e['comment']['body'].replace('/sangil-watch-publish','/sangil-publish')),
            lambda e:e['comment'].update(updated_at='edited')]:
            e=copy.deepcopy(self.event);edit(e)
            with self.assertRaises(ValueError):w.validate_event(e,self.now,4)
        for now in [self.now-1,self.now+901]:
            with self.assertRaises(ValueError):w.validate_event(self.event,now,4)
    def test_phone_candidate_wrong_signer_module_source_and_boolean_coercion_stop_before_write(self):
        for change in [dict(appId='sangil'),dict(sourceModule='app'),dict(component='phone'),dict(sourceAppId='other'),
            dict(signerAppId='sangil-wear'),dict(watchHardwareFeature=False),dict(watchActivity='other'),
            dict(certificateSha256='f'*64),dict(snapshotSha='b'*40),dict(schema=True),dict(installed=True)]:
            self.bundle(change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.publish()
            self.assertEqual(self.writes(),[])
    def test_apk_receipt_mismatch_and_extra_archive_entry_are_rejected(self):
        with self.assertRaises(ValueError):self.publish(verify_apk=lambda p:self.native(p)|dict(nativeAbis=['arm64-v8a']))
        self.assertEqual(self.writes(),[])
        (self.root/'candidate.apk').unlink()
        self.bundle(extras={'../key.pem':'synthetic'})
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.writes(),[])
    def test_feed_or_watch_baseline_changes_stop_before_any_release(self):
        self.changed_feed=True
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.writes(),[])
        self.changed_feed=False;self.request['watchBaselineSha256']='1'*64
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.writes(),[])
    def test_revoked_original_approval_stops_before_any_release(self):
        self.revoked=True
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual(self.writes(),[])
    def test_changed_phone_latest_after_draft_prevents_asset_upload(self):
        original=self.api
        def api(path,method='GET',body=None):
            value=original(path,method,body)
            if method=='POST':self.phone_changed=True
            return value
        with self.assertRaises(ValueError):self.publish(read=api)
        self.assertTrue(self.release['draft']);self.assertEqual(self.release['assets'],[])
    def test_bad_github_asset_digest_preserves_draft_and_never_retries(self):
        self.bad_digest=True
        with self.assertRaises(ValueError):self.publish()
        self.assertEqual([x[0] for x in self.writes()],['POST']);self.assertTrue(self.release['draft'])
    def test_valid_history_blocks_duplicate_or_downgrade_and_drafts_need_review(self):
        self.publish();r=copy.deepcopy(self.release);digest,maximum=w.watch_inventory([r])
        self.assertEqual(maximum,32);self.assertNotEqual(digest,'0'*64)
        for change in [dict(draft=True),dict(prerelease=False),dict(body='missing manifest')]:
            with self.assertRaises(ValueError):w.watch_inventory([r|change])
        self.bundle();self.existing=[r];self.release=None
        self.event['comment']['body']=self.event['comment']['body'].replace('0'*64,digest)
        self.request=w.validate_event(self.event,self.now,4)
        with self.assertRaises(ValueError):self.publish()
    def test_no_contents_delete_phone_tag_or_latest_operation_allowed_by_api(self):
        for path,method,body in [(w.PREFIX+'/contents/latest.json','PUT',{}),(w.PREFIX+'/releases/9','DELETE',None),
            (w.PREFIX+'/releases/9','PATCH',dict(draft=False,make_latest='true')),
            (w.PREFIX+'/releases','POST',dict(tag_name='v0.1.31-dev',draft=True,prerelease=True,make_latest='false'))]:
            with patch.object(w,'gh',side_effect=AssertionError('no network')):
                with self.assertRaises(ValueError):w.api(path,method,body)
    def test_native_aapt_requires_watch_launcher_feature_and_32bit_compatibility(self):
        with tempfile.TemporaryDirectory() as folder:
            sdk=Path(folder);tools=sdk/'build-tools/35.0.0';tools.mkdir(parents=True)
            (tools/('apksigner.bat' if w.os.name=='nt' else 'apksigner')).touch()
            (tools/('aapt.exe' if w.os.name=='nt' else 'aapt')).touch()
            pem='-----BEGIN CERTIFICATE-----\nZg==\n-----END CERTIFICATE-----'
            metadata=f"package: name='{w.PACKAGE}' versionCode='32' versionName='0.1.31-dev'\nuses-feature: name='android.hardware.type.watch'\nlaunchable-activity: name='{w.ACTIVITY}'\nnative-code: 'arm64-v8a' 'armeabi-v7a'\n"
            def verify(meta):
                outputs=[subprocess.CompletedProcess([],0,'Number of signers: 1\n'+pem),subprocess.CompletedProcess([],0,meta)]
                with patch.object(w.subprocess,'run',side_effect=outputs),patch.object(w.ssl,'PEM_cert_to_DER_cert',return_value=b'synthetic'):
                    return w.verify_native_apk(self.root/'fixture.apk',sdk)
            self.assertEqual(verify(metadata)['nativeAbis'],['arm64-v8a','armeabi-v7a'])
            self.assertEqual(verify(metadata.replace("uses-feature:", "  uses-feature:"))['watchHardwareFeature'], True)
            self.assertEqual(verify(metadata.replace("uses-feature:", "\tuses-feature:"))['watchHardwareFeature'], True)
            for bad in [metadata.replace(w.ACTIVITY,'phone.MainActivity'),metadata.replace('uses-feature:','uses-feature-not-required:'),
                metadata.replace(" 'armeabi-v7a'",""),metadata.replace("'armeabi-v7a'","'unknown'")]:
                with self.assertRaises(ValueError):verify(bad)

if __name__=='__main__':unittest.main()
