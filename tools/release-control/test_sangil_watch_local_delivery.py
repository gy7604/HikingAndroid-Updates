"""Owner-staged PC file delivery tests. No live API, key, APK or publication."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sangil_watch_publish as w


class LocalCandidateDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bytes = b'synthetic bounded bundle, not an APK'
        self.digest = hashlib.sha256(self.bytes).hexdigest()
        self.request = dict(requestId='pc-watch-33', snapshotSha='a'*40, versionCode=33,
            apkSha256='b'*64, baselineBlobSha='c'*40, watchBaselineSha256='0'*64,
            outerSha256=self.digest, delivery='github-draft-v1:101:202')
        self.release = dict(id=101, draft=True, prerelease=True,
            tag_name='private-watch-candidate-pc-watch-33', author=dict(login='gy7604'),
            body=w.private_bundle_body(self.request), assets=[dict(id=202, name='approved.zip',
                state='uploaded', size=len(self.bytes), digest='sha256:'+self.digest,
                url='https://api.github.com/'+w.PREFIX+'/releases/assets/202')])
        self.downloads = []
        self.reads = []

    def read(self, path):
        self.reads.append(path)
        self.assertEqual(path, w.PREFIX+'/releases/101')
        return copy.deepcopy(self.release)

    def download(self, asset_id, target):
        self.downloads.append(asset_id)
        self.assertEqual(asset_id, 202)
        target.write_bytes(self.bytes)

    def receive(self, **changes):
        args = dict(request=self.request, root=self.root, read=self.read, download=self.download)
        args.update(changes)
        w.receive_github_draft(**args)

    def test_exact_private_same_repository_asset_is_verified_without_external_url(self):
        self.receive()
        self.assertEqual(self.downloads, [202])
        self.assertEqual((self.root/'approved.zip').read_bytes(), self.bytes)
        self.assertNotIn('http', self.request['delivery'])

    def test_github_crlf_metadata_is_equivalent_but_other_content_is_not(self):
        self.release['body'] = self.release['body'].replace('\n', '\r\n')
        self.receive()
        self.assertEqual(self.downloads, [202])

    def test_public_or_wrong_owner_tag_body_release_are_rejected_before_download(self):
        for change in [dict(draft=False), dict(prerelease=False), dict(id=102),
                dict(author=dict(login='someone')), dict(tag_name='wear-v0.1.32-dev'),
                dict(body='different request')]:
            with self.subTest(change=change):
                original = copy.deepcopy(self.release)
                self.release.update(change)
                with self.assertRaises(ValueError): self.receive()
                self.assertEqual(self.downloads, [])
                self.release = original

    def test_asset_identity_hash_size_path_state_and_extra_assets_fail_closed(self):
        for change in [dict(id=203), dict(id=True), dict(name='candidate.apk'),
                dict(digest='sha256:'+'f'*64), dict(size=0), dict(size=True),
                dict(size=w.MAX+1), dict(state='new'),
                dict(url='https://api.github.com/repos/other/repo/releases/assets/202')]:
            with self.subTest(change=change):
                original = copy.deepcopy(self.release)
                self.release['assets'][0].update(change)
                with self.assertRaises(ValueError): self.receive()
                self.assertEqual(self.downloads, [])
                self.release = original
        self.release['assets'].append(copy.deepcopy(self.release['assets'][0]))
        with self.assertRaises(ValueError): self.receive()
        self.assertEqual(self.downloads, [])

    def test_changed_downloaded_bytes_stop_before_bundle_inspection_or_publication(self):
        with self.assertRaises(ValueError):
            self.receive(download=lambda asset_id, target: target.write_bytes(b'tampered'))

    def test_existing_destination_is_never_overwritten(self):
        (self.root/'approved.zip').write_bytes(b'preserve')
        with self.assertRaises(ValueError): self.receive()
        self.assertEqual((self.root/'approved.zip').read_bytes(), b'preserve')
        self.assertEqual(self.downloads, [])

    def test_arbitrary_urls_other_modes_and_invalid_ids_are_not_delivery_references(self):
        for ref in ['https://example.com/file.zip', 'github-draft-v1:0:202',
                'github-draft-v1:101:0', 'github-draft-v1:../:202', 'sealed-v1']:
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                self.receive(request=self.request | dict(delivery=ref))
        self.assertEqual(self.reads, [])

    def test_original_owner_approval_format_binds_draft_and_asset_ids(self):
        now=1793664000
        command='/sangil-watch-publish approve pc-watch-33 '+'a'*40+' 33 '+'b'*64+' '+'c'*40+' '+'0'*64+' '+self.digest+' github-draft-v1:101:202\n\n워치 업데이트'
        event=dict(action='created', repository=dict(full_name=w.REPO),sender=dict(login='gy7604'),
            issue=dict(number=4,title=w.TITLE,user=dict(login='gy7604')),
            comment=dict(id=123,user=dict(login='gy7604'),created_at='2026-11-03T00:00:00Z',
                updated_at='2026-11-03T00:00:00Z',body=command))
        request=w.validate_event(event,now,4)
        self.assertEqual(request['delivery'],'github-draft-v1:101:202')
        crlf=copy.deepcopy(event)
        crlf['comment']['body']=command.replace('\n','\r\n')
        self.assertEqual(w.validate_event(crlf,now,4),request)
        for bad in ['github-draft-v1:0:202','github-draft-v1:101:202:303','https://example.com/x']:
            other=copy.deepcopy(event)
            other['comment']['body']=command.replace('github-draft-v1:101:202',bad)
            with self.assertRaises(ValueError): w.validate_event(other,now,4)
        other=copy.deepcopy(event);other['sender']['login']='someone'
        with self.assertRaises(ValueError): w.validate_event(other,now,4)

    def test_binary_reader_uses_only_fixed_repo_numeric_asset_and_stops_on_failure(self):
        target=self.root/'download.zip'
        completed=w.subprocess.CompletedProcess([],0)
        with patch.object(w.subprocess,'run',return_value=completed) as call:
            w.download_github_asset(202,target)
        args=call.call_args[0][0]
        self.assertEqual(args[:5],['gh','api','--method','GET',w.PREFIX+'/releases/assets/202'])
        self.assertIn('Accept: application/octet-stream',args)
        for invalid in [True,0,-1,'202','../secrets']:
            with self.assertRaises(ValueError): w.download_github_asset(invalid,self.root/'other.zip')
        with patch.object(w.subprocess,'run',return_value=w.subprocess.CompletedProcess([],1)):
            with self.assertRaises(ValueError): w.download_github_asset(202,self.root/'failed.zip')


if __name__ == '__main__':
    unittest.main()
