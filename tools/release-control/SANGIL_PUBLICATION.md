# 산길 승인 후 게시

빌드는 비공개 요청형 Actions 또는 사용자가 선택한 PC에서 수행한다. 이 저장소는 검증된 기존 APK의 승인 게시만 담당하며 앱을 빌드·실행·설치하지 않는다.

소유자 전용 창구는 [#1](https://github.com/gy7604/HikingAndroid-Updates/issues/1)이다. 등록 시 SANGIL_PUBLICATION_ENABLED는 꺼져 있으며, push·PR·schedule 빌드는 없다. 게시 활성화와 그 버전의 명시적 사용자 승인을 확인하기 전에는 요청을 등록하지 않는다.

에이전트는 승인된 후보 요청 ID·40자리 snapshot SHA·버전 코드·APK SHA256·기존 latest.json blob SHA·후보와 비밀 없는 영수증만 포함한 ZIP의 SHA256·승인된 파일 링크·변경 설명을 준비한다. 사용자가 명령을 외우거나 파일을 직접 만들 필요는 없다.

요청 형식:

`/sangil-publish approve REQUEST_ID SNAPSHOT_SHA VERSION_CODE APK_SHA256 BASELINE_FEED_BLOB_SHA OUTER_ZIP_SHA256 APPROVED_FILE_URL`

빈 줄 다음에 사용자에게 보여 준 변경 설명을 붙인다. 링크는 승인된 *.oaiusercontent.com/files/ 파일 참조이고 외부 redirect는 허용하지 않는다. 공개 승인을 받기 전에는 비공개 후보 링크를 공개 이슈에 전달하지 않는다. 키·암호·토큰·개인 기록·로그는 전달하지 않는다.

검증은 원본 소유자 댓글·15분 유효기간·후보 해시·실제 APK의 패키지·버전·원래 서명·ARM64와 기존 공개 APK/feed 일치를 포함한다. 게시기는 새 draft를 만들고 APK 서버 해시를 확인한 뒤 release를 공개하고 기존 latest.json만 SHA 조건부로 갱신한다. 앱 소스나 다른 저장소에는 쓰지 않는다.

기존 태그/draft, 승인 편집·만료, baseline 변경, 잘못된 서명·해시, 부분 실패는 자동 재시도·삭제·덮어쓰기를 막는다. release 공개 후 feed 실패는 수동 조정이 필요한 부분 완료이며 앱 업데이트 성공으로 보고하지 않는다.

로컬 검사는 `python -B -m unittest discover -s tools/release-control -v`다. 합성 API 검사는 실제 게시·다운로드·실기기 검증과 구분한다. 새 게시 workflow는 검토된 정확한 helper commit에 고정한다. GitHub 자체 GITHUB_TOKEN만 사용하며 개인 서명키나 비공개 소스 접근 권한을 가져오지 않는다.
