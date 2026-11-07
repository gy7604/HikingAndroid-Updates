# 산길 기존 APK 승인 게시와 비공개 파일 전달

이 저장소는 이미 만들어진 APK의 승인 게시만 담당한다. 앱을 빌드·실행·설치하지 않는다. 자동 push/PR/schedule 실행은 추가하지 않는다. 산길 워치는 이 경로에 포함되지 않는다.

## 승인과 파일 전달

에이전트는 먼저 앱·대상·후보 요청 ID·전체 소스 SHA·버전·APK 해시·외부 ZIP 해시·run/artifact ID·현재 공개 feed 기준·변경 내용을 사용자에게 제시한다. **그 정확한 버전의 공개를 명시 승인받은 뒤에만** 소유자 전용 [#1](https://github.com/gy7604/HikingAndroid-Updates/issues/1)에 원본 요청을 등록한다.

공개 승인 댓글에는 파일 주소 대신 고정된 전달 방식 이름을 넣는다.

`/sangil-publish approve REQUEST_ID SNAPSHOT_SHA VERSION_CODE APK_SHA256 BASELINE_FEED_BLOB_SHA OUTER_ZIP_SHA256 sealed-v1`

빈 줄 다음에는 승인받은 변경 설명을 붙인다. 예전처럼 파일 주소를 넣는 형식은 거부한다. 사용자가 명령 작성·다운로드·암호화·업로드를 직접 할 필요는 없다.

1. 게시기는 원래 소유자 승인·활성화·첫 실행·검토된 제어기 SHA를 확인한다.
2. 그 실행의 메모리 안에서 일회용 RSA-3072 암호화 수신자를 만든다. 공개 확인 자료만 bot 댓글에 게시한다. 개인 부분은 파일·artifact·cache·출력·GitHub secret에 저장하지 않는다. 기존 앱 서명키·API 키·계정 자격은 변경하지 않는다.
3. 에이전트는 native 실행의 소유자·workflow·고정 제어기·실행 ID·원본 승인·댓글 bot·수신 유효기간을 대조한 뒤 같은 후보의 임시 파일 주소를 암호화한다. 승인 댓글과 notes 전체의 해시도 암호화 맥락에 묶는다.
4. 전달 댓글은 `/publication-file-deliver sangil REQUEST_ID PUBLISHER_RUN_ID ENVELOPE_JSON`이며 주소의 평문을 포함하지 않는다. 암호화는 Node 24 기본 기능 RSA-OAEP-SHA256 + AES-256-GCM만 사용한다.
5. 게시기는 최대 180초 동안 한 번의 원본 소유자 전달만 받는다. 다른 실행·앱·후보·기준·암호화 맥락, 변조·편집·중복·만료·승인 철회는 거부한다. 복호화 주소는 Python과 Node 사이의 비공개 pipe로만 전달하고 로그·명령 인자·출력 파일에 남기지 않는다.
6. 원래 허용 호스트와 redirect 차단, ZIP 크기/해시, 비밀 없는 영수증, APK 패키지·버전·원래 인증서·ARM64, 기존 공개 APK/feed 검사를 통과한 동일 파일만 기존 Release/latest.json 경로로 게시한다.

이 방식은 다른 비공개 저장소를 읽는 권한을 공개 저장소에 추가하지 않는다. 기존 GITHUB_TOKEN의 해당 저장소 contents 쓰기는 유지하고, 공개 확인 자료 댓글을 쓰기 위한 해당 저장소 issues 쓰기만 사용한다. 별도 계정·PAT·App private key·장기 암호화키를 등록하지 않는다.

## 실패·실행 경계

원본 승인의 15분 유효기간, 기존 태그/draft·해시·baseline·서명 검사와 부분 실패 시 자동 재시도·삭제·덮어쓰기 금지를 유지한다. Release 공개 후 feed 실패는 부분 완료이며 설치 성공으로 보고하지 않는다.

에이전트는 동일한 후보의 기존 성공 결과와 유효한 artifact를 먼저 읽는다. 만료나 실패를 새 빌드·재게시·새 키로 자동 해결하지 않는다. 실제 게시에는 해당 버전의 별도 명시 승인이 필요하다. 게시 결과의 파일 해시·서명·feed 확인과 기기 설치/업데이트는 별개다.

## 검증 범위

- Python: `python -B -m unittest discover -s tools/release-control -v`
- 전달 모듈: `node --test tools/release-control/test_sealed_file_transfer.mjs`

검토 시 가짜 주소·가짜 파일·가짜 API로 Python 20개와 전달 모듈 16개 검사가 통과했다. 실제 GitHub의 암호화 전달·공개 게시·휴대폰 설치·일반 웹/모바일 채팅 실행은 이 검사로 확인되지 않는다. 새 온라인 검증은 사용량과 명시 요청을 확인하고 실행한다.

암호화의 기반은 기존 Sites 전달 패턴이며, [Node 24 암호화 API](https://nodejs.org/docs/latest-v24.x/api/crypto.html)와 [GitHub workflow 권한 설명](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)을 기준으로 확인했다.
