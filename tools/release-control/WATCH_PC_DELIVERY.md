# 워치 게시기: 실제 AAPT 출력 및 기존 PC 후보 전달

승인된 산길 워치 APK 0.1.32-dev/code33의 SHA-256은 c9185d04815c7e99b18ee801f2789c599d8f5b2a158395f1c4e2c14c81a79b64다. APK를 새로 빌드하거나 바꾸지 않는다.

## 수정 이유

기존 고정 게시기는 실제 AAPT 출력의 선행 공백을 허용하지 않아 정상 워치 APK를 거부했다. 앞쪽 가로 공백/탭과 CRLF만 허용하고 필수 워치 기능 이름·전체 행 형식·정확한 시작 화면·32비트 ARM·원래 서명 검사는 유지한다. 잘못된 기능명이나 optional feature 표시는 계속 거부한다.

기존 sealed-v1은 ChatGPT 첨부 파일 주소만 허용하므로, Windows PC에서 사용자가 승인해 만든 기존 APK를 전송할 별도 참조가 필요했다. 새 서버나 키 없이 같은 HikingAndroid-Updates의 비공개 draft release 자산을 GitHub 실행기 토큰으로 읽는 github-draft-v1:releaseId:assetId를 추가한다.

GitHub API가 저장하는 CRLF 줄바꿈은 LF와 같은 내용으로 비교한다. 승인 댓글의 원문·생성/수정 시각 비교와 기존 공개 상태의 전체 원문 해시 결합은 유지한다. 내용 변경·일반 공백 변경은 허용하지 않는다.

## 유지하는 보호

- 기존 전용 요청함 #4, 소유자의 원본·미수정·유효기간 안 승인 댓글, APK와 ZIP 전체 해시, 소스 SHA, 휴대폰/워치 공개 기준 검사를 그대로 사용한다.
- 기존 issue_comment 첫 실행·게시 활성화 값·동시 실행 잠금·고정된 게시 코드·검증 후 공개 절차를 유지한다. 새 빌드나 Actions 자동 재시도는 없다.
- 전달할 draft는 같은 저장소, 소유자 gy7604, private-watch-candidate-<requestId> 태그, draft/prerelease=true, 정확한 JSON 본문과 approved.zip 자산 1개여야 한다.
- 자산 ID·크기·GitHub SHA-256 digest·same-repository API 주소를 승인 내용과 대조한 뒤 읽고, 내려받은 ZIP 크기·전체 해시를 다시 검증한다. 임의 URL, 다른 저장소, 공개 자산, 추가 자산, 변조 파일은 거부한다.
- 인증된 고정 GitHub API 자산 읽기만 사용한다. 접근 가능한 임시 다운로드 주소나 키·토큰을 댓글/소스에 남기지 않는다. 기존 sealed-v1 암호화 경로와 도구는 그대로다.
- PC 후보 확인서에는 실제 OWNER_APPROVED_WINDOWS_PC 출처를 기록한다. GitHub 앱 빌드·서명이 실행됐다고 주장하거나 CI run ID를 만들지 않는다. 게시기에서 원래 인증서·서명·패키지·워치 기능·버전·ABI와 동일 파일 해시를 독립 확인한다.
- 워치 공개 태그는 wear-v, 파일은 HikingWear APK, 공개 상태는 prerelease=true/make_latest=false다. 휴대폰 latest.json·최신 정식 Release·기존 데이터·서명키는 바꾸지 않는다.

## 검증

기존 게시 보호 검사 12개와 PC 전달 검사 9개, 합계 21개가 통과했다. 실제 승인된 APK ZIP도 수정된 파서와 기존 Build Tools 35 검증기로 검증했다. 새 코드의 실제 GitHub 게시 실행은 승인 전 미수행이다.

이 변경은 APK의 공개 승인과 별개인 고정 게시기 반영 검토본이다. 기본 브랜치와 workflow의 고정 SHA를 바꾸는 것은 이 검토본 승인 후에만 한다.
