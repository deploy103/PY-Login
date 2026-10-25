# PY-Login

회원가입과 로그인이 가능한 Flask 기반 미니 웹 프로젝트입니다.

## 주요 기능

- 아이디 기반 회원가입 / 로그인
- 비밀번호 확인 입력
- 8자리 랜덤 캡차
- 세션 기반 로그인 유지
- 관리자 로그인 시 관리자 페이지 이동
- 사용자 목록 조회 / 삭제
- 활동 로그 기록

## 기술 스택

- Backend: Python, Flask
- Frontend: HTML, CSS
- Database: SQLite
- Deployment: gunicorn, nginx

## 실행 방법

```bash
npm run setup
npm run dev
```

브라우저에서 `http://127.0.0.1:5000`으로 접속하면 됩니다.

로컬 개발 스크립트는 `.env`를 자동으로 읽지 않습니다. 필요한 설정은 실행 전에
환경변수로 전달하세요. 기본 허용 호스트는 `localhost,127.0.0.1`이며 다른 주소는
`TRUSTED_HOSTS`에 명시해야 합니다.

Compose 배포는 `.env.example`을 참고해 Git에 포함되지 않는 `.env`를 준비합니다.
`SECRET_KEY`를 충분히 긴 무작위 값으로 교체하고 `TRUSTED_HOSTS`를 실제 호스트로
지정하세요. HTTPS 배포에서는 `SESSION_COOKIE_SECURE=true`를 유지합니다.
`ADMIN_PASSWORD`가 비어 있으면 내장 관리자 로그인이 비활성화됩니다.
Compose 예시는 기존 외부 Docker 네트워크와 리버스 프록시를 전제로 하므로 로컬
개발 명령과 구분해 사용하세요. 운영 비밀번호와 키를 Git·명령행 기록에 넣지 마세요.

## 보안 적용 내용

- 비밀번호 해시 저장
- CSRF 토큰 검증
- SQL 파라미터 바인딩
- 세션 보안 설정
- 보안 헤더 적용
