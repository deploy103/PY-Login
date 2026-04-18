# PY-Login

Flask 기반 회원가입/로그인 미니 웹 프로젝트입니다.

## 주요 기능

- 아이디 기반 회원가입 / 로그인
- 비밀번호 확인 입력
- 8자리 랜덤 캡차
- 세션 기반 로그인 유지
- 관리자 로그인 시 관리자 페이지 이동
- 사용자 목록 조회 / 삭제
- 활동 로그 기록
- SQLite 기반 데이터 저장

## 기술 스택

- Python
- Flask
- SQLite
- HTML / CSS
- gunicorn
- nginx

## 실행 방법

```bash
npm run setup
npm run dev
```

브라우저에서 `http://127.0.0.1:5000`으로 접속하면 됩니다.

## 관리자 계정

관리자 계정은 일반 사용자 DB가 아니라 서버 환경변수로 관리합니다.

- username: `admin`
- password: 서버 환경변수 `ADMIN_PASSWORD`

## 보안 적용 내용

- 비밀번호 해시 저장
- CSRF 토큰 검증
- SQL 파라미터 바인딩
- 세션 보안 설정
- 보안 헤더 적용

## 데이터 저장

사용자와 활동 로그는 `data/app.db` SQLite 데이터베이스에 저장됩니다.
