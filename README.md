# AX Filter prototype

생성형 AI 프롬프트 개인정보 검출·마스킹·차단 프로토타입 (서버 핵심) + 자사 자산 점검 도구.
데모/연구용이며 프로덕션 보안 제품이 아닙니다.

## server/
FastAPI 기반 검사 API.

```
cd axfilter/server
pip install -e ".[postgres,dev]"       # 패키지 설치 (콘솔 명령 axfilter 생성)
AXFILTER_ADMIN_KEY=... AXFILTER_VIEWER_KEY=... AXFILTER_AGENT_KEY=... \
  axfilter serve --port 8000           # 키 생략 시 실행 때 임시 키 출력
axfilter show-config                   # 적용된 설정 확인(비밀값 마스킹)
python -m pytest                       # 41건 (SQLite 38 + 실 PostgreSQL 3; PG는 URL 없으면 skip)
```

| 역할 | 권한 |
|---|---|
| agent | `POST /v1/inspect` (프롬프트 검사) |
| viewer | 통계·이력·정책 조회 (원문 불가) |
| admin | 원문 열람(감사 로그 기록), 정책 변경, 감사 로그 검증 |

- 검출: 주민등록번호(날짜·체크섬), 카드번호(Luhn), 사업자번호(체크섬), 여권번호, 전화번호, 이메일,
  자격증명/비밀키(AWS·GitHub·Slack 토큰, 개인키 블록, JWT, `password=`류 대입), 사내 키워드
- 조치: 유형별 `allow / mask / block`, 서비스별 허용·차단, 그룹(CIDR)별 이용 시간
- 원문은 AES-256-GCM으로 암호화 저장, 관리자 열람과 정책 변경은 해시 체인 감사 로그에 기록
- 인증 무차별 대입 방어(IP별 실패 횟수 초과 시 잠금), 모든 응답에 보안 헤더(nosniff·DENY·no-store·CSP)
- 통계: 총 처리 / 검출 / 허용(allow+mask) / 차단 / 마스킹, 일별·서비스별·그룹별·IP별 Top
- **봉투 암호화**: 마스터 키(로컬 또는 AWS KMS)가 DB별 데이터 키(DEK)를 감싸고, DB에는 감싼 DEK만 저장
  - 로컬: `AXFILTER_DATA_KEY`(hex 64자) 또는 `data/data.key`(0600)
  - KMS: `AXFILTER_KEY_PROVIDER=awskms AXFILTER_KMS_KEY_ID=alias/...` (boto3 필요, EncryptionContext 적용)
  - 키 교체: `POST /v1/keys/rotate` (admin) — 새 DEK 생성 후 모든 원문을 한 트랜잭션에서 재암호화, 감사 로그 기록
- **TLS**: `./gen_dev_cert.sh`로 개발용 인증서 생성 후 `axfilter serve --ssl-certfile --ssl-keyfile`
  - `AXFILTER_REQUIRE_TLS=1`이면 평문 HTTP를 426으로 거부, HTTPS 응답에 HSTS 추가
  - TLS 종단 프록시 뒤에서는 `AXFILTER_TRUSTED_PROXY=1`로 `X-Forwarded-Proto` 신뢰
- **저장소**: SQLite(기본) 또는 **PostgreSQL** — `AXFILTER_DATABASE_URL`로 선택 (SQLAlchemy Core)
  - 마이그레이션: `alembic upgrade head` (SQLite·PostgreSQL 모두 검증)
- **설정**: 모든 환경변수는 `AXFILTER_` 접두사 (`axfilter/server/.env.example` 참고), pydantic-settings로 중앙 관리
- **로깅**: 구조화 JSON 로그 + 요청 ID. 프롬프트 원문·검출값은 로그에 남기지 않음(메타데이터만)

## deploy/
`docker-compose`로 PostgreSQL + API + nginx(TLS 종단, 대시보드 서빙) 한 묶음 실행. 기동 시 마이그레이션 자동 적용.
자세한 내용은 `deploy/README.md`.

## 한계
- 정규식·체크섬 기반이라 이름, 주소, 비정형 기밀은 검출하지 못함(NER/ML 미구현)
- SSO/인증 연동, 부하·고가용성 검증, 외부 보안 점검(모의해킹)은 미실시
- KMS 공급자는 가짜 클라이언트로만 검증, 실제 AWS 계정 미검증
- Docker 이미지·compose는 파일로 작성·검증(`docker compose config`)했으나 이 환경에선 데몬 미기동으로 컨테이너 실행은 미검증
- PostgreSQL 경로는 로컬 PostgreSQL 16으로 검증

## dashboard/
의존성 없는 단일 페이지 대시보드. 통계 API에 viewer 키로 연결하거나, 임베드된 합성 데모 데이터로 동작합니다.
`axfilter/server/seed_demo.py`로 데모 데이터를 채우고, API에 `AXFILTER_CORS_ORIGINS`를 설정하면 실데이터로 연결됩니다.

## extension/
Chrome(MV3) 확장. ChatGPT·Claude·Gemini에서 전송 전 프롬프트를 가로채 검사 API로 보내고 허용·마스킹·차단합니다.
`extension/test`의 `node unit.mjs`와 `node e2e.mjs`로 검증합니다. 자세한 내용은 `extension/README.md`.

## assetcheck/
자사 자산 노출 점검 (`assetcheck.py`): 위험 포트 개방 여부, HTTP Basic 기본 비밀번호 허용 여부.
스코프 파일(IP/CIDR, 최대 /24)과 `--confirm-authorized` 없이는 실행되지 않으며, 공인 IP는 `--allow-public`이 필요합니다.
소유했거나 서면으로 점검 권한을 받은 자산에만 사용하세요.

```
python3 assetcheck.py --scope scope.txt --confirm-authorized
python3 -m pytest
```
