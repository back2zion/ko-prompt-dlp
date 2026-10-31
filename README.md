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
| admin | 원문 열람(감사 로그 기록), 정책 변경, 감사 로그 검증·검색, 정책 변경 이력, **컴플라이언스 증적 리포트** |

- 검출: 주민등록번호(날짜·체크섬), 카드번호(Luhn), 사업자번호(체크섬), 여권번호, 전화번호, 이메일,
  자격증명/비밀키(AWS·GitHub·Slack 토큰, 개인키 블록, JWT, `password=`류 대입), **한국어 이름·주소(문맥·사전 기반)**, 사내 키워드
  - 이름/주소는 신뢰도 점수를 가지며, `Policy.detect_names`/`detect_addresses`로 끌 수 있음
  - 외부 NER 모델(트랜스포머·Presidio 등)을 `recognizers.recognize(extra=[...])`로 꽂을 수 있는 구조
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

### 인증·연동 (SSO / SIEM)
- **SSO(OIDC)**: API 키에 더해 `Authorization: Bearer <JWT>` 허용. IdP의 JWKS로 RS256 검증, iss/aud/exp 확인,
  그룹 클레임→역할 매핑(`AXFILTER_OIDC_ROLE_MAP`). 감사로그의 행위자가 토큰의 이메일/서브젝트로 기록됨.
  (`AXFILTER_OIDC_ISSUER/AUDIENCE/JWKS_URL/ROLE_CLAIM/ROLE_MAP`, 폐쇄망은 `OIDC_JWKS_JSON` 인라인)
- **SIEM 연동**: 검사·감사 이벤트를 **CEF / RFC5424 syslog / JSON**으로 전송(file 또는 UDP). 
  **메타데이터만 전송**(서비스·사용자·IP·검출유형·조치·요청ID) — 프롬프트 원문·검출값은 제외.
  (`AXFILTER_SIEM_SINK/FORMAT/TARGET`)

### 컴플라이언스 증적
ISMS-P / ISO 27001 심사 대응용 증적 자료를 생성합니다(인증 보장이 아닌 **증적 자료**이며 통제 매핑은 참고용).
- `GET /v1/compliance/report?period=&framework=` — 서명(HMAC-SHA256)된 JSON 리포트
- `GET /v1/compliance/report.csv` — 통제 매핑 CSV / `POST /v1/compliance/verify` — 서명 검증
- `GET /v1/policy/history` — 정책 변경 이력(버전·변경자·해시) / `GET /v1/audit/search` — 감사로그 검색(행위자·행위·기간)
- CLI: `axfilter report --framework ISMS-P --csv`
- 증적 내용: RBAC·원문열람 이력, 저장 암호화·키공급자, 감사 해시체인 검증 결과, 전송구간 TLS,
  마스킹·차단 통계, 정책 변경 이력 → ISMS-P 2.5/2.7/2.9.4/2.10/3.2/1.2, ISO A.8.24/A.8.15/A.5.15/A.8.11에 매핑
- 리포트 생성 자체도 감사로그(`EXPORT_COMPLIANCE_REPORT`)에 기록

### 탐지 품질 벤치마크
`axfilter bench`로 라벨 데이터셋(합성, `bench/dataset.jsonl`) 대비 유형별 정밀도·재현율·F1을 측정합니다.
현재 결과(규칙·사전 기반):

| 유형 | 정밀도 | 재현율 | 비고 |
|---|---|---|---|
| 주민·카드·이메일·전화·사업자·여권·비밀키 | 1.00 | 1.00 | 정규식 + 체크섬 |
| 이름(NAME) | 1.00 | 0.80 | 문맥 단서(이름:/담당자/님/과장…) 필요, 맨이름은 누락 |
| 주소(ADDRESS) | 1.00 | 0.50 | 시/군/구 없는 자유형 도로명은 누락 |
| 전체 | 1.00 | 0.86 | F1 0.92, 오탐 0 |

이름/주소의 재현율 격차는 **정밀도 우선 규칙 설계의 한계**이며, 학습된 NER 모델을 꽂으면 올라갈 지점입니다.
`bench/make_dataset.py`가 스팬을 정확히 계산해 데이터셋을 생성하고, `tests/test_bench.py`가 품질 회귀를 막습니다.

## deploy/
`docker-compose`로 PostgreSQL + API + nginx(TLS 종단, 대시보드 서빙) 한 묶음 실행. 기동 시 마이그레이션 자동 적용.
자세한 내용은 `deploy/README.md`.

## 한계
- 이름·주소는 규칙·사전 기반이라 재현율이 제한적(NER 모델 미탑재, 다만 플러그인 구조 제공). 벤치마크 수치는 합성 데이터 기준으로 실제 분포와 다를 수 있음
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
