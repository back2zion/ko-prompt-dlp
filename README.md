# AX Filter (v0.2.0)

생성형 AI 프롬프트의 **개인정보·자격증명 유출 방지** 솔루션. 프롬프트를 전송 전 검사해
마스킹·차단하고, 정책·감사·컴플라이언스·멀티테넌시·강제 차단(게이트웨이)까지 갖춘 프로토타입.
데모/연구용이며, 실제 판매 전에는 실환경 검증·보안 점검·인증이 필요합니다(아래 '한계' 참고).

구성: `server/`(검사 API) · `dashboard/`(통계+관리자 콘솔) · `extension/`(크롬 MV3) ·
`assetcheck/`(자산 점검) · `deploy/`(docker-compose·AWS) · `security/`(위협모델·점검).

## server/
FastAPI 기반 검사 API.

```
cd axfilter/server
pip install -e ".[postgres,dev]"       # 패키지 설치 (콘솔 명령 axfilter 생성)
AXFILTER_ADMIN_KEY=... AXFILTER_VIEWER_KEY=... AXFILTER_AGENT_KEY=... \
  axfilter serve --port 8000           # 키 생략 시 실행 때 임시 키 출력
axfilter show-config                   # 적용된 설정 확인(비밀값 마스킹)
python -m pytest                       # 97건 (SQLite) / 101건 (실 PostgreSQL 포함, URL 없으면 PG 4건 skip)
```

| 역할 | 권한 |
|---|---|
| agent | `POST /v1/inspect` (프롬프트 검사) |
| viewer | 통계·이력·정책 조회 (원문 불가) |
| admin | 원문 열람(감사됨), 정책 변경, 감사 검증·검색, 정책 이력, 컴플라이언스 리포트, **API키 발급/회수**, **보존·파기 실행** |

인증: 역할별 정적 API 키(`X-API-Key`) 또는 **OIDC 베어러(SSO)** 또는 **DB 발급 명명 키**(`axfilter apikey`). 멀티테넌시는 `X-Tenant` 헤더.

- 검출: 주민등록번호(날짜·체크섬), 카드번호(Luhn), 사업자번호(체크섬), 여권번호, 전화번호, 이메일,
  자격증명/비밀키(AWS·GitHub·Slack 토큰, 개인키 블록, JWT, `password=`류 대입), **한국어 이름·주소(문맥·사전 기반)**, 사내 키워드
  - 이름/주소는 신뢰도 점수를 가지며, `Policy.detect_names`/`detect_addresses`로 끌 수 있음
  - 외부 NER 모델을 `detect(text, extra=[...])` / `recognizers.recognize(extra=[...])`로 꽂는 구조
  - **트랜스포머 NER 어댑터**(`ner_models.TransformerNerRecognizer`): HF 토큰분류 파이프라인의 라벨(PS/PER→이름, LC/LOC→주소)을 매핑.
    `pip install "axfilter[ner]"` 후 `axfilter bench --ner-model <모델명>`으로 모델 포함 성능 측정.
    *단, 모델 가중치 다운로드가 필요해 모델 접근이 가능한 환경에서 실행해야 함. 본 저장소에서는 어댑터·라벨매핑·병합 로직만 스텁 파이프라인으로 단위 검증(실모델 미구동).*
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

### 운영·관리 기능 (v0.2)
- **레이트리밋·쿼터**: 클라이언트별 토큰버킷 + 일일 쿼터, 초과 시 429 + `Retry-After` (`AXFILTER_RATE_PER_SEC/DAY`, 0=무제한)
- **멀티테넌시**: `X-Tenant` 헤더로 이벤트·정책·통계·정책이력을 테넌트별 격리. 기본 테넌트는 기존과 동일, 기존 DB는 런타임 ALTER로 자동 이행
- **데이터 보존·파기**: `POST /v1/retention/run`(admin) 및 `axfilter purge` — 원문은 N일 후 파기, 이벤트는 선택적 파기. 감사로그는 추가전용으로 보존 (`AXFILTER_RETENTION_ORIGINAL_DAYS/EVENT_DAYS`)
- **명명 API 키 관리**: `POST/GET/DELETE /v1/keys`(admin), `axfilter apikey issue|revoke|list` — 토큰은 해시만 저장하고 발급 시 1회만 노출, 발급/회수 감사
- **관리자 콘솔**: `dashboard/admin.html` — 정책 편집·이력·감사 검색·원문 열람(경고·감사)·컴플라이언스 리포트
- **대시보드 드릴다운**: 검출 유형별 순위, 최근 이벤트 테이블(필터·페이지네이션), 서비스/그룹/IP 행 클릭 필터

### 강제 차단 (이그레스 게이트웨이 / 네트워크 프록시)
확장은 사용자가 끌 수 있어 우회 가능합니다. 서버·앱 트래픽까지 강제하려면:
- **LLM 이그레스 게이트웨이**(`/gateway/v1/chat/completions`): 사내 앱의 OpenAI `base_url`을 이 게이트웨이로 지정.
  프롬프트를 검사해 **차단은 업스트림 미도달(403), 마스킹은 치환 후 전달, 허용은 통과**. 공급자 API 키는 게이트웨이가 주입.
  공급자로의 egress를 게이트웨이로만 제한하면 호출 앱이 우회할 수 없음. (`AXFILTER_GATEWAY_UPSTREAM`, `AXFILTER_GATEWAY_UPSTREAM_KEY`)
- **투명 프록시**(`deploy/mitmproxy_addon.py`): 브라우저 포함 모든 egress를 가로채는 옵션. mitmproxy CA를 단말에 배포(MDM) 필요,
  TLS 가로채기는 정책·법령 준수 전제. *이 저장소 테스트로는 미검증(라이브 프록시·단말 필요).*

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

## 보안·인증 준비 (security/, deploy/aws/)
- **SAST/의존성 스캔**: `security/scan.sh` — bandit(MED/HIGH 0건) + pip-audit(**axfilter 의존성 취약점 0건**)
- **문서**: 위협모델(STRIDE), 보안 자가점검(코드 매핑), 모의해킹 ROE, 인증 준비(GS/ISMS-P/CC/조달) — `security/`
- **AWS KMS**: Terraform(KMS 키·최소권한 IAM) + `verify_aws_kms.py`(실계정 wrap/unwrap·EncryptionContext 검증) — `deploy/aws/`
- **실모델 NER 벤치**: 권장 모델·라벨맵·실행법 — `server/bench/NER_MODELS.md`, `axfilter bench --ner-model <모델>`
- **CI**(`.github/workflows/axfilter-ci.yml`): 테스트(SQLite+PostgreSQL) + bandit + pip-audit, main 푸시 시 실 AWS KMS 검증(OIDC 역할 구성 시)

> 실제 AWS 계정 검증·실모델 벤치·모의해킹·GS/ISMS-P/CC 인증은 **코드로 끝나지 않는 환경/조직 영역**입니다.
> 위 준비물은 그 작업을 턴키로 만들기 위한 것이며, 본 저장소에서 실행 검증한 것은 SAST·의존성 스캔·moto 기반 KMS 검증까지입니다.

## 한계
- 이름·주소는 규칙·사전 기반이라 재현율이 제한적. 트랜스포머 NER 어댑터를 제공하나 **실제 모델은 미구동**(HuggingFace 접근 차단 환경) — 어댑터·라벨매핑·병합만 단위 검증. 벤치마크 수치는 합성 데이터 기준
- 부하·고가용성 검증, 외부 보안 점검(모의해킹)은 미실시
- AWS KMS는 **moto(인프로세스 KMS, 실제 boto3 경로·EncryptionContext 강제)로 검증**; 실제 AWS 계정은 미검증
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
