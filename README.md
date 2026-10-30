# AX Filter prototype

생성형 AI 프롬프트 개인정보 검출·마스킹·차단 프로토타입 (서버 핵심) + 자사 자산 점검 도구.
데모/연구용이며 프로덕션 보안 제품이 아닙니다.

## server/
FastAPI 기반 검사 API.

```
cd axfilter/server
pip install -r requirements.txt
AXFILTER_ADMIN_KEY=... AXFILTER_VIEWER_KEY=... AXFILTER_AGENT_KEY=... \
  uvicorn main:app --port 8000      # 키를 생략하면 실행 시 임시 키를 출력
python -m pytest
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
- `AXFILTER_DATA_KEY`(hex 64자)로 데이터 키 지정, 미지정 시 `data/data.key`(0600) 생성

## 한계
- 정규식·체크섬 기반이라 이름, 주소, 비정형 기밀은 검출하지 못함
- 데이터 키 관리(KMS), TLS, 인증 연동, 부하 검증은 미구현

## assetcheck/
자사 자산 노출 점검 (`assetcheck.py`): 위험 포트 개방 여부, HTTP Basic 기본 비밀번호 허용 여부.
스코프 파일(IP/CIDR, 최대 /24)과 `--confirm-authorized` 없이는 실행되지 않으며, 공인 IP는 `--allow-public`이 필요합니다.
소유했거나 서면으로 점검 권한을 받은 자산에만 사용하세요.

```
python3 assetcheck.py --scope scope.txt --confirm-authorized
python3 -m pytest
```
