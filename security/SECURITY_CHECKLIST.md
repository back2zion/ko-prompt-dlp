# 보안 자가점검 (코드 매핑)

| 항목 | 상태 | 근거 |
|---|---|---|
| 인증 | ✅ | API 키(hmac.compare_digest) + OIDC 베어러(oidc.py) |
| 인가(최소권한) | ✅ | 역할 랭크 검사; KMS IAM Encrypt/Decrypt 한정 |
| 저장 암호화 | ✅ | AES-256-GCM + 봉투암호화(keys.py), moto 검증 |
| 전송 암호화 | ✅ | TLS 강제·HSTS(require_tls), nginx 종단 |
| 키 관리 | ◐ | KMS 봉투+교체 구현; **리포트 서명키 분리 권장** |
| 비밀 정보 로깅 금지 | ✅ | 로그·SIEM 메타데이터만; 테스트로 원문 미유출 확인 |
| 감사·부인방지 | ✅ | 해시체인 감사, 정책 이력, 원문열람 기록 |
| 입력 검증 | ✅ | pydantic 모델(길이·타입), 쿼리 Literal/범위 |
| 무차별 대입 방어 | ✅ | IP별 실패 잠금(app.py) |
| 보안 헤더 | ✅ | nosniff·DENY·no-store·CSP·HSTS |
| SAST | ✅ | bandit 0건(HIGH/MED/LOW) |
| 의존성 취약점 | ✅ | pip-audit: axfilter 의존성 무취약(베이스 이미지 무관 패키지 제외) |
| 레이트리밋/쿼터 | ❌ | 미구현 — 앞단 게이트/WAF 필요 |
| 멀티테넌시 격리 | ❌ | 단일 테넌트 전제 |
| 침투 테스트 | ❌ | 외부 수행 필요(PENTEST_SCOPE.md) |

✅ 충족 / ◐ 부분 / ❌ 미구현
