# AX필터 배포 (docker-compose)

PostgreSQL + API + nginx(TLS 종단, 대시보드 서빙) 한 묶음.

## 실행
```
cd server && cp .env.example .env     # 키·비밀번호 채우기
cd ../server && ./gen_dev_cert.sh ../deploy/certs   # 개발용 인증서 (운영은 CA 발급 인증서)
cd ../deploy && POSTGRES_PASSWORD=... docker compose up --build
```
- 대시보드/API: https://localhost:8443 (자체 서명 인증서면 브라우저 경고 수락)
- API는 nginx 뒤에서 `AXFILTER_REQUIRE_TLS=1` + `AXFILTER_TRUSTED_PROXY=1`로 동작
- 기동 시 `alembic upgrade head`로 스키마 자동 적용

## 운영 메모
- 마스터 키는 `.env`의 `AXFILTER_DATA_KEY` 대신 **AWS KMS**(`AXFILTER_KEY_PROVIDER=awskms`) 권장
- 인증서는 CA 발급분을 `deploy/certs/`에 배치
- 대시보드에서 통계 조회 시 viewer 키 입력(같은 호스트이므로 CORS 불필요)
