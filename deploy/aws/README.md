# AWS KMS 설정·검증

1. `terraform init && terraform apply` — KMS 키·별칭·최소권한 IAM 생성
2. 앱에 적용: `AXFILTER_KEY_PROVIDER=awskms AXFILTER_KMS_KEY_ID=$(terraform output -raw kms_key_id)`
3. **실계정 검증**: AWS 자격증명이 있는 환경에서
   `AXFILTER_KMS_KEY_ID=alias/axfilter-dek python verify_aws_kms.py`
   — wrap/unwrap 왕복과 EncryptionContext 강제를 실 KMS로 확인(인프로세스 moto 검증과 동일 항목).

IAM은 `kms:Encrypt/Decrypt/DescribeKey`만, 그리고 `EncryptionContext:app=axfilter` 조건에서만 허용(최소권한).
