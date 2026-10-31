#!/usr/bin/env python3
"""Validate the AX Filter KMS provider against a REAL AWS account.

Requires AWS credentials (env/role/profile) and a KMS key the caller may use.
Run in an environment with AWS network access (this repo's CI or your laptop):

    AXFILTER_KMS_KEY_ID=alias/axfilter-dek AWS_REGION=ap-northeast-2 \
        python deploy/aws/verify_aws_kms.py

It performs the same checks the moto tests run, but against live KMS:
wrap/unwrap roundtrip and EncryptionContext enforcement. Exit 0 = pass.
"""
import os
import sys

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "server"))
from axfilter.keys import AwsKmsKeyProvider  # noqa: E402


def main() -> int:
    key_id = os.environ.get("AXFILTER_KMS_KEY_ID")
    if not key_id:
        print("set AXFILTER_KMS_KEY_ID", file=sys.stderr)
        return 2
    kms = boto3.client("kms")
    prov = AwsKmsKeyProvider(key_id, client=kms)

    dek = os.urandom(32)
    blob = prov.wrap(dek)
    assert prov.unwrap(blob) == dek, "roundtrip failed"
    print("roundtrip OK (wrap/unwrap under EncryptionContext app=axfilter)")

    try:
        kms.decrypt(CiphertextBlob=blob, EncryptionContext={"app": "evil"})
        print("FAIL: wrong EncryptionContext was accepted", file=sys.stderr)
        return 1
    except kms.exceptions.InvalidCiphertextException:
        print("EncryptionContext enforcement OK (wrong context rejected)")
    print("REAL AWS KMS validation: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
