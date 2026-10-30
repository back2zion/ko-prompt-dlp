from axfilter.detector import detect, mask


def make_rrn(prefix12: str) -> str:
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    c = (11 - sum(int(a) * b for a, b in zip(prefix12, w)) % 11) % 10
    return prefix12 + str(c)


def types(text, kw=None):
    return [f.type for f in detect(text, kw)]


def test_rrn_with_hyphen_and_checksum():
    r = make_rrn("900101123456")
    assert types(f"주민번호 {r[:6]}-{r[6:]} 입니다") == ["RRN"]
    assert types(f"번호 {r}") == ["RRN"]  # bare, checksum valid


def test_rrn_bare_with_bad_checksum_ignored_but_hyphenated_accepted():
    assert types("1234567890123") == []
    assert types("900101-1234567") == ["RRN"]  # post-2020 numbers have no checksum


def test_rrn_invalid_date_rejected():
    assert types("901301-1234567") == []


def test_card_luhn():
    assert types("카드 4539 1488 0343 6467 결제") == ["CARD"]
    assert types("카드 4539 1488 0343 6468") == []


def test_bizno_and_phone_and_email():
    assert types("사업자 220-81-62517") == ["BIZNO"]
    assert types("연락처 010-1234-5678") == ["PHONE"]
    assert types("02-123-4567") == ["PHONE"]
    assert types("a.b@example.co.kr") == ["EMAIL"]


def test_keywords_case_insensitive_and_multiple():
    f = detect("Project Falcon과 project falcon", ["project falcon"])
    assert [x.type for x in f] == ["KEYWORD", "KEYWORD"]


def test_no_false_positive_on_plain_text():
    assert types("2026년 10월 28일 매출 12,345,678원, 주문번호 20261028") == []


def test_mask_replaces_with_labels():
    t = "메일 a@b.com 전화 010-1234-5678"
    assert mask(t, detect(t)) == "메일 [이메일] 전화 [전화번호]"


def test_mask_only_selected_types():
    t = "a@b.com 010-1234-5678"
    assert mask(t, detect(t), {"EMAIL"}) == "[이메일] 010-1234-5678"


def test_passport_detected():
    assert types("여권 M12345678 소지") == ["PASSPORT"]
    assert types("코드 Z12345678") == []  # not a passport letter


def test_secret_aws_key_blocked_type():
    assert types("key AKIAIOSFODNN7EXAMPLE here") == ["SECRET"]


def test_secret_private_key_header():
    assert types("-----BEGIN RSA PRIVATE KEY-----") == ["SECRET"]


def test_secret_key_value_assignment():
    assert types("password = s3cr3tValue") == ["SECRET"]
    assert types('api_key: "abcdef123456"') == ["SECRET"]


def test_secret_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456"
    assert "SECRET" in types(f"token {jwt}")


def test_mask_passport_and_secret_labels():
    t = "여권 M12345678 키 AKIAIOSFODNN7EXAMPLE"
    assert mask(t, detect(t)) == "여권 [여권번호] 키 [자격증명/비밀키]"
