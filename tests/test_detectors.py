from camroll_check.detectors import scan_text

def kinds(t): return {f.kind for f in scan_text(t)}

def test_seed():
    assert "seed_phrase" in kinds(" ".join(["abandon"] * 11 + ["about"]))

def test_card_luhn():
    assert "payment_card" in kinds("4111 1111 1111 1111")
    assert "payment_card" not in kinds("4111 1111 1111 1112")

def test_iban():
    assert "iban" in kinds("GB82 WEST 1234 5698 7654 32")
    assert "iban" not in kinds("GB00 WEST 1234 5698 7654 32")

def test_keys():
    assert "github_token" in kinds("ghp_" + "a" * 36)
    assert "aws_key" in kinds("AKIAIOSFODNN7EXAMPLE")

def test_no_false_positives_on_prose():
    prose = ("we went to the beach about noon and it was a great day, all of us "
             "had lunch, my order number is 2024 0815 and the phone is +420 777 123 456. "
             "call me after ten, the movie starts at nine.")
    assert kinds(prose) == set()

def test_password_label():
    assert "password" in kinds("wifi password: hunter22")
