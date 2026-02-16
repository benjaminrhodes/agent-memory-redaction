"""Tests for PII redaction."""

from src.redactor import Redactor, PIIType


class TestEmailRedaction:
    def test_redact_email_simple(self):
        redactor = Redactor()
        text = "Contact john@example.com for help"
        result = redactor.redact(text)
        assert "john@example.com" not in result
        assert "[EMAIL]" in result

    def test_redact_email_multiple(self):
        redactor = Redactor()
        text = "Email jane@test.org or bob@company.net"
        result = redactor.redact(text)
        assert "jane@test.org" not in result
        assert "bob@company.net" not in result

    def test_redact_email_subdomains(self):
        redactor = Redactor()
        text = "Reach out to admin@mail.server.co.uk"
        result = redactor.redact(text)
        assert "admin@mail.server.co.uk" not in result


class TestPhoneRedaction:
    def test_redact_phone_us(self):
        redactor = Redactor()
        text = "Call 555-123-4567 for support"
        result = redactor.redact(text)
        assert "555-123-4567" not in result
        assert "[PHONE]" in result

    def test_redact_phone_parentheses(self):
        redactor = Redactor()
        text = "Call (555) 123-4567"
        result = redactor.redact(text)
        assert "(555) 123-4567" not in result

    def test_redact_phone_international(self):
        redactor = Redactor()
        text = "Call +1-555-123-4567"
        result = redactor.redact(text)
        assert "+1-555-123-4567" not in result


class TestSSNRedaction:
    def test_redact_ssn(self):
        redactor = Redactor()
        text = "SSN: 123-45-6789"
        result = redactor.redact(text)
        assert "123-45-6789" not in result
        assert "[SSN]" in result

    def test_redact_ssn_no_dashes(self):
        redactor = Redactor()
        text = "SSN 123456789"
        result = redactor.redact(text)
        assert "123456789" not in result


class TestCreditCardRedaction:
    def test_redact_credit_card_visa(self):
        redactor = Redactor()
        text = "Card: 4111-1111-1111-1111"
        result = redactor.redact(text)
        assert "4111-1111-1111-1111" not in result
        assert "[CREDIT_CARD]" in result

    def test_redact_credit_card_no_dashes(self):
        redactor = Redactor()
        text = "Card 5555555555554444"
        result = redactor.redact(text)
        assert "5555555555554444" not in result


class TestAPIKeyRedaction:
    def test_redact_api_key(self):
        redactor = Redactor()
        text = "API key: sk-abc123xyz"
        result = redactor.redact(text)
        assert "sk-abc123xyz" not in result
        assert "[API_KEY]" in result

    def test_redact_api_key_long(self):
        redactor = Redactor()
        text = "Key: sk_test_51HxYZabcdefghijklmnop123456"
        result = redactor.redact(text)
        assert "sk_test_" not in result


class TestIPAddressRedaction:
    def test_redact_ipv4(self):
        redactor = Redactor()
        text = "Server at 192.168.1.100"
        result = redactor.redact(text)
        assert "192.168.1.100" not in result
        assert "[IP_ADDRESS]" in result

    def test_redact_ipv6(self):
        redactor = Redactor()
        text = "Server: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = redactor.redact(text)
        assert "2001:0db8" not in result


class TestAWSKeyRedaction:
    def test_redact_aws_access_key(self):
        redactor = Redactor()
        text = "AWS Access Key: AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[AWS_KEY]" in result

    def test_redact_aws_secret_key(self):
        redactor = Redactor()
        text = "Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = redactor.redact(text)
        assert "wJalrXUtnFEMI" not in result


class TestURLRedaction:
    def test_redact_url_with_token(self):
        redactor = Redactor()
        text = "Visit https://api.example.com/v1?token=abc123xyz"
        result = redactor.redact(text)
        assert "token=abc123xyz" not in result
        assert "[URL]" in result

    def test_redact_url_with_api_key(self):
        redactor = Redactor()
        text = "URL: https://service.com/api?key=secret123"
        result = redactor.redact(text)
        assert "key=secret123" not in result


class TestNameRedaction:
    def test_redact_name(self):
        redactor = Redactor()
        text = "John Smith works here"
        result = redactor.redact(text)
        assert "John Smith" not in result
        assert "[NAME]" in result

    def test_redact_name_with_context(self):
        redactor = Redactor()
        text = "Contact Jane Doe for support"
        result = redactor.redact(text)
        assert "Jane Doe" not in result


class TestAddressRedaction:
    def test_redact_address(self):
        redactor = Redactor()
        text = "Send to 123 Main Street, New York, NY 10001"
        result = redactor.redact(text)
        assert "123 Main Street" not in result
        assert "[ADDRESS]" in result


class TestRedactorOptions:
    def test_redact_specific_pii_types(self):
        redactor = Redactor(pii_types=[PIIType.EMAIL, PIIType.PHONE])
        text = "Email test@example.com or call 555-123-4567"
        result = redactor.redact(text)
        assert "test@example.com" not in result
        assert "555-123-4567" not in result

    def test_redact_preserve_non_pii(self):
        redactor = Redactor()
        text = "Hello world, this is a test"
        result = redactor.redact(text)
        assert result == text


class TestCLI:
    def test_cli_with_text(self, capsys, monkeypatch):
        from src.cli import main

        monkeypatch.setattr("sys.argv", ["cli", "Contact john@example.com"])
        main()
        captured = capsys.readouterr()
        assert "[EMAIL]" in captured.out

    def test_cli_with_pii_types(self, capsys, monkeypatch):
        from src.cli import main

        monkeypatch.setattr("sys.argv", ["cli", "john@example.com", "--pii-types", "email"])
        main()
        captured = capsys.readouterr()
        assert "[EMAIL]" in captured.out

    def test_cli_stdin(self, capsys, monkeypatch):
        from src.cli import main

        monkeypatch.setattr("sys.argv", ["cli"])
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO("test@example.com"))
        main()
        captured = capsys.readouterr()
        assert "[EMAIL]" in captured.out


class TestRedactionEdgeCases:
    def test_empty_string(self):
        redactor = Redactor()
        result = redactor.redact("")
        assert result == ""

    def test_no_pii_found(self):
        redactor = Redactor()
        text = "Just some regular text without any PII"
        result = redactor.redact(text)
        assert result == text

    def test_overlapping_pii(self):
        redactor = Redactor()
        text = "test@test.com and 555-555-5555"
        result = redactor.redact(text)
        assert "@" not in result.split("[EMAIL]")[0] or "@" in result.split("[EMAIL]")[-1]
