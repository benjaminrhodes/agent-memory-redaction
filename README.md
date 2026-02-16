# Agent Memory Redaction

Redact sensitive data from agent memory/context.

## Features

- Scan agent memory for PII
- Redact sensitive data
- Support multiple PII types:
  - Email addresses
  - Phone numbers (US)
  - Social Security Numbers (SSN)
  - Credit card numbers
  - API keys (sk-*, api_*)
  - IP addresses (IPv4, IPv6)
  - AWS access keys
  - URLs with tokens/secrets
  - Names (First Last format)
  - Street addresses

## Usage

```bash
# Install
pip install agent-memory-redaction

# Redact all PII from text
python -m src.cli "Contact john@example.com or call 555-123-4567"

# Redact specific PII types
python -m src.cli --pii-types email phone "Email test@example.com"

# Read from stdin
echo "Email: john@example.com" | python -m src.cli
```

## Testing

```bash
pytest tests/ -v
```

## Security

- Uses synthetic/test data only
- No real credentials or production systems

## License

MIT
