.PHONY: test

test:
cd /opt/vpnztna/api && \
DISABLE_RATELIMIT=true \
TEST_DATABASE_URL=postgresql+asyncpg://vpnztna:changeme@localhost:5432/vpnztna_test \
PYTHONPATH=. ../.venv/bin/python -m pytest tests/ -v
