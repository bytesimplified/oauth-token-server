"""Create isolated files for the test suite before importing application settings."""

import os
import tempfile
from pathlib import Path

TEST_DIR = tempfile.TemporaryDirectory()
os.environ["OAUTH_DB_URL"] = f"sqlite:///{TEST_DIR.name}/test.db"
os.environ["OAUTH_PRIVATE_KEY_PATH"] = str(Path(TEST_DIR.name) / "private.pem")
os.environ["OAUTH_ISSUER"] = "http://127.0.0.1:8000"
os.environ["OAUTH_AUDIENCE"] = "orders-api"
os.environ["OAUTH_TOKEN_TTL_SECONDS"] = "600"
os.environ["OAUTH_ALLOWED_SCOPES"] = "orders:read orders:write"

from app.crypto import generate_private_key  # noqa: E402

generate_private_key(os.environ["OAUTH_PRIVATE_KEY_PATH"])
