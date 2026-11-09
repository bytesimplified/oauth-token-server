import argparse
import secrets

from .config import settings
from .crypto import generate_private_key
from .db import OAuthClient, SessionLocal, hash_secret, init_db


def create_client(allowed_scopes: list[str], default_scopes: list[str]) -> tuple[str, str]:
    configured = set(settings.allowed_scopes.split())
    allowed, default = set(allowed_scopes), set(default_scopes)
    if not allowed or not allowed <= configured or not default <= allowed:
        raise ValueError("Scopes must be configured, defaults must be a subset of allowed scopes")
    client_id = "cli_" + secrets.token_urlsafe(18)
    client_secret = "sec_" + secrets.token_urlsafe(32)
    init_db()
    with SessionLocal.begin() as db:
        db.add(OAuthClient(
            client_id=client_id, secret_hash=hash_secret(client_secret),
            scopes=" ".join(sorted(allowed)), default_scopes=" ".join(sorted(default)), active=True,
        ))
    return client_id, client_secret


def deactivate_client(client_id: str) -> None:
    init_db()
    with SessionLocal.begin() as db:
        client = db.get(OAuthClient, client_id)
        if client is None:
            raise ValueError("Client not found")
        client.active = False


def rotate_client_secret(client_id: str) -> str:
    """Replace an active client's secret, immediately invalidating its prior secret."""
    init_db()
    new_secret = "sec_" + secrets.token_urlsafe(32)
    with SessionLocal.begin() as db:
        client = db.get(OAuthClient, client_id)
        if client is None or not client.active:
            raise ValueError("Active client not found")
        client.secret_hash = hash_secret(new_secret)
    return new_secret


def list_clients() -> list[tuple[str, str, bool]]:
    """Return identifiers and permitted scopes, never client secrets."""
    init_db()
    with SessionLocal() as db:
        return [(c.client_id, c.scopes, c.active) for c in db.query(OAuthClient).order_by(OAuthClient.client_id)]


def main() -> None:
    parser = argparse.ArgumentParser(description="OAuth 2.0 administration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("generate-keys", help="Create an RSA private signing key if one does not exist")
    creation = sub.add_parser("create-client", help="Register a new client and print its credentials ONCE")
    creation.add_argument("--scopes", nargs="+", required=True)
    creation.add_argument("--default-scopes", nargs="*", default=[])
    deletion = sub.add_parser("deactivate-client", help="Disable new token issuance for a client")
    deletion.add_argument("client_id")
    rotation = sub.add_parser("rotate-client-secret", help="Immediately replace one active client's secret")
    rotation.add_argument("client_id")
    sub.add_parser("list-clients", help="Print IDs, scopes and active status (never secrets)")
    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_private_key(settings.private_key_path)
        print("Generated private signing key at:", settings.private_key_path)
    elif args.command == "create-client":
        client_id, client_secret = create_client(args.scopes, args.default_scopes)
        print("CLIENT_ID=" + client_id)
        print("CLIENT_SECRET=" + client_secret)
        print("Store CLIENT_SECRET securely; this is the only time it will be shown.")
    elif args.command == "deactivate-client":
        deactivate_client(args.client_id)
        print("Client deactivated. Previously issued JWTs remain valid until expiration.")
    elif args.command == "rotate-client-secret":
        print("NEW_CLIENT_SECRET=" + rotate_client_secret(args.client_id))
        print("Previous secret is invalid immediately. Store the new value securely; shown only once.")
    elif args.command == "list-clients":
        for client_id, scopes, active in list_clients():
            print(f"{client_id}\t{'ACTIVE' if active else 'INACTIVE'}\t{scopes}")


if __name__ == "__main__":
    main()
