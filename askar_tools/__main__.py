"""Askar wallet tools."""

import argparse
import asyncio
import logging
import sys
from urllib.parse import urlparse

from askar_tools.error import InvalidArgumentsError
from askar_tools.exporter import Exporter
from askar_tools.mediator_converter import MediatorConverter
from askar_tools.multi_wallet_converter import MultiWalletConverter
from askar_tools.pg_connection import PgConnection
from askar_tools.sqlite_connection import SqliteConnection
from askar_tools.tenant_importer import TenantImporter, TenantImportObject


def config():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser("askar-wallet-tools")

    # Strategy
    parser.add_argument(
        "--strategy",
        required=True,
        choices=["export", "mt-convert-to-mw", "tenant-import", "mediator-convert"],
        help=(
            "Specify migration strategy depending on database type, wallet "
            "management mode, and agent type."
        ),
    )

    # Main wallet
    parser.add_argument(
        "--uri",
        required=True,
        help=("Specify URI of database to be migrated."),
    )
    parser.add_argument(
        "--wallet-name",
        required=True,
        type=str,
        help=(
            "Specify name of wallet to be migrated for DatabasePerWallet "
            "(export) migration strategy."
        ),
    )
    parser.add_argument(
        "--wallet-key",
        required=True,
        type=str,
        help=(
            "Specify key corresponding to the given name of the wallet to "
            "be migrated for database per wallet (export) migration strategy."
        ),
    )
    parser.add_argument(
        "--wallet-key-derivation-method",
        type=str,
        help=("Specify key derivation method for the wallet. Default is 'ARGON2I_MOD'."),
        default="ARGON2I_MOD",
    )

    # Export
    parser.add_argument(
        "--export-filename",
        type=str,
        help=(
            "Specify the filename to export the data to. Default is 'wallet_export.json'."
        ),
        default="wallet_export.json",
    )

    # Multiwallet conversion
    parser.add_argument(
        "--multitenant-sub-wallet-name",
        type=str,
        help=(
            "The existing wallet name for a multitenant single wallet conversion."
            "The default if not provided is 'multitenant_sub_wallet'"
        ),
        default="multitenant_sub_wallet",
    )

    # Tenant import
    parser.add_argument(
        "--tenant-uri",
        help=("Specify URI of the tenant database to be imported."),
    )
    parser.add_argument(
        "--tenant-wallet-name",
        type=str,
        help=("Specify name of tenant wallet to be imported."),
    )
    parser.add_argument(
        "--tenant-wallet-key",
        type=str,
        help=("Specify key corresponding of the tenant wallet to be imported."),
    )
    parser.add_argument(
        "--tenant-wallet-key-derivation-method",
        type=str,
        help=(
            "Specify key derivation method for the tenant wallet. Default is 'ARGON2I_MOD'."
        ),
        default="ARGON2I_MOD",
    )
    parser.add_argument(
        "--tenant-wallet-type",
        type=str,
        help=(
            """Specify the wallet type of the tenant wallet. Either 'askar' 
              or 'askar-anoncreds'. Default is 'askar'."""
        ),
        default="askar",
    )
    parser.add_argument(
        "--tenant-label",
        type=str,
        help=("Specify the label for the tenant wallet."),
    )
    parser.add_argument(
        "--tenant-image-url",
        type=str,
        help=("Specify the image URL for the tenant wallet."),
    )
    parser.add_argument(
        "--tenant-webhook-urls",
        type=list,
        help=("Specify the webhook URLs for the tenant wallet."),
    )
    parser.add_argument(
        "--tenant-extra-settings",
        type=dict,
        help=("Specify extra settings for the tenant wallet."),
    )
    parser.add_argument(
        "--tenant-dispatch-type",
        type=str,
        help=("Specify the dispatch type for the tenant wallet."),
        default="base",
    )

    args, _ = parser.parse_known_args(sys.argv[1:])

    if args.strategy == "tenant-import" and (
        not args.tenant_uri or not args.tenant_wallet_name or not args.tenant_wallet_key
    ):
        parser.error(
            """For tenant-import strategy, tenant-uri, tenant-wallet-name, and 
            tenant-wallet-key are required."""
        )

    return args


async def main(args):
    """Run the main function."""
    logging.basicConfig(level=logging.WARN)
    parsed = urlparse(args.uri)

    # Connection setup
    if parsed.scheme == "sqlite":
        conn = SqliteConnection(args.uri)
    elif parsed.scheme == "postgres":
        conn = PgConnection(args.uri)
    else:
        raise ValueError("Unexpected DB URI scheme")

    # Strategy setup
    if args.strategy == "export":
        print(args)
        await conn.connect()
        method = Exporter(
            conn=conn,
            wallet_name=args.wallet_name,
            wallet_key=args.wallet_key,
            wallet_key_derivation_method=args.wallet_key_derivation_method,
            export_filename=args.export_filename,
        )
    elif args.strategy == "mt-convert-to-mw":
        await conn.connect()
        method = MultiWalletConverter(
            conn=conn,
            wallet_name=args.wallet_name,
            wallet_key=args.wallet_key,
            wallet_key_derivation_method=args.wallet_key_derivation_method,
            sub_wallet_name=args.multitenant_sub_wallet_name,
        )
    elif args.strategy == "tenant-import":
        tenant_parsed = urlparse(args.tenant_uri)
        if tenant_parsed.scheme == "sqlite":
            tenant_conn = SqliteConnection(args.tenant_uri)
        elif tenant_parsed.scheme == "postgres":
            tenant_conn = PgConnection(args.tenant_uri)
        else:
            raise ValueError("Unexpected tenant DB URI scheme")

        await conn.connect()
        await tenant_conn.connect()
        method = TenantImporter(
            admin_conn=conn,
            admin_wallet_name=args.wallet_name,
            admin_wallet_key=args.wallet_key,
            admin_wallet_key_derivation_method=args.wallet_key_derivation_method,
            tenant_import_object=TenantImportObject(
                tenant_conn=tenant_conn,
                tenant_wallet_name=args.tenant_wallet_name,
                tenant_wallet_key=args.tenant_wallet_key,
                tenant_wallet_type=args.tenant_wallet_type,
                tenant_wallet_key_derivation_method=args.tenant_wallet_key_derivation_method,
                tenant_label=args.tenant_label,
                tenant_image_url=args.tenant_image_url,
                tenant_webhook_urls=args.tenant_webhook_urls,
                tenant_extra_settings=args.tenant_extra_settings,
                tenant_dispatch_type=args.tenant_dispatch_type,
            ),
        )
    elif args.strategy == "mediator-convert":
        await conn.connect()
        method = MediatorConverter(
            conn=conn,
            wallet_name=args.wallet_name,
            wallet_key=args.wallet_key,
        )
    else:
        raise InvalidArgumentsError("Invalid strategy")

    await method.run()


def entrypoint():
    """Entrypoint for the CLI."""
    args = config()
    asyncio.run(main(args))


if __name__ == "__main__":
    asyncio.run(entrypoint())
