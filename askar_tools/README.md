# Tools: This repo contains a collection of tools for interacting with an Aries Cloud Agent Python (ACAPy) askar wallets.

## Prerequisites:

 * Wallet(s) must be of type askar.

## Install

```
poetry install
```

### Export Wallet:

 * Exports a wallet into a file with a readable json format. This can be useful for debugging or for sharing wallet information with others.
 * Currently the private keys are not decrypted and are excluded from the exported file.

- `export` (Output the contents of a wallet to a json file):

    ```
    poetry run askar-tools \
    --strategy export \
    --uri postgres://<username>:<password>@<hostname>:<port>/<dbname> \
    --wallet-name <base wallet name> \
    --wallet-key <base wallet key> \
    --wallet-key-derivation-method <optional> \
    --export-filename <optional>
    ```

### Multi-tenant Wallet - Switch from single wallet to multi wallet:

##### Prerequisites:
    Backup sub-wallet. This operation will delete the sub-wallet when finished. If the wallet is broken for some reason you will not be able to recover it without a backup.

 * Converts the profiles in the sub-wallet to individual wallets and databases.
 * After completion, the sub-wallet will be deleted and the deployment should no longer use the `--multitenancy-config '{"wallet_type": "single-wallet-askar"}'` configuration.

- `mt-convert-to-mw` (Convert from single wallet to multi-wallet multi-tenant agent):

    ```
    poetry run askar-tools \ 
    --strategy mt-convert-to-mw  \ 
    --uri postgres://<username>:<password>@<hostname>:<port>/<dbname> \ 
    --wallet-name <base wallet name> \
    --wallet-key <base wallet key> \ 
    --wallet-key-derivation-method <optional> \
    --multitenant-sub-wallet-name <optional: custom sub wallet name>
    ```

### Import Wallet:

- Imports a wallet from a database location into a multi-tenant multi-wallet admin and database location.
- **Important:** Existing connections to the imported agent won't work without a proxy server routing the requests to the correct agent. This is because any external agents will still only know the old endpoint.
- The database will not be deleted from the source location.
- `tenant-import` (Import a wallet into a multi-wallet multi-tenant agent):

    ```
    poetry run askar-tools \
    --strategy tenant-import \
    --uri postgres://<username>:<password>@<hostname>:<port>/<dbname> \
    --wallet-name <base wallet name> \
    --wallet-key <base wallet key> \
    --wallet-key-derivation-method <optional> \
    --tenant-uri postgres://<username>:<password>@<hostname>:<port>/<dbname> \
    --tenant-wallet-name <tenant wallet name> \
    --tenant-wallet-key <tenant wallet key> \
    --tenant-wallet-key-derivation-method <optional> \
    --tenant-wallet-type <optional: default is askar> \
    --tenant-label <optional: default is None> \
    --tenant-image-url <optional: default is None> \
    --tenant-webhook-urls <optional: default is None> \
    --tenant-extra-settings <optional: default is None> \
    --tenant-dispatch-type <optional: default is None>
    ```
    
### Convert from acapy mediator to credo mediator:

 * Converts an acapy mediator records to a credo mediator records.
 * The acapy mediator wallet records will be deleted after the conversion.
 * The credo mediator wallet will be created in the same database as the acapy mediator wallet.
 * Only the default derivation method is supported.
- `mediator-convert` (Convert from acapy mediator to credo mediator):

     ```
    poetry run askar-tools \
    --strategy mediator-convert \
    --uri postgres://<username>:<password>@<hostname>:<port>/<dbname> \
    --wallet-name <base wallet name> \
    --wallet-key <base wallet key> 
    ```