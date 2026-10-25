# Profile example

Build from `ontic-js/`:

```sh
npm ci
npm run build:example
```

Then from inside the `example` directory:

```sh
python3 -m http.server
```

Open **http://localhost:8000/**.

The build bundles the local SDK and its dependencies into `ontic.bundle.js`.
The separate `app.js` imports that bundle directly. Rebuild after changing SDK
sources; edits to `app.js` need no build.
For deployment, upload `index.html`, `app.js`, `ontic.bundle.js`, `style.css`,
`onticspace.png`, and `example-proofs.json` together.

The **How this works?** panel explains portable historical proofs,
Ethereum commitments, and the SDK’s role independently of the example design.
It sits to the right on desktop and below the example on smaller screens.

The page displays the fixture's `profile_pic` and `username`. Click the shield
beside the username to open the tooltip. Each account/membership row has a shield
link to that snapshot's verification page on Ontic Space.

**Verify all with Ontic SDK** calls `onticClient.verifyProofData` on the bundled
JSON. It makes no Ontic Space API requests. Hashing and Merkle verification run
locally; Ethereum network requests check the published root, canonical block,
and timestamp. The expected Sepolia chain and Ontic publishing contract are
configured explicitly in `app.js`, independently of the proof file.
The main shield turns green only after every proof passes. Network access to
the Ethereum RPC is required; failures appear in the browser console.

The Python downloader in this folder can refresh the sample JSON. Verification proves historical records, not current ownership
or organization membership.


## Download all public proofs for a user

```sh
# Requires Python 3. Saves alice-proofs.json in the current directory.
./download-proofs.py alice

# Choose an output file or a different backend.
ONTIC_API_URL=http://127.0.0.1:8976/api/v1 ./download-proofs.py alice proofs.json
```

## Fetch and verify proof data separately

```js
// Fetching calls the Ontic Space API; it does not verify the result.
const { proof } = await onticClient.fetchProofData('external_account', snapshotID);
// Other types: 'organization_membership' and 'statement'.

// For saved JSON, use the bundled proof directly instead of fetching it.
const result = await onticClient.verifyProofData(JSON.stringify(proof), {
  publishing: {
    chain_id: '11155111',
    contract_address: '0x705542739d468560821b993d7b0e6e1345f74d4b',
  },
});
```

`verifyProofData` never calls the Ontic Space API. It checks hashes, signatures
(for statements), Merkle inclusion, and Ethereum publication/block timestamps
using the configured RPC. Supply the expected chain ID (a string) and contract
from trusted application configuration, independently of untrusted proof JSON.
It verifies historical attestations; it does not recheck current account ownership
or membership. For signed statements it proves the signing key, without a fresh
registry lookup associating that key with the claimed username.
`fetchProofData` returns `{ proof, publishing }`; its publishing configuration
comes from the selected backend. Existing verification methods retain their
registry checks for compatibility.
