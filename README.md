# ontic-js

ontic-js is a JavaScript SDK for integrating Ontic Space into web apps and other
JavaScript applications. It provides account authentication, external-account
ownership workflows, and independent verification of statements and external-account proofs.

## Add the dependency

Add `ontic-js` to your app's `package.json`:

```json
{
  "dependencies": {
    "ontic-js": "github:onticspace/ontic-js"
  }
}
```

Then install dependencies:

```sh
npm install
```

## Set up the client

```js
import { OnticClient } from 'ontic-js';

const server = 'https://ontic.space';
const onticClient = new OnticClient({
  apiBaseURL: `${server}/api/v1`,
  // Use an RPC for the network where this server publishes its proofs.
  ethereumVerificationRPC: 'https://your-ethereum-rpc.example',
});

// Login is required to add entries and submit ownership proofs.
// The client keeps the returned credentials for subsequent requests.
await onticClient.auth('login', {
  username: 'alice',
  password: 'your-password',
  device_name: 'My integration',
});
```

## Prove ownership of a Twitter account

```js
// Twitter verification must be enabled on the backend.
let twitter = await onticClient.entries.create({
  service: 'Twitter/X',
  value: 'your_twitter_handle',
});

// Publish this exact text as an original public tweet from that account.
console.log(twitter.proof.text);

// After publishing, submit your tweet's URL.
twitter = await onticClient.entries.submitProof(twitter.id, {
  url: 'https://x.com/your_twitter_handle/status/YOUR_TWEET_ID',
});
console.log(twitter.verified_at);

// If the challenge expires before verification, request a fresh one:
// twitter = await onticClient.entries.renewProof(twitter.id);
```

## Prove ownership of a GitHub account

```js
let github = await onticClient.entries.create({ service: 'GitHub' });

// Publish this exact text on its own lines in a public gist you own.
console.log(github.proof.text);

// After publishing, submit your gist's URL.
github = await onticClient.entries.submitProof(github.id, {
  url: 'https://gist.github.com/your_github_username/YOUR_GIST_ID',
});
console.log(github.value, github.verified_at);
```

## Request the proof of a user's external entry

```js
// Read all public entries, following pagination automatically.
const entries = await onticClient.entries.all({ username: 'bob' });
const entry = entries.find(item =>
  item.service === 'GitHub' && item.value === 'octocat'
);
if (!entry?.verification_url) throw new Error('No verification proof is available.');

// verification_url identifies the historical verification snapshot.
const snapshotID = new URL(entry.verification_url, server)
  .searchParams.get('external_account');
if (!snapshotID) throw new Error('The verification snapshot ID is missing.');

const proof = await onticClient.entries.getVerification(snapshotID, { private: false });
```

## Verify the external-entry proof

```js
const result = await onticClient.entries.verifyAttestation(JSON.stringify(proof), {
  progress: message => console.log(message),
});

console.log({
  username: result.author,
  service: result.service,
  account: result.account,
  ethereumBlock: result.blockNumber,
  timestamp: result.timestamp,
});

// Success verifies the historical registry attestation and Ethereum inclusion.
// It does not independently prove that the user still owns the external account.
```

## Request and verify an organization membership proof

```js
// Public profiles include accepted organizations and their verification URLs.
const profile = await onticClient.request('/users/bob');
const organization = profile.organizations.find(item => item.username === 'acme');
if (!organization?.verification_url) {
  throw new Error('No membership verification proof is available.');
}

const membershipSnapshotID = new URL(organization.verification_url, server)
  .searchParams.get('organization_membership');
if (!membershipSnapshotID) throw new Error('The membership snapshot ID is missing.');

const membershipProof = await onticClient.getOrganizationMembershipVerification(
  membershipSnapshotID
);
const membershipResult = await onticClient.verifyOrganizationMembership(
  JSON.stringify(membershipProof),
  { progress: message => console.log(message) }
);

console.log({
  username: membershipResult.author,
  organization: membershipResult.organization,
  ethereumBlock: membershipResult.blockNumber,
  timestamp: membershipResult.timestamp,
});

// Verification requires a mined Ethereum publication.
// Success establishes historical accepted membership, not current membership.
```
