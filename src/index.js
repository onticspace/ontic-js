export { OnticClient, createOnticClient } from './client.js';
export { APIError } from './backend-client.js';
export {
  parseStatementBundle, verifyStatementSignature, verifyStatementMerkleProof,
  verifyStatementEthereum, verifyStatementJSON, createVerificationRPC, statementVerificationMessage,
} from './verification.js';
export { signWalletMessage } from './wallet-signing.js';
export { startGitHub, githubCallback } from './github-auth.js';
export { startLinkedIn, completeLinkedIn, hasLinkedInCallback } from './linkedin-linking.js';
