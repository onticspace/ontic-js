// Request only personal message signing, after confirming address and network.
export async function signWalletMessage(provider, address, chainID, message) {
  if (!provider?.request) throw new Error('No wallet provider. Use manual signature submission.');
  const accounts = await provider.request({ method: 'eth_requestAccounts' });
  if (!accounts.some(account => account.toLowerCase() === address.toLowerCase())) throw new Error('Connect the wallet matching this address.');
  const chain = await provider.request({ method: 'eth_chainId' });
  if (BigInt(chain) !== BigInt(chainID)) throw new Error('Select the challenge network in your wallet.');
  const bytes = new TextEncoder().encode(message);
  const encoded = '0x' + Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return provider.request({ method: 'personal_sign', params: [encoded, address] });
}
