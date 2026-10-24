// Only the backend may choose the LinkedIn authorization destination.
export async function startLinkedIn(entryID, request, navigate) {
  const result = await request(`/me/entries/${encodeURIComponent(entryID)}/linkedin/start`, 'POST');
  const destination = new URL(result.authorization_url);
  if (destination.protocol !== 'https:' || destination.hostname !== 'www.linkedin.com' || destination.port || destination.username || destination.password || destination.pathname !== '/oauth/v2/authorization' || destination.hash) {
    throw new Error('Invalid LinkedIn authorization destination.');
  }
  navigate(destination.href);
}

export function hasLinkedInCallback(url) {
  return ['code', 'state', 'error'].some(name => url.searchParams.has(name));
}

// Treat provider errors as local messages and reject ambiguous callback parameters.
export async function completeLinkedIn(url, request, signal) {
  const params = url.searchParams;
  if (params.has('error')) throw new Error('LinkedIn authorization was cancelled or declined. Connect again to retry.');
  if (params.getAll('code').length !== 1 || params.getAll('state').length !== 1 || !params.get('code') || params.get('state').length !== 64) {
    throw new Error('Invalid LinkedIn callback. Connect again to retry.');
  }
  return request('/me/linkedin/complete', 'POST', { code: params.get('code'), state: params.get('state') }, { signal });
}
