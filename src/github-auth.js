// Accept only the provider authorization endpoint chosen by the backend.
export async function startGitHub(start, navigate) {
  const result = await start();
  const destination = new URL(result.authorization_url);
  if (destination.origin !== 'https://github.com' || destination.username || destination.password || destination.pathname !== '/login/oauth/authorize' || destination.hash) {
    throw new Error('Invalid GitHub authorization destination.');
  }
  navigate(destination.href);
}

// Reject ambiguous callback inputs and avoid rendering provider-controlled messages.
export function githubCallback(url) {
  const params = url.searchParams;
  if (params.has('error')) throw new Error('GitHub authorization was cancelled or declined. Try again.');
  if (params.getAll('code').length !== 1 || params.getAll('state').length !== 1 || !params.get('code') || params.get('code').length > 4096 || !/^[a-f0-9]{64}$/.test(params.get('state') || '')) {
    throw new Error('Invalid GitHub callback. Start again.');
  }
  return { code: params.get('code'), state: params.get('state') };
}
