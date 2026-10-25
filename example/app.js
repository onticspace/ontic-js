import { OnticClient, parseStatementBundle } from './ontic.bundle.js';

// Application-owned configuration. The supplied fixture uses Ethereum Sepolia.
const onticClient = new OnticClient({
  apiBaseURL: 'https://ontic.space/api/v1',
  ethereumVerificationRPC: 'https://ethereum-sepolia-rpc.publicnode.com',
});
// Trusted application policy, independent of the proof file.
const publishing = { chain_id: '11155111', contract_address: '0x705542739d468560821b993d7b0e6e1345f74d4b' };
const byID = id => document.getElementById(id);
const profile = document.querySelector('.profile');
const toggle = byID('proofs-toggle');
const tooltip = byID('proofs-tooltip');
const verifyAll = byID('verify-all');
const rows = [];
const shield = toggle.querySelector('svg');

// Fit the complete username into the identity column instead of hiding characters.
const usernameHeading = byID('username');
const identity = document.querySelector('.identity');
function fitUsername() {
  usernameHeading.style.removeProperty('font-size');
  const available = identity.clientWidth;
  if (available > 0 && usernameHeading.scrollWidth > available) {
    const size = parseFloat(getComputedStyle(usernameHeading).fontSize);
    usernameHeading.style.fontSize = `${size * available / usernameHeading.scrollWidth - .1}px`;
  }
}
let identityWidth = 0;
const identityObserver = new ResizeObserver(([entry]) => {
  if (entry.contentRect.width !== identityWidth) {
    identityWidth = entry.contentRect.width;
    fitUsername();
  }
});
identityObserver.observe(identity);


function setOpen(open, restoreFocus = false) {
  tooltip.hidden = !open;
  toggle.setAttribute('aria-expanded', String(open));
  if (open) tooltip.focus({ preventScroll: true });
  else if (restoreFocus) toggle.focus({ preventScroll: true });
}
toggle.addEventListener('click', () => setOpen(tooltip.hidden));
document.addEventListener('pointerdown', event => { if (!profile.contains(event.target)) setOpen(false); });
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !tooltip.hidden) setOpen(false, true); });

function platformName(record) {
  const platforms = { GitHub: 'github.com', 'Twitter/X': 'x.com', Bluesky: 'bsky.app', LinkedIn: 'linkedin.com', 'Ethereum address': 'Ethereum' };
  if (record.service === 'website') {
    try { return new URL(record.target || record.account).hostname; } catch { return 'Website'; }
  }
  return platforms[record.service] || record.service;
}
// Inline vectors keep platform icons available without external image requests.
function platformIcon(service) {
  const paths = {
    GitHub: 'M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.86c-2.78.6-3.37-1.18-3.37-1.18-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.09-.65.35-1.09.64-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.03A9.6 9.6 0 0 1 12 6.82c.85 0 1.71.11 2.51.34 1.91-1.3 2.75-1.03 2.75-1.03.55 1.38.2 2.4.1 2.65.64.7 1.03 1.6 1.03 2.69 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.76c0 .27.18.58.69.48A10 10 0 0 0 12 2Z',
    'Twitter/X': 'M18.9 2H22l-6.77 7.74L23.2 22h-6.24l-4.89-7.4L5.6 22H2.46l8.15-9.32L.8 2h6.4l4.42 6.75L18.9 2Zm-1.1 18h1.73L6.25 3.9H4.4L17.8 20Z',
    Bluesky: 'M12 10.5C10.4 7.4 6.1 3.3 3.3 2.2.6 1.1 1 4.4 1 5.3c0 .9.5 7.3.9 8.4.6 1.5 2.8 2 4.8 1.6-3.5.6-6.6 2-2.5 6.4 4.5 4.6 6.2-1 7.8-4.2 1.6 3.2 3.3 8.8 7.8 4.2 4.1-4.4 1-5.8-2.5-6.4 2 .4 4.2-.1 4.8-1.6.4-1.1.9-7.5.9-8.4 0-.9.4-4.2-2.3-3.1-2.8 1.1-7.1 5.2-8.7 8.3Z',
    LinkedIn: 'M3 3h4v4H3V3Zm0 6h4v12H3V9Zm6 0h4v1.7c.8-1.3 2-2 3.7-2 3.2 0 4.3 2.1 4.3 5.4V21h-4v-6.1c0-1.6-.3-2.9-1.9-2.9-1.8 0-2.1 1.5-2.1 2.9V21H9V9Z',
    'Ethereum address': 'M12 1 5 12l7 4 7-4L12 1Zm0 17-7-4 7 9 7-9-7 4Z',
  };
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'platform-icon');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  if (service === 'Organization') {
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.7');
    svg.setAttribute('stroke-linejoin', 'round');
    const path = document.createElementNS(svg.namespaceURI, 'path');
    path.setAttribute('d', 'M4 22V3h16v19M2 22h20M9 22v-5h6v5M8 7h2m4 0h2M8 11h2m4 0h2');
    svg.append(path);
  } else if (paths[service]) {
    svg.setAttribute('fill', 'currentColor');
    const path = document.createElementNS(svg.namespaceURI, 'path');
    path.setAttribute('d', paths[service]);
    svg.append(path);
  } else {
    // Websites and unrecognized services use a globe.
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.7');
    for (const [tag, attributes] of [
      ['circle', { cx: '12', cy: '12', r: '9' }],
      ['ellipse', { cx: '12', cy: '12', rx: '4', ry: '9' }],
      ['path', { d: 'M3 12h18' }],
    ]) {
      const shape = document.createElementNS(svg.namespaceURI, tag);
      for (const [name, value] of Object.entries(attributes)) shape.setAttribute(name, value);
      svg.append(shape);
    }
  }
  return svg;
}

function accountProfileURL(record) {
  const account = encodeURIComponent(String(record.account || '').replace(/^@/, ''));
  const profiles = {
    GitHub: `https://github.com/${account}`,
    'Twitter/X': `https://x.com/${account}`,
    Bluesky: `https://bsky.app/profile/${account}`,
    LinkedIn: `https://www.linkedin.com/in/${account}`,
    'Ethereum address': `https://etherscan.io/address/${account}`,
  };
  try {
    const url = new URL(record.target || profiles[record.service] || record.account);
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

function addProof(bundle, field, parameter, username) {
  // Parse with the SDK, then read the committed content for display. Parsing alone
  // is not verification; only the explicit SDK action below verifies the evidence.
  bundle = parseStatementBundle(JSON.stringify(bundle));
  const entry = bundle[field];
  if (!entry || !/^[a-f0-9]{32}$/.test(entry.id)) throw new Error('Invalid proof snapshot ID.');
  const record = JSON.parse(entry.content);
  if (record.username !== username) throw new Error('A proof belongs to a different user.');
  const membership = field === 'organization_membership';
  const website = !membership && record.service === 'website';
  const label = membership ? `Organization – @${record.organization}` : website ? record.account : `${platformName(record)} – ${record.account}`;
  const row = document.createElement('li');
  row.className = 'proof-row';
  const description = document.createElement('div');
  description.className = 'proof-description';
  const title = document.createElement('span');
  title.className = 'proof-label';
  const profileURL = membership ? `https://ontic.space/${encodeURIComponent(record.organization)}` : accountProfileURL(record);
  if (profileURL) {
    const accountLink = document.createElement('a');
    accountLink.className = 'account-link';
    accountLink.textContent = membership ? `@${record.organization}` : record.account;
    accountLink.href = profileURL;
    accountLink.target = '_blank'; accountLink.rel = 'noopener noreferrer';
    title.append(membership ? 'Organization – ' : website ? '' : `${platformName(record)} – `, accountLink);
  } else title.textContent = label;
  const kind = document.createElement('span');
  kind.className = 'proof-kind'; kind.textContent = membership ? 'Organization membership' : 'Account ownership';
  const timestamp = bundle.ethereum_anchor?.block_timestamp;
  const anchoredAt = typeof timestamp === 'string' ? new Date(timestamp) : null;
  if (anchoredAt && Number.isFinite(anchoredAt.getTime())) {
    const date = document.createElement('time');
    date.dateTime = anchoredAt.toISOString();
    date.textContent = date.dateTime.slice(0, 10);
    date.title = `${membership ? 'Date of membership proven' : 'Date of ownership proven'}: ${anchoredAt.toUTCString()}`;
    date.setAttribute('aria-label', date.title);
    kind.append(' · ', date);
  }
  const status = document.createElement('span');
  status.className = 'proof-status';
  description.append(title, kind, status);
  const link = document.createElement('a');
  link.className = 'proof-link';
  const url = new URL('https://ontic.space/statements/verify');
  url.searchParams.set(parameter, entry.id);
  link.href = url.href;
  link.target = '_blank'; link.rel = 'noopener noreferrer';
  link.setAttribute('aria-label', `Verify ${label} on Ontic Space (opens a new tab)`);
  link.title = `Verify ${label}`;
  link.append(shield.cloneNode(true));
  row.append(platformIcon(membership ? 'Organization' : record.service));
  row.append(description, link);
  byID('proof-list').append(row);
  rows.push({ bundle, membership, row, status });
}

verifyAll.addEventListener('click', async () => {
  verifyAll.disabled = true;
  byID('verification-status').dataset.state = 'checking';
  byID('verification-status').textContent = `0 of ${rows.length} proofs verified. Checking…`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000);
  let verified = 0;
  try {
    for (const item of rows) {
      item.status.textContent = 'Checking…';
      item.row.classList.remove('verified');
      try {
        const text = JSON.stringify(item.bundle);
        await onticClient.verifyProofData(text, { publishing, signal: controller.signal });
        item.row.classList.add('verified');
        item.status.textContent = 'Account ownership verified';
        verified++;
      } catch (error) {
        item.status.textContent = controller.signal.aborted ? 'Verification timed out. Use the proof link.' : 'Could not verify here. Use the proof link.';
        console.error('Proof verification failed:', error);
      }
      byID('verification-status').textContent = `${verified} of ${rows.length} proofs verified. Checking…`;
    }
    toggle.classList.toggle('all-verified', verified === rows.length && rows.length > 0);
    byID('verification-status').dataset.state = verified === rows.length && rows.length > 0 ? 'verified' : 'incomplete';
    byID('verification-status').textContent = `${verified} of ${rows.length} proofs verified. Membership and ownership proofs are historical records.`;
  } finally {
    clearTimeout(timeout);
    verifyAll.disabled = false;
  }
});

try {
  const response = await fetch('./example-proofs.json');
  if (!response.ok) throw new Error(`Could not load example-proofs.json (${response.status}).`);
  const data = await response.json();
  if (typeof data.username !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,38}$/.test(data.username)) throw new Error('Invalid profile username.');
  byID('username').textContent = `@${data.username}`;
  fitUsername();
  byID('avatar-fallback').textContent = data.username.slice(0, 2).toUpperCase();
  if (typeof data.profile_pic === 'string' && data.profile_pic) {
    const url = new URL(data.profile_pic);
    if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Unsupported profile picture URL.');
    const image = byID('profile-picture');
    image.alt = `Profile picture of @${data.username}`;
    image.addEventListener('error', () => { image.hidden = true; });
    image.src = url.href; image.hidden = false;
  }
  for (const bundle of data.external_account_proofs || []) addProof(bundle, 'external_account', 'external_account', data.username);
  for (const bundle of data.organization_membership_proofs || []) addProof(bundle, 'organization_membership', 'organization_membership', data.username);
  toggle.disabled = rows.length === 0;
  verifyAll.disabled = rows.length === 0;
  byID('page-status').textContent = rows.length ? '' : 'This profile has no proof bundles.';
} catch (error) {
  byID('page-status').textContent = error.message;
}
