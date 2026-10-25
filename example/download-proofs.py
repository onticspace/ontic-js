#!/usr/bin/env python3
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import URLError


def main():
    parser = argparse.ArgumentParser(
        description='Download public external-account and accepted organization-membership proof bundles into one JSON file. Downloads evidence; does not verify it.',
        epilog='Set ONTIC_API_URL to choose a backend (default: https://ontic.space/api/v1). Requires only Python 3.',
    )
    parser.add_argument('username', help='Ontic username')
    parser.add_argument('output', nargs='?', help='Output JSON file (default: example-proofs.json)')
    args = parser.parse_args()
    username, output = args.username, args.output
    base = os.environ.get('ONTIC_API_URL', 'https://ontic.space/api/v1')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,38}', username):
        raise ValueError('Use an Ontic username of 1–39 letters, digits, underscores, or hyphens.')
    username = username.lower()
    output = Path(output or f'example-proofs.json')
    base = base.rstrip('/')
    origin = urlsplit(base)
    if (origin.scheme not in ('http', 'https') or not origin.hostname
            or origin.username or origin.password or origin.query or origin.fragment):
        raise ValueError('ONTIC_API_URL must be an HTTP(S) API base URL without credentials, query, or fragment.')

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, new_url):
            return None

    opener = build_opener(NoRedirect)

    def get(path):
        # Never follow redirects or fetch destinations supplied in returned JSON.
        request = Request(base + path, headers={'Accept': 'application/json'})
        try:
            with opener.open(request, timeout=60) as response:
                value = json.load(response)
        except (URLError, OSError) as error:
            raise RuntimeError(f'Could not download {path}: {error}') from error
        if not isinstance(value, dict):
            raise ValueError(f'Expected a JSON object from {path}.')
        return value

    def snapshot_id(record, parameter):
        url = record.get('verification_url')
        if not url:
            return None
        if not isinstance(url, str):
            raise ValueError('Invalid verification URL in backend response.')
        values = parse_qs(urlsplit(url).query).get(parameter, [])
        if len(values) != 1 or not re.fullmatch(r'[a-f0-9]{32}', values[0]):
            raise ValueError(f'Invalid {parameter} snapshot ID in backend response.')
        return values[0]

    def download(record, parameter, resource, field, seen, destination):
        snapshot = snapshot_id(record, parameter)
        if snapshot is None or snapshot in seen:
            return
        bundle = get(f'/{resource}/{snapshot}')
        if bundle.get('version') != 1 or not isinstance(bundle.get(field), dict) or bundle[field].get('id') != snapshot:
            raise ValueError(f'Invalid proof bundle for snapshot {snapshot}.')
        seen.add(snapshot)
        destination.append(bundle)

    profile = get('/users/' + quote(username, safe=''))
    if profile.get('username') != username:
        raise ValueError('The backend returned a different username.')
    external, memberships = [], []
    external_ids, membership_ids, cursors = set(), set(), set()
    cursor = None
    while True:
        query = {'limit': 100}
        if cursor:
            query['cursor'] = cursor
        page = get(f'/users/{username}/entries?' + urlencode(query))
        if not isinstance(page.get('items'), list):
            raise ValueError('Invalid entries page.')
        for entry in page['items']:
            download(entry, 'external_account', 'external-verifications', 'external_account', external_ids, external)
        cursor = page.get('next_cursor')
        if cursor is not None and not isinstance(cursor, str):
            raise ValueError('Invalid entries cursor.')
        if not cursor:
            break
        if cursor in cursors or len(cursor) > 2048:
            raise ValueError('Repeated or oversized entries cursor.')
        cursors.add(cursor)

    organizations = profile.get('organizations', [])
    if not isinstance(organizations, list):
        raise ValueError('Invalid organizations list.')
    for organization in organizations:
        download(organization, 'organization_membership', 'organization-membership-verifications',
                 'organization_membership', membership_ids, memberships)

    combined = {
        'version': 1,
        'username': username,
        'source_api': base,
        'downloaded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'external_account_proofs': external,
        'organization_membership_proofs': memberships,
    }
    # Only replace the destination once every download has succeeded.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output.resolve().parent,
                                         prefix='.ontic-proofs-', delete=False) as handle:
            temporary = handle.name
            json.dump(combined, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
        os.replace(temporary, output)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    print(f'Saved {len(external)} external-account and {len(memberships)} organization-membership proofs to {output}', file=sys.stderr)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, AttributeError, TypeError) as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)
