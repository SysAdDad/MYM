"""Installation setup, organization branding, and directory authentication."""
import base64
import fcntl
import hashlib
import html
import hmac
import json
import os
import re
import secrets
import ssl
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import httpx2 as httpx
import ldap3
from cryptography.fernet import Fernet
from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from ldap3.utils.conv import escape_filter_chars
from ldap3.operation.search import parse_filter

DEFAULTS = {
    "organization": "", "logo_url": "", "accent": "#9a51d2",
    "oidc_enabled": False, "oidc_issuer": "", "oidc_client_id": "",
    "oidc_client_secret": "", "oidc_redirect_uri": "", "oidc_auto_provision": False,
    "ldap_enabled": False, "ldap_host": "", "ldap_port": 636, "ldap_tls": "ldaps",
    "ldap_bind_dn": "", "ldap_bind_password": "", "ldap_base_dn": "",
    "ldap_filter": "(uid={username})", "ldap_id_attribute": "entryUUID",
    "ldap_ca_pem": "", "ldap_auto_provision": True,
}
SECRETS = {"oidc_client_secret", "ldap_bind_password"}


def persistent_secret(directory, name):
    """Serialize first-start writers so workers never read an incomplete key."""
    with (directory / '.bootstrap.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = directory / name
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as output:
                output.write(secrets.token_urlsafe(48))
        return path.read_text().strip()


class Community:
    def __init__(self, main):
        self.m = main
        key = persistent_secret(main.DATA, '.settings-key')
        self.auth_key = key.encode()
        self.cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))

    def settings(self):
        with self.m.Session() as db:
            row = db.get(self.m.InstallationSettings, 1)
            if row:
                return {**DEFAULTS, **json.loads(self.cipher.decrypt(row.value.encode()))}, row.revision
        # Environment configuration remains available to installations upgrading from the original app.
        return {**DEFAULTS,
                "oidc_enabled": self.m.oidc_configured, "oidc_issuer": self.m.issuer,
                "oidc_client_id": os.getenv('OIDC_CLIENT_ID', ''),
                "oidc_client_secret": os.getenv('OIDC_CLIENT_SECRET', ''),
                "oidc_redirect_uri": self.m.oidc_callback_url,
                "oidc_auto_provision": self.m.oidc_auto_provision}, ''

    def auth_revision(self):
        values, revision = self.settings()
        if not revision:
            return ''
        authentication = {key: value for key, value in values.items()
                          if key.startswith(('oidc_', 'ldap_'))}
        return hmac.new(self.auth_key, json.dumps(authentication, sort_keys=True).encode(), hashlib.sha256).hexdigest()

    def rate_limit(self, request):
        # SQLite shares limits between workers and preserves them across restarts.
        peer = request.client.host if request.client else 'unknown'
        key = hashlib.sha256(peer.encode()).hexdigest()
        now = time.time()
        m = self.m
        with m.Session() as db:
            db.connection().exec_driver_sql('BEGIN IMMEDIATE')
            db.query(m.LoginAttempt).filter(m.LoginAttempt.window_start < now - 86400).delete()
            row = db.get(m.LoginAttempt, key)
            if row and now - row.window_start < 60 and row.count >= 120:
                raise HTTPException(429, 'Too many sign-in attempts. Try again in one minute.', headers={'Retry-After': '60'})
            if row is None:
                row = m.LoginAttempt(key=key, count=0, window_start=now)
                db.add(row)
            if now - row.window_start >= 60:
                row.count, row.window_start = 0, now
            row.count += 1
            db.commit()

    def setup_needed(self):
        with self.m.Session() as db:
            return db.get(self.m.LocalAdmin, 1) is None and not self.m.ADMIN_HASH

    def public_settings(self):
        values, revision = self.settings()
        return {**{k: v for k, v in values.items() if k not in SECRETS},
                **{k + '_configured': bool(values[k]) for k in SECRETS}, "revision": revision}

    def candidate(self, data):
        allowed_keys = set(DEFAULTS) | {'revision'} | {'clear_' + name for name in SECRETS}
        if not isinstance(data, dict) or data.keys() - allowed_keys:
            raise HTTPException(400, 'Unsupported installation setting')
        current, revision = self.settings()
        values = dict(current)
        for key, value in data.items():
            if key == 'revision':
                continue
            if key.startswith('clear_'):
                if type(value) is not bool:
                    raise HTTPException(400, 'Invalid secret removal option')
                if value:
                    secret = key.removeprefix('clear_')
                    if data.get(secret):
                        raise HTTPException(400, 'Choose a replacement secret or remove it')
                    values[secret] = ''
                continue
            if type(value) is not type(DEFAULTS[key]):
                raise HTTPException(400, f'Invalid value for {key}')
            if isinstance(value, str) and len(value) > (16384 if key == 'ldap_ca_pem' else 4096):
                raise HTTPException(400, f'{key} is too long')
            # Empty secret inputs retain the stored value. JSON null is never accepted.
            if key not in SECRETS or value:
                values[key] = value.strip() if isinstance(value, str) and key not in SECRETS else value
        if len(values['organization']) > 100:
            raise HTTPException(400, 'Organization name must be under 100 characters')
        if not re.fullmatch(r'#[0-9a-fA-F]{6}', values['accent']):
            raise HTTPException(400, 'Choose a valid accent color')
        logo = values['logo_url']
        if logo and not self.m.local_asset_path(logo) and not self.m.safe_url(logo, {'https'}):
            raise HTTPException(400, 'Upload a logo or use its HTTPS image URL')
        secure = os.getenv('COOKIE_SECURE', 'true').lower() == 'true'
        if (values['oidc_enabled'] or values['ldap_enabled']) and not secure:
            raise HTTPException(400, 'Set COOKIE_SECURE=true and serve the app over HTTPS before enabling external sign-in')
        if values['oidc_enabled']:
            for key in ('oidc_issuer', 'oidc_redirect_uri'):
                if not self.m.safe_url(values[key], {'https'}) or urlsplit(values[key]).query or urlsplit(values[key]).fragment:
                    raise HTTPException(400, 'Use complete HTTPS issuer and callback URLs without query parameters')
            if not values['oidc_redirect_uri'].endswith('/auth/oidc/callback'):
                raise HTTPException(400, 'The callback URL must end with /auth/oidc/callback')
            if not values['oidc_client_id']:
                raise HTTPException(400, 'Enter the OIDC client ID')
        if values['ldap_enabled']:
            if not re.fullmatch(r'[a-zA-Z0-9.-]+', values['ldap_host']) or not 1 <= values['ldap_port'] <= 65535:
                raise HTTPException(400, 'Enter a directory hostname and valid port')
            if values['ldap_tls'] not in ('ldaps', 'starttls'):
                raise HTTPException(400, 'Choose LDAPS or StartTLS')
            if not all(values[k] for k in ('ldap_base_dn', 'ldap_bind_dn', 'ldap_bind_password')):
                raise HTTPException(400, 'Enter a search base and directory service-account credentials')
            search = values['ldap_filter']
            if search.count('{username}') != 1 or not search.startswith('(') or not search.endswith(')'):
                raise HTTPException(400, 'The LDAP filter must contain {username} exactly once')
            try:
                parse_filter(search.replace('{username}', 'connection-test'), None, True, True, None, False)
            except ldap3.core.exceptions.LDAPException:
                raise HTTPException(400, 'Enter a valid LDAP search filter') from None
            if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9-]*', values['ldap_id_attribute']):
                raise HTTPException(400, 'Enter a stable directory ID attribute such as entryUUID or objectGUID')
            if values['ldap_ca_pem']:
                try:
                    ssl.create_default_context(cadata=values['ldap_ca_pem'])
                except (ssl.SSLError, ValueError):
                    raise HTTPException(400, 'The directory CA must be a valid PEM certificate') from None
        return values, revision

    def apply_oidc(self, values):
        m = self.m
        m.issuer = values['oidc_issuer']
        m.oidc_callback_url = values['oidc_redirect_uri']
        m.oidc_auto_provision = values['oidc_auto_provision']
        m.oidc_subject = ''  # Community accounts receive roles through the user manager.
        m.oidc_configured = values['oidc_enabled']
        oauth = m.OAuth()
        if m.oidc_configured:
            oauth.register(name='oidc', client_id=values['oidc_client_id'],
                           client_secret=values['oidc_client_secret'],
                           server_metadata_url=m.issuer.rstrip('/') + '/.well-known/openid-configuration',
                           client_kwargs={'scope': 'openid profile email', 'code_challenge_method': 'S256'})
        m.oauth = oauth

    def sync(self):
        values, revision = self.settings()
        if revision and revision != getattr(self, '_loaded_revision', None):
            self.apply_oidc(values)
            self._loaded_revision = revision

    async def check_oidc(self, values):
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                response = await client.get(values['oidc_issuer'].rstrip('/') + '/.well-known/openid-configuration')
                response.raise_for_status()
                metadata = response.json()
                if not isinstance(metadata, dict) or metadata.get('issuer') != values['oidc_issuer']:
                    raise ValueError('Issuer does not match discovery')
                if not all(self.m.safe_url(metadata.get(k, ''), {'https'})
                           for k in ('authorization_endpoint', 'token_endpoint', 'jwks_uri')):
                    raise ValueError('Discovery must advertise HTTPS endpoints')
                response = await client.get(metadata['jwks_uri'])
                response.raise_for_status()
                jwks = response.json()
                if not isinstance(jwks, dict) or not isinstance(jwks.get('keys'), list) or not jwks['keys']:
                    raise HTTPException(400, 'OIDC signing keys are missing. Select a signing key in your identity provider; in Authentik, select an RSA Signing Key on the provider.')
                KeySet.import_key_set(jwks)
        except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError, JoseError):
            raise HTTPException(400, 'OIDC discovery or signing-key validation failed. Check the issuer URL, published public keys, DNS, and TLS certificate.') from None

    @contextmanager
    def directory_connection(self, values, user=None, password=None):
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED,
                        ca_certs_data=values['ldap_ca_pem'] or None,
                        version=ssl.PROTOCOL_TLS_CLIENT, sni=values['ldap_host'])
        server = ldap3.Server(values['ldap_host'], port=values['ldap_port'],
                              use_ssl=values['ldap_tls'] == 'ldaps', tls=tls, connect_timeout=8, get_info=ldap3.NONE)
        connection = ldap3.Connection(server, user=user or values['ldap_bind_dn'],
                                       password=password if password is not None else values['ldap_bind_password'],
                                       receive_timeout=8, auto_referrals=False, raise_exceptions=True)
        try:
            connection.open()
            if values['ldap_tls'] == 'starttls' and not connection.start_tls():
                raise ValueError('Directory TLS failed')
            if not connection.bind():
                raise ValueError('Directory bind failed')
            yield connection
        finally:
            connection.unbind()

    def check_directory(self, values):
        try:
            with self.directory_connection(values) as connection:
                connection.search(values['ldap_base_dn'], '(objectClass=*)', search_scope=ldap3.BASE,
                                  attributes=['objectClass'], size_limit=1, time_limit=5)
                if not connection.entries:
                    raise ValueError('Search base is unavailable')
        except (ldap3.core.exceptions.LDAPException, OSError, ValueError):
            raise HTTPException(400, 'Directory test failed. Check TLS trust, service-account credentials, and the search base.') from None

    def directory_login(self, request, username, password):
        values, _ = self.settings()
        revision = self.auth_revision()
        if not values['ldap_enabled']:
            raise HTTPException(503, 'Directory sign-in is disabled')
        if not password.strip() or len(password) > 4096:
            raise HTTPException(401, 'Invalid directory credentials')
        try:
            with self.directory_connection(values) as connection:
                search = values['ldap_filter'].replace('{username}', escape_filter_chars(username))
                connection.search(values['ldap_base_dn'], search, attributes=[values['ldap_id_attribute']],
                                  size_limit=2, time_limit=5)
                if len(connection.entries) != 1:
                    raise ValueError('A unique directory entry is required')
                entry = connection.entries[0]
                identifiers = entry.entry_raw_attributes.get(values['ldap_id_attribute'], [])
                if len(identifiers) != 1 or not identifiers[0]:
                    raise ValueError('Stable directory ID missing')
                subject = base64.urlsafe_b64encode(identifiers[0]).decode()
                dn = entry.entry_dn
            with self.directory_connection(values, dn, password):
                pass
        except (ldap3.core.exceptions.LDAPException, OSError, ValueError, KeyError):
            raise HTTPException(401, 'Directory sign-in failed. Check your credentials or contact your administrator.') from None
        namespace = hashlib.sha256(json.dumps([values[k] for k in (
            'ldap_host', 'ldap_port', 'ldap_base_dn', 'ldap_id_attribute')]).encode()).hexdigest()
        m = self.m
        with m.Session() as db:
            db.connection().exec_driver_sql('BEGIN IMMEDIATE')
            if self.auth_revision() != revision:
                raise HTTPException(409, 'Authentication settings changed. Start sign-in again.')
            identity = db.get(m.DirectoryIdentity, (namespace, subject))
            user = db.get(m.WorkspaceUser, identity.user_id) if identity else None
            if not identity and values['ldap_auto_provision']:
                name = username
                while name == m.local_credentials(db)[0] or m.find_editor(db, name):
                    name = username[:100] + '-' + secrets.token_hex(4)
                user = m.WorkspaceUser(id=secrets.token_hex(16), username=name, password_hash='',
                                       enabled=True, is_admin=False, revision=secrets.token_urlsafe(24))
                db.add(user)
                db.add(m.DirectoryIdentity(namespace=namespace, subject=subject, user_id=user.id))
                db.commit()
            if not user or not user.enabled:
                raise HTTPException(403, 'Directory account is not authorized')
        m.start_session(request, user.username, 'ldap', editor=user)
        request.session['auth_revision'] = revision
        return RedirectResponse('/', status_code=303)

    def brand(self, page):
        values, _ = self.settings()
        if values['organization'] or values['logo_url']:
            name = html.escape(values['organization'] or 'Make Your Mark')
            image = (f'<img class="organization-logo" src="{html.escape(values["logo_url"], quote=True)}" alt="">'
                     if values['logo_url'] else '')
            # Replace only the default product lockup, leaving the permanent credit in place.
            page = re.sub(r'<span class="brand-header-lockup">.*?</span>\s*</span>', lambda match: image + f'<span class="organization-name">{name}</span>', page, count=1, flags=re.S)
            page = re.sub(r'<span class="brand-lockup">.*?</span>', lambda match: image + f'<span class="organization-name">{name}</span>', page, count=1, flags=re.S)
        if values['organization'] or values['logo_url']:
            page = page.replace('class="brand-byline">by ', 'class="brand-byline">Make Your Mark by ')
        return page.replace('</head>', '<link rel="stylesheet" href="/installation/theme.css"></head>') if '</head>' in page else page.replace('<style>', '<link rel="stylesheet" href="/installation/theme.css"><style>', 1)

    def install_routes(self):
        m = self.m
        app = m.app

        @app.get('/setup', response_class=HTMLResponse)
        def setup_page(request: Request):
            if not self.setup_needed():
                return RedirectResponse('/login', status_code=303)
            csrf = request.session.setdefault('setup_csrf', secrets.token_urlsafe(32))
            page = (Path(__file__).parent / 'static' / 'setup.html').read_text()
            return HTMLResponse(page.replace('__SETUP_CSRF__', csrf), headers={'Cache-Control': 'no-store'})

        @app.post('/setup')
        def setup(request: Request, token: str = Form(...), csrf: str = Form(...),
                  username: str = Form(...), password: str = Form(...)):
            self.rate_limit(request)
            if not hmac_compare(request.session.get('setup_csrf', ''), csrf):
                raise HTTPException(403, 'Setup session expired. Reload setup.')
            expected = persistent_secret(m.DATA, 'setup-token')
            if not hmac_compare(expected, token):
                raise HTTPException(403, 'Incorrect setup token')
            username = m.checked_username(username)
            m.check_new_password(password)
            if not password:
                raise HTTPException(400, 'Choose an administrator password of at least 12 characters')
            replacement = m.ph.hash(password)
            with m.Session() as db:
                db.connection().exec_driver_sql('BEGIN IMMEDIATE')
                if db.get(m.LocalAdmin, 1) or m.ADMIN_HASH:
                    raise HTTPException(409, 'Setup has already been completed')
                db.add(m.LocalAdmin(id=1, username=username, password_hash=replacement,
                                    revision=secrets.token_urlsafe(24)))
                db.commit()
            request.session.clear()
            return RedirectResponse('/login', status_code=303)

        @app.get('/installation/theme.css')
        def theme():
            values, _ = self.settings()
            css = f':root {{ --wink-purple: {values["accent"]}; --interactive-border: {values["accent"]}; }}'
            css += '.organization-logo{max-width:160px;max-height:56px;object-fit:contain}.organization-name{font:600 16px system-ui;text-align:center}.brand-byline{font-size:10px}'
            return Response(css, media_type='text/css', headers={'Cache-Control': 'no-store'})

        @app.get('/admin/settings', response_class=HTMLResponse)
        def settings_page(request: Request):
            m.require_admin(request)
            page = (Path(__file__).parent / 'static' / 'installation-settings.html').read_text()
            return HTMLResponse(page, headers={'Cache-Control': 'no-store'})

        @app.get('/api/admin/settings')
        def settings_get(request: Request):
            m.require_admin(request)
            return self.public_settings()

        @app.post('/api/admin/settings/test')
        async def settings_test(request: Request):
            m.require_admin(request)
            m.require_csrf(request)
            values, _ = self.candidate(await m.json_object(request))
            if values['oidc_enabled']:
                await self.check_oidc(values)
            if values['ldap_enabled']:
                from starlette.concurrency import run_in_threadpool
                await run_in_threadpool(self.check_directory, values)
            enabled = []
            if values['oidc_enabled']:
                enabled.append('OIDC discovery and signing keys')
            if values['ldap_enabled']:
                enabled.append('Directory connection and search base')
            detail = 'No external sign-in method is enabled. Enable a provider to test its connection.'
            if enabled:
                detail = ' and '.join(enabled) + ' passed. Complete a real sign-in before relying on external authentication.'
            return {'ok': True, 'detail': detail}

        @app.post('/api/admin/settings')
        async def settings_save(request: Request):
            m.require_admin(request)
            m.require_csrf(request)
            data = await m.json_object(request)
            values, previous = self.candidate(data)
            if data.get('revision') != previous:
                raise HTTPException(409, 'Settings changed elsewhere. Reload before saving.')
            if values['oidc_enabled']:
                await self.check_oidc(values)
            if values['ldap_enabled']:
                from starlette.concurrency import run_in_threadpool
                await run_in_threadpool(self.check_directory, values)
            revision = secrets.token_urlsafe(24)
            with m.Session() as db:
                db.connection().exec_driver_sql('BEGIN IMMEDIATE')
                row = db.get(m.InstallationSettings, 1)
                if (row.revision if row else '') != previous:
                    raise HTTPException(409, 'Settings changed elsewhere. Reload before saving.')
                encrypted = self.cipher.encrypt(json.dumps(values).encode()).decode()
                db.merge(m.InstallationSettings(id=1, value=encrypted, revision=revision))
                db.commit()
            self.sync()
            return self.public_settings()


def hmac_compare(expected, supplied):
    return bool(expected) and hmac.compare_digest(expected.encode(), supplied.encode())
