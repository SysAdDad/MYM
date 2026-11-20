import base64
import io
import os
import re
import secrets
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from contextlib import contextmanager
from types import SimpleNamespace
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fastapi.testclient import TestClient
from PIL import Image


class SignatureManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        settings = patch.dict(os.environ, {
            "DATA_DIR": cls.directory.name,
            "SESSION_SECRET": secrets.token_urlsafe(32),
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "temporary-test-password",
            "ADMIN_PASSWORD_HASH": "",
            "COOKIE_SECURE": "true",
            "PUBLIC_BASE_URL": "",
            "OIDC_ISSUER": "",
        })
        settings.start()
        cls.addClassCleanup(settings.stop)

        cls.database = Path(cls.directory.name) / "signatures.db"
        with sqlite3.connect(cls.database) as db:
            db.execute("""CREATE TABLE records (
                id VARCHAR PRIMARY KEY, kind VARCHAR NOT NULL, name VARCHAR NOT NULL,
                content TEXT NOT NULL, source_html TEXT NOT NULL, published BOOLEAN NOT NULL,
                updated DATETIME NOT NULL
            )""")
            db.execute("INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?)", (
                "legacy", "signature", "Legacy", '{"blocks":[{"text":"Original"}]}',
                "<p>Original source</p>", True, "2024-01-01 00:00:00",
            ))
        from app import main
        cls.main = main
        cls.addClassCleanup(main.engine.dispose)

    def setUp(self):
        self.client = TestClient(self.main.app, base_url="https://testserver")
        self.addCleanup(self.client.close)
        login = self.client.post("/login", data={
            "username": "admin", "password": "temporary-test-password",
        }, follow_redirects=False)
        self.assertEqual(login.status_code, 303)
        self.assertIn("secure", login.headers["set-cookie"].lower())
        csrf = self.client.get("/api/session").json()["csrf"]
        self.headers = {"X-CSRF-Token": csrf}

    def post(self, path, data):
        return self.client.post(path, json=data, headers=self.headers)

    @contextmanager
    def community_database(self):
        m = self.main
        with tempfile.TemporaryDirectory() as directory:
            engine = create_engine(f"sqlite:///{directory}/community.db", connect_args={"check_same_thread": False})
            m.Base.metadata.create_all(engine)
            previous_revision = getattr(m.community, '_loaded_revision', None)
            with patch.multiple(m, Session=sessionmaker(engine, expire_on_commit=False), DATA=Path(directory),
                                oauth=m.oauth, issuer=m.issuer, oidc_callback_url=m.oidc_callback_url,
                                oidc_auto_provision=m.oidc_auto_provision, oidc_subject=m.oidc_subject,
                                oidc_configured=m.oidc_configured):
                try:
                    yield directory
                finally:
                    m.community._loaded_revision = previous_revision
                    engine.dispose()

    def test_community_setup_requires_server_token_and_only_claims_once(self):
        with self.community_database() as directory, patch.object(self.main, 'ADMIN_HASH', ''):
            response = self.client.get('/login')
            self.assertEqual(response.status_code, 200)
            csrf = re.search(r'name="csrf" value="([^"]+)"', response.text)[1]
            token = (Path(directory) / 'setup-token')
            # An invalid token cannot claim the installation.
            data = {'token': 'wrong', 'csrf': csrf, 'username': 'owner', 'password': 'unique-setup-password'}
            self.assertEqual(self.client.post('/setup', data=data).status_code, 403)
            data['token'] = token.read_text()
            data['password'] = 'short'
            self.assertEqual(self.client.post('/setup', data=data).status_code, 400)
            data['password'] = 'unique-setup-password'
            response = self.client.post('/setup', data=data, follow_redirects=False)
            self.assertEqual(response.status_code, 303, response.text)
            self.assertEqual(self.client.post('/setup', data=data).status_code, 403)
            login = self.client.post('/login', data={'username': 'owner', 'password': data['password']})
            self.assertEqual(login.status_code, 200)
            self.assertTrue(self.client.get('/api/session').json()['can_manage_users'])
            with self.main.Session() as db:
                owner = db.get(self.main.LocalAdmin, 1)
                self.assertNotIn(data['password'], owner.password_hash)

    def test_community_settings_encrypt_secrets_and_detect_stale_updates(self):
        with self.community_database():
            response = self.post('/api/admin/settings', {
                'revision': '', 'organization': r'<Example \1 & Co>', 'accent': '#663399',
                'oidc_client_secret': 'private-client-secret', 'ldap_bind_password': 'private-bind-secret',
            })
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn('private-client-secret', response.text)
            self.assertNotIn('private-bind-secret', response.text)
            self.assertTrue(response.json()['oidc_client_secret_configured'])
            with self.main.Session() as db:
                self.assertNotIn('private-client-secret', db.get(self.main.InstallationSettings, 1).value)
            login = self.client.get('/login').text
            self.assertIn(r'&lt;Example \1 &amp; Co&gt;', login)
            self.assertIn('Make Your Mark by', login)
            self.assertEqual(self.post('/api/admin/settings', {'revision': '', 'organization': 'stale'}).status_code, 409)
            self.assertEqual(self.post('/api/admin/settings', {
                'revision': response.json()['revision'], 'logo_url': 'javascript:alert(1)',
            }).status_code, 400)
            self.assertEqual(self.client.post('/api/admin/settings', json={}).status_code, 403)
            self.assertEqual(self.client.get('/admin/settings').status_code, 200)
            no_provider = self.post('/api/admin/settings/test', {'revision': response.json()['revision']})
            self.assertIn('No external sign-in method', no_provider.json()['detail'])
            removed = self.post('/api/admin/settings', {
                'revision': response.json()['revision'], 'clear_oidc_client_secret': True,
                'clear_ldap_bind_password': True,
            })
            self.assertEqual(removed.status_code, 200, removed.text)
            self.assertFalse(removed.json()['oidc_client_secret_configured'])
            self.assertFalse(removed.json()['ldap_bind_password_configured'])

    def test_directory_login_escapes_search_creates_editor_and_blocks_deleted_identity(self):
        from app.community import DEFAULTS
        values = {**DEFAULTS, 'ldap_enabled': True, 'ldap_host': 'directory.example.test',
                  'ldap_bind_dn': 'cn=reader', 'ldap_bind_password': 'service-secret',
                  'ldap_base_dn': 'ou=people', 'ldap_filter': '(uid={username})'}
        entry = SimpleNamespace(entry_dn='uid=person,ou=people', entry_raw_attributes={'entryUUID': [b'stable-user-id']})
        connection = MagicMock()
        connection.entries = [entry]
        with self.community_database(), patch.object(self.main.community, 'settings', return_value=(values, 'directory-revision')):
            with patch('app.community.ldap3.Connection', return_value=connection) as factory:
                with TestClient(self.main.app, base_url='https://testserver') as client:
                    response = client.post('/login', data={'username': 'person*)(uid=*)', 'password': 'user-password', 'method': 'ldap'}, follow_redirects=False)
                    self.assertEqual(response.status_code, 303, response.text)
                    session = client.get('/api/session').json()
                    self.assertFalse(session['can_manage_users'])
                    account = client.get('/api/account').json()
                    self.assertEqual(account['sign_in_method'], 'ldap')
                    self.assertEqual(account['role'], 'member')
                    self.assertFalse(account['local_login_enabled'])
                    self.assertEqual(client.get('/api/admin/settings').status_code, 403)
                    self.assertIn(r'person\2a\29\28uid=\2a\29', connection.search.call_args.args[1])
                    self.assertEqual(factory.call_args.kwargs['password'], 'user-password')
                    user_id = session['user']['id']
                    with self.main.Session() as db:
                        user = db.get(self.main.WorkspaceUser, user_id)
                        self.assertEqual(user.password_hash, '')
                        user.enabled = False
                        db.commit()
                    self.assertEqual(client.get('/api/session').status_code, 401)
                    self.assertEqual(client.post('/login', data={'username': 'person', 'password': 'user-password', 'method': 'ldap'}).status_code, 403)
                    with self.main.Session() as db:
                        db.delete(db.get(self.main.WorkspaceUser, user_id))
                        db.commit()
                    self.assertEqual(client.post('/login', data={'username': 'person', 'password': 'user-password', 'method': 'ldap'}).status_code, 403)

    def test_directory_rejects_bad_credentials_before_provisioning_and_requires_tls(self):
        from app.community import DEFAULTS
        from ldap3.core.exceptions import LDAPInvalidCredentialsResult
        values = {**DEFAULTS, 'ldap_enabled': True, 'ldap_host': 'directory.example.test',
                  'ldap_bind_dn': 'cn=reader', 'ldap_bind_password': 'service-secret',
                  'ldap_base_dn': 'ou=people'}
        with self.community_database(), patch.object(self.main.community, 'settings', return_value=(values, 'bad-login-test')):
            with patch('app.community.ldap3.Connection') as factory, patch('app.community.ldap3.Server') as server:
                factory.return_value.bind.side_effect = LDAPInvalidCredentialsResult()
                result = self.client.post('/login', data={'username': 'person', 'password': 'wrong', 'method': 'ldap'})
                self.assertEqual(result.status_code, 401)
                self.assertEqual(server.call_args.kwargs['tls'].validate, __import__('ssl').CERT_REQUIRED)
                self.assertFalse(factory.call_args.kwargs['auto_referrals'])
                with self.main.Session() as db:
                    self.assertEqual(db.query(self.main.DirectoryIdentity).count(), 0)
            with patch.dict(os.environ, {'COOKIE_SECURE': 'false'}):
                with self.assertRaises(self.main.HTTPException):
                    self.main.community.candidate({'ldap_enabled': True})

    def test_two_setup_requests_cannot_replace_each_others_administrator(self):
        from concurrent.futures import ThreadPoolExecutor
        from app.community import persistent_secret
        with self.community_database() as directory, patch.object(self.main, 'ADMIN_HASH', ''):
            token = persistent_secret(Path(directory), 'setup-token')
            clients = [TestClient(self.main.app, base_url='https://testserver') for _ in range(2)]
            try:
                forms = []
                for index, client in enumerate(clients):
                    page = client.get('/setup').text
                    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
                    forms.append({'token': token, 'csrf': csrf, 'username': f'owner-{index}', 'password': 'unique-setup-password'})
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(client.post, '/setup', data=form, follow_redirects=False)
                               for client, form in zip(clients, forms)]
                    statuses = sorted(future.result().status_code for future in futures)
                self.assertEqual(statuses, [303, 409])
                with self.main.Session() as db:
                    self.assertEqual(db.query(self.main.LocalAdmin).count(), 1)
            finally:
                for client in clients:
                    client.close()

    def test_oidc_settings_require_matching_discovery_and_preserve_recovery_login(self):
        import httpx2
        metadata = {'issuer': 'https://sso.example.test/application/o/signatures/',
                    'authorization_endpoint': 'https://sso.example.test/authorize',
                    'token_endpoint': 'https://sso.example.test/token',
                    'jwks_uri': 'https://sso.example.test/jwks'}
        from joserfc.jwk import RSAKey
        jwks = {'keys': [RSAKey.generate_key(2048).as_dict(private=False)]}
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.get.side_effect = lambda url: httpx2.Response(200, json=(metadata if url.endswith('openid-configuration') else jwks), request=httpx2.Request('GET', url))
        values = {'revision': '', 'oidc_enabled': True, 'oidc_issuer': metadata['issuer'],
                  'oidc_client_id': 'public-client', 'oidc_redirect_uri': 'https://signatures.example.test/auth/oidc/callback'}
        with self.community_database(), patch('app.community.httpx.AsyncClient', return_value=client):
            saved = self.post('/api/admin/settings', values)
            self.assertEqual(saved.status_code, 200, saved.text)
            auth_revision = self.main.community.auth_revision()
            self.assertTrue(self.client.get('/api/session').json()['can_manage_users'])
            # Branding does not invalidate a pending external authentication session.
            branding = self.post('/api/admin/settings', {'revision': saved.json()['revision'], 'organization': 'Company'})
            self.assertEqual(branding.status_code, 200, branding.text)
            self.assertEqual(auth_revision, self.main.community.auth_revision())
            metadata['issuer'] = 'https://wrong-issuer.example.test/'
            invalid = self.post('/api/admin/settings/test', {**values, 'revision': branding.json()['revision']})
            self.assertEqual(invalid.status_code, 400)
            # The existing local owner remains usable after external authentication is enabled.
            self.assertEqual(self.client.post('/login', data={'username': 'admin', 'password': 'temporary-test-password'}).status_code, 200)

    def test_oidc_connection_rejects_empty_or_malformed_signing_keys(self):
        import asyncio
        import httpx2
        from fastapi import HTTPException
        issuer = 'https://sso.example.test/application/o/signatures/'
        metadata = {'issuer': issuer, 'authorization_endpoint': issuer + 'authorize',
                    'token_endpoint': issuer + 'token', 'jwks_uri': issuer + 'jwks'}
        client = AsyncMock()
        client.__aenter__.return_value = client
        for jwks in ({}, {'keys': []}, [], {'keys': [{'kty': 'RSA'}]}):
            with self.subTest(jwks=jwks), patch('app.community.httpx.AsyncClient', return_value=client):
                client.get.side_effect = [
                    httpx2.Response(200, json=metadata, request=httpx2.Request('GET', issuer)),
                    httpx2.Response(200, json=jwks, request=httpx2.Request('GET', metadata['jwks_uri'])),
                ]
                with self.assertRaises(HTTPException) as caught:
                    asyncio.run(self.main.community.check_oidc({'oidc_issuer': issuer}))
                self.assertEqual(caught.exception.status_code, 400)

    def test_oidc_callback_handles_malformed_provider_response_without_server_error(self):
        oidc = AsyncMock()
        for error in (KeyError('keys'), ValueError('do-not-log-token-content'), TypeError('invalid response')):
            with self.subTest(error=type(error).__name__), patch.object(self.main.oauth, 'create_client', return_value=oidc):
                oidc.authorize_access_token.side_effect = error
                with patch('builtins.print') as log:
                    response = self.client.get('/auth/oidc/callback')
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()['detail'], 'Single sign-on could not be verified')
                self.assertNotIn('do-not-log-token-content', str(log.call_args))

    def test_authentication_rate_limit_expires_and_covers_failed_sign_ins(self):
        with self.community_database(), patch('app.community.time.time', return_value=100000), patch.object(self.main, 'verify_password', return_value=False):
            for _ in range(120):
                response = self.client.post('/login', data={'username': 'unknown', 'password': 'wrong'})
                self.assertEqual(response.status_code, 401)
            response = self.client.post('/login', data={'username': 'unknown', 'password': 'wrong'})
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.headers['retry-after'], '60')
            with patch('app.community.time.time', return_value=100061):
                self.assertEqual(self.client.post('/login', data={'username': 'unknown', 'password': 'wrong'}).status_code, 401)

    def test_admin_can_change_credentials_and_revoke_other_local_sessions(self):
        original = {"username": "admin", "password": "temporary-test-password"}
        new = {"username": "signature-admin", "password": "new-test-password-123"}
        change = {"username": new["username"], "current_password": original["password"],
                  "new_password": new["password"]}
        with TestClient(self.main.app, base_url="https://testserver", follow_redirects=False) as other:
            self.assertEqual(other.get("/api/account").status_code, 401)
            self.assertEqual(other.post("/login", data=original).status_code, 303)
            self.assertEqual(self.client.get("/api/account").json(), {
                "username": "admin", "local_login_enabled": True,
                "signed_in_as": "admin", "role": "admin", "sign_in_method": "local",
            })
            self.assertEqual(self.client.post("/api/account", data=change).status_code, 403)
            rejected = self.client.post("/api/account", headers=self.headers,
                                        data={**change, "current_password": "wrong"})
            self.assertEqual(rejected.status_code, 403)
            weak = self.client.post("/api/account", headers=self.headers, data={**change, "new_password": "short"})
            self.assertEqual(weak.status_code, 400)
            try:
                updated = self.client.post("/api/account", data=change, headers=self.headers)
                self.assertEqual(updated.json(), {"username": new["username"]})
                self.assertEqual(self.client.get("/api/session").json()["user"]["name"], new["username"])
                self.assertEqual(other.get("/api/session").status_code, 401)
                self.assertEqual(other.get("/").headers["location"], "/login")
                self.assertEqual(other.post("/login", data=original).status_code, 401)
                self.main.initialize_database()
                self.assertEqual(other.post("/login", data=new).status_code, 303)
                with sqlite3.connect(self.database) as db:
                    stored_hash, = db.execute("SELECT password_hash FROM local_admin WHERE id=1").fetchone()
                self.assertTrue(stored_hash.startswith("$argon2"))
                self.assertNotIn(new["password"], stored_hash)

                renamed = self.client.post("/api/account", headers=self.headers, data={
                    "username": "renamed-admin", "current_password": new["password"],
                })
                self.assertEqual(renamed.json(), {"username": "renamed-admin"})
                self.assertEqual(other.post("/login", data={**new, "username": "renamed-admin"}).status_code, 303)
            finally:
                with sqlite3.connect(self.database) as db:
                    db.execute("DELETE FROM local_admin")

    def test_legacy_migration_is_repeatable_and_preserves_source(self):
        self.main.initialize_database()
        self.main.initialize_database()
        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute(
                "SELECT name, source_html, published, published_html FROM records WHERE id='legacy'"
            ).fetchone(), ("Legacy", "<p>Original source</p>", 1, ""))
        self.assertEqual(self.client.get("/api/render/legacy?published=true").status_code, 409)
        self.assertIn("Original", self.client.get("/api/render/legacy").json()["html"])

    def test_bind_policy_rejects_wildcard_and_public_addresses(self):
        for value in ("127.0.0.1", "192.168.1.10"):
            self.main.check_bind_address(value)
        for value in ("0.0.0.0", "::", "8.8.8.8", "localhost"):
            with self.assertRaises(RuntimeError):
                self.main.check_bind_address(value)

    def test_oidc_callback_requires_the_configured_subject(self):
        oidc = AsyncMock()
        issuer = "https://sso.example.test/application/"
        oidc.authorize_access_token.return_value = {"userinfo": {"sub": "other-user", "iss": issuer}}
        with patch.object(self.main.oauth, "create_client", return_value=oidc), patch.object(
            self.main, "oidc_subject", "admin-subject"
        ), patch.object(self.main, "issuer", issuer), patch.object(
            self.main, "oidc_configured", True
        ), TestClient(self.main.app, base_url="https://testserver") as anonymous:
            response = anonymous.get("/auth/oidc/callback", follow_redirects=False)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(anonymous.get("/api/session").status_code, 401)

            oidc.authorize_access_token.return_value = {"userinfo": {"sub": "admin-subject", "iss": issuer}}
            response = anonymous.get("/auth/oidc/callback", follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            self.assertEqual(anonymous.get("/api/session").json()["user"]["sub"], "admin-subject")
            account = anonymous.get("/api/account").json()
            self.assertEqual(account["signed_in_as"], "admin-subject")
            self.assertEqual(account["sign_in_method"], "oidc")
            self.assertEqual(account["role"], "admin")

    def test_owner_can_add_and_disable_local_editors(self):
        password = "editor-test-password"
        data = {"username": "local-editor", "password": password}
        self.assertEqual(self.client.post("/api/users", data=data).status_code, 403)
        created = self.client.post("/api/users", headers=self.headers, data=data)
        self.assertEqual(created.status_code, 200, created.text)
        editor = created.json()
        self.assertNotIn("password_hash", editor)
        self.assertEqual(self.client.post("/api/users", headers=self.headers, data=data).status_code, 409)
        self.assertEqual(self.client.post("/api/users", headers=self.headers, data={
            **data, "username": "admin",
        }).status_code, 409)
        with TestClient(self.main.app, base_url="https://testserver", follow_redirects=False) as client:
            self.assertEqual(client.post("/login", data=data).status_code, 303)
            self.assertEqual(client.get("/api/records").status_code, 200)
            self.assertFalse(client.get("/api/session").json()["can_manage_users"])
            self.assertEqual(client.get("/api/users").status_code, 403)
            self.assertEqual(client.get("/api/account").json()["username"], "local-editor")
            csrf = client.get("/api/session").json()["csrf"]
            renamed = client.post("/api/account", headers={"X-CSRF-Token": csrf}, data={
                "username": "renamed-editor", "current_password": password,
            })
            self.assertEqual(renamed.status_code, 200, renamed.text)
            self.assertEqual(self.client.post("/api/users", headers=self.headers, data={
                "username": "renamed-editor", "user_id": editor["id"], "enabled": "false",
            }).status_code, 200)
            self.assertEqual(client.get("/api/records").status_code, 401)
            self.assertEqual(client.post("/login", data={**data, "username": "renamed-editor"}).status_code, 401)

    def test_editor_records_are_private_and_templates_are_read_only(self):
        def save(client, headers, **data):
            response = client.post("/api/records", headers=headers, json={
                "name": "Example", "content": {"blocks": [{"text": "Example"}]}, **data,
            })
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()["id"]

        template_id = save(self.client, self.headers, kind="template")
        owner_id = save(self.client, self.headers, publish=True)
        credentials = {"username": "editor", "password": "editor-test-password"}
        editor = self.client.post("/api/users", headers=self.headers, data=credentials).json()
        with TestClient(self.main.app, base_url="https://testserver", follow_redirects=False) as client:
            self.assertEqual(client.post("/login", data=credentials).status_code, 303)
            headers = {"X-CSRF-Token": client.get("/api/session").json()["csrf"]}
            draft_id = save(client, headers)
            save(client, headers, id=draft_id)
            shared_id = save(client, headers, kind="template")
            save(client, headers, kind="template", id=shared_id)
            self.assertIn(shared_id, {r["id"] for r in self.client.get("/api/records").json()})
            visible_ids = {r["id"] for r in client.get("/api/records").json()}
            self.assertTrue({template_id, draft_id}.issubset(visible_ids))
            self.assertNotIn(owner_id, visible_ids)
            self.assertEqual(client.get(f"/api/render/{template_id}").status_code, 200)
            self.assertEqual(client.get(f"/api/render/{owner_id}?published=true").status_code, 404)
            self.assertEqual(client.post("/api/export/bundle", headers=headers, json={
                "published_id": owner_id,
            }).status_code, 404)
            self.assertEqual(client.post("/api/records", headers=headers, json={
                "id": owner_id, "name": "Overwrite",
            }).status_code, 404)
            self.assertEqual(client.post("/api/records", headers=headers, json={
                "id": template_id, "name": "Overwrite", "kind": "template",
            }).status_code, 403)
            self.assertEqual(client.delete(f"/api/records/{draft_id}", headers=headers).status_code, 403)
            self.assertEqual(client.delete(f"/api/records/{shared_id}", headers=headers).status_code, 403)
            self.assertEqual(client.get("/api/users").status_code, 403)
            self.assertEqual(self.client.post("/api/users", headers=self.headers, data={
                "user_id": editor["id"], "username": editor["username"], "is_admin": "true",
            }).status_code, 200)
            self.assertEqual(client.get("/api/session").status_code, 401)
            self.assertEqual(client.post("/login", data=credentials).status_code, 303)
            session = client.get("/api/session").json()
            self.assertTrue(session["can_manage_users"])
            self.assertEqual(client.get("/api/users").status_code, 200)
            self.assertEqual(client.delete(f"/api/records/{owner_id}", headers={
                "X-CSRF-Token": session["csrf"],
            }).status_code, 200)

    def test_oidc_first_login_creates_only_one_editor_and_removal_blocks_return(self):
        provider = "https://sso.example.test/application/"
        oidc = AsyncMock()
        oidc.authorize_access_token.return_value = {
            "userinfo": {"iss": provider, "sub": "new-sso-subject", "preferred_username": "admin"}
        }
        with patch.object(self.main.oauth, "create_client", return_value=oidc), patch.multiple(
            self.main, issuer=provider, oidc_configured=True, oidc_auto_provision=True,
        ), TestClient(self.main.app, base_url="https://testserver", follow_redirects=False) as client:
            self.assertEqual(client.get("/auth/oidc/callback").status_code, 303)
            session = client.get("/api/session").json()
            self.assertFalse(session["can_manage_users"])
            self.assertNotEqual(session["user"]["name"], "admin")
            user_id = session["user"]["id"]
            self.assertEqual(client.get("/auth/oidc/callback").status_code, 303)
            self.assertEqual(client.get("/api/session").json()["user"]["id"], user_id)
            self.assertEqual(self.client.delete(f"/api/users/{user_id}", headers=self.headers).status_code, 204)
            self.assertEqual(client.get("/auth/oidc/callback").status_code, 403)

    def test_oidc_editors_require_explicit_issuer_subject_mapping(self):
        oidc = AsyncMock()
        issuer = "https://sso.example.test/application/"
        with patch.object(self.main.oauth, "create_client", return_value=oidc), patch.object(
            self.main, "oidc_subject", "reserved-owner"
        ), patch.object(self.main, "issuer", issuer), patch.object(
            self.main, "oidc_configured", True
        ), TestClient(self.main.app, base_url="https://testserver", follow_redirects=False) as client:
            data = {"username": "sso-editor", "subject": "directory-subject"}
            created = self.client.post("/api/users", headers=self.headers, data=data)
            self.assertEqual(created.status_code, 200, created.text)
            self.assertEqual(self.client.post("/api/users", headers=self.headers, data={
                **data, "username": "other-sso-editor",
            }).status_code, 409)
            for claims in (
                {"iss": issuer, "sub": "unknown", "email": "sso-editor"},
                {"iss": "https://wrong.example.test", "sub": "directory-subject"},
            ):
                oidc.authorize_access_token.return_value = {"userinfo": claims}
                self.assertEqual(client.get("/auth/oidc/callback").status_code, 403)
            oidc.authorize_access_token.return_value = {"userinfo": {"iss": issuer, "sub": "directory-subject"}}
            self.assertEqual(client.get("/auth/oidc/callback").status_code, 303)
            self.assertEqual(client.get("/api/session").json()["user"]["name"], "sso-editor")
            self.assertEqual(client.get("/api/users").status_code, 403)
            directory = self.client.get("/api/users").json()
            self.assertTrue(directory["owner"]["local_login_enabled"])
            self.assertTrue(directory["owner"]["oidc_login_enabled"])
            url = f'/api/users/{created.json()["id"]}'
            self.assertEqual(client.delete(url, headers={
                "X-CSRF-Token": client.get("/api/session").json()["csrf"],
            }).status_code, 403)
            self.assertEqual(self.client.delete(url).status_code, 403)
            self.assertEqual(self.client.delete(url, headers=self.headers).status_code, 204)
            self.assertNotIn(created.json()["id"], {
                user["id"] for user in self.client.get("/api/users").json()["users"]
            })
            self.assertEqual(client.get("/api/session").status_code, 401)
            self.assertEqual(client.get("/auth/oidc/callback").status_code, 403)

    def test_profile_edits_and_draft_saves_do_not_change_snapshot(self):
        profile = self.post("/api/profiles", {"name": "Primary", "fields": {
            "name": '<Alice & "Co">',
            "email": "alice@example.test",
            "website": "javascript:alert(1)",
        }})
        self.assertEqual(profile.status_code, 200, profile.text)
        profile_id = profile.json()["id"]
        content = {"profile_id": profile_id, "blocks": [
            {"type": "text", "text": "{{ name }} / {{ unknown }}"},
            {"type": "link", "text": "Email", "href": "mailto:{{email}}"},
            {"type": "link", "text": "Website", "href": "{{website}}"},
            {"type": "text", "text": "Hidden block", "hidden": True},
        ]}
        record = self.post("/api/records", {"name": "Test", "content": content, "publish": True})
        self.assertEqual(record.status_code, 400, record.text)
        content["blocks"][2]["href"] = "example.test"
        record = self.post("/api/records", {"name": "Test", "content": content, "publish": True})
        self.assertEqual(record.status_code, 200, record.text)
        record_id = record.json()["id"]
        url = f"/api/render/{record_id}"
        snapshot = self.client.get(url + "?published=true").json()["html"]
        self.assertIn("&lt;Alice &amp; &quot;Co&quot;&gt; / ", snapshot)
        self.assertIn('href="mailto:alice@example.test"', snapshot)
        self.assertIn('href="https://example.test"', snapshot)
        self.assertNotIn("javascript:", snapshot)
        self.assertNotIn("Hidden block", snapshot)

        updated = self.post("/api/profiles", {"id": profile_id, "name": "Primary", "fields": {"name": "Bob", "email": "bob@example.test"}})
        self.assertEqual(updated.status_code, 200)
        content["blocks"][0]["text"] = "Draft for {{name}}"
        saved = self.post("/api/records", {"id": record_id, "name": "Draft", "content": content})
        self.assertEqual(saved.status_code, 200)
        self.assertIn("Draft for Bob", self.client.get(url).json()["html"])
        self.assertEqual(snapshot, self.client.get(url + "?published=true").json()["html"])
        republished = self.post("/api/records", {"id": record_id, "name": "Draft", "content": content, "publish": True})
        self.assertEqual(republished.status_code, 200)
        self.assertIn("Draft for Bob", self.client.get(url + "?published=true").json()["html"])

    def test_source_only_import_remains_reviewable_and_cannot_publish(self):
        raw = (
            '<table><tr><td style="color:#222;width:url(https://example.test/track);'
            'font-family:Arial" onclick="alert(1)">Name</td></tr></table>'
            '<script>alert(2)</script><a href="//example.test/">relative</a>'
            '<a href="jav&#x61;script:alert(3)">bad</a><img src="data:image/png;base64,AA">'
            '<img src="https://example.test/logo.png" onerror="alert(4)">'
            '<a href="mailto:person@example.test">good</a>'
        )
        imported = self.post("/api/import", {"html": raw})
        self.assertEqual(imported.status_code, 200, imported.text)
        self.assertEqual(imported.json()["source_html"], raw)
        safe = imported.json()["safe_html"]
        for text in ("<table>", "color:#222", "font-family:Arial", "https://example.test/logo.png", "mailto:person"):
            self.assertIn(text, safe)
        for text in ("onclick", "<script", 'href="//', "javascript:", "url(", "onerror", "data:image"):
            self.assertNotIn(text, safe)
        draft = self.post("/api/records", {"source_html": raw})
        self.assertEqual(draft.status_code, 200)
        record_id = draft.json()["id"]
        saved = next(r for r in self.client.get("/api/records").json() if r["id"] == record_id)
        self.assertEqual(saved["source_html"], raw)
        self.assertEqual(self.post("/api/records", {"id": record_id, "publish": True}).status_code, 400)
        self.assertEqual(self.client.get(f"/api/render/{record_id}?published=true").status_code, 404)
        self.assertEqual(self.post("/api/import", {"html": "é" * 250_001}).status_code, 413)

    def test_two_column_snapshot_renders_multiline_text_and_social_links(self):
        document = {"align": "center", "blocks": [{
            "type": "section", "align": "right", "columns": [
                [{"type": "image", "url": "https://example.test/photo.png", "alt": "Portrait"}],
                [{"type": "text", "text": "First <line>\r\nSecond & line"},
                 {"type": "social", "align": "left", "links": {
                     "linkedin": "https://www.linkedin.com/in/example",
                     "instagram": "https://www.instagram.com/example",
                 }}],
            ],
        }]}
        response = self.post("/api/preview", {"content": document})
        self.assertEqual(response.status_code, 200, response.text)
        output = response.json()["html"]
        self.assertRegex(output, r'^<table [^>]*align="center"')
        self.assertIn('<td align="right">', output)
        self.assertEqual(output.count('<td valign="top">'), 2)
        self.assertLess(output.index('alt="Portrait"'), output.index("First &lt;line&gt;<br>Second &amp; line"))
        self.assertIn('text-align:left;', output)
        self.assertIn('>LinkedIn</a> &middot; ', output)
        self.assertIn('>Instagram</a>', output)
        saved = self.post("/api/records", {"name": "Layout", "content": document, "publish": True})
        self.assertEqual(saved.status_code, 200, saved.text)
        record_id = saved.json()["id"]
        snapshot = self.client.get(f"/api/render/{record_id}?published=true")
        editor = self.post("/api/preview", {"content": document, "editor": True}).json()
        self.assertEqual(snapshot.json()["html"], editor["html"])
        self.assertTrue(snapshot.json()["has_local_images"])

    def test_nested_spacer_uses_cell_height_without_a_text_line(self):
        content = {"blocks": [{"type": "section", "columns": [
            [{"type": "spacer"}, {"type": "text", "text": "Name"}],
            [{"type": "image", "url": "https://example.test/portrait.png"}],
        ]}]}
        preview = self.post("/api/preview", {"content": content})
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertIn('height="12" style="height:12px;font-size:0;line-height:0">&nbsp;', preview.json()["html"])

    def test_vertical_alignment_centers_contact_text_without_a_spacer(self):
        section = {"type": "section", "column_vertical_align": ["middle", "top"],
                   "column_widths": [110, None], "columns": [
                       [{"text": "Name"}, {"text": "Title"}],
                       [{"type": "image", "url": "https://example.test/portrait.png"}],
                   ]}
        preview = self.post("/api/preview", {"content": {"blocks": [section]}})
        self.assertEqual(preview.status_code, 200, preview.text)
        markup = preview.json()["html"]
        self.assertIn('valign="middle" width="110" style="width:110px;vertical-align:middle"', markup)
        self.assertIn('<td valign="top">', markup)
        self.assertNotIn('height="12"', markup)
        section["column_vertical_align"] = ["center"]
        self.assertEqual(self.post("/api/preview", {"content": {"blocks": [section]}}).status_code, 400)

    def test_contact_qr_encodes_a_downloadable_vcard(self):
        url = "/api/export/contact-qr"
        data = {"name": "Zoë Example", "company": "Research, Design; LLC",
                "email": "zoe@example.test", "phone": "+1 (804) 555-0123"}
        self.assertEqual(self.client.post(url, json=data).status_code, 403)
        self.assertEqual(self.post(url, {"name": "Name\nEMAIL:other@example.test"}).status_code, 400)
        result = self.post(url, data)
        self.assertEqual(result.status_code, 200, result.text if result.status_code != 200 else "")
        self.assertEqual(result.headers["cache-control"], "no-store")
        result = result.json()
        card = result["vcard"]
        self.assertIn("VERSION:3.0\r\nFN:Zoë Example\r\n", card)
        self.assertIn(r"ORG:Research\, Design\; LLC", card)
        self.assertIn("TEL;TYPE=VOICE:+1 (804) 555-0123", card)
        with Image.open(io.BytesIO(base64.b64decode(result["png"]))) as image:
            self.assertEqual(image.format, "PNG")
            self.assertEqual(image.width, image.height)
        self.assertEqual(self.post(url, {**data, "color": "#1266a5"}).json()["color"], "#1266a5")
        self.assertEqual(self.post(url, {**data, "color": "#b2ef3e"}).json()["color"], "#000000")

    def test_phone_country_formats_label_and_preserves_international_target(self):
        blocks = [
            {"type": "phone", "href": "8045550123", "country_region": "US"},
            {"type": "phone", "href": "020 8366 1177", "country_region": "GB"},
        ]
        result = self.post("/api/preview", {"content": {"blocks": blocks}}).json()["html"]
        self.assertIn('href="tel:+18045550123"', result)
        self.assertIn('>(804) 555-0123</a>', result)
        self.assertIn('href="tel:+442083661177"', result)
        self.assertIn('>020 8366 1177</a>', result)

    def test_guided_export_checks_readiness_without_publishing(self):
        document = {"guided": {"version": 1, "name": "Taylor"}, "blocks": [{"text": "Taylor"}]}
        check = self.post("/api/preview", {"content": document, "editor": True, "check_export": True}).json()
        self.assertIn("Taylor", check["copy_html"])
        self.assertNotIn("copy_issue", check)
        saved = self.post("/api/records", {"name": "Guided", "content": document})
        self.assertEqual(saved.status_code, 200)
        records = self.client.get("/api/records").json()
        self.assertEqual(next(record for record in records if record["id"] == saved.json()["id"])["content"], document)
        document["blocks"].append({"type": "image", "url": "/media/" + "c" * 32 + ".png"})
        check = self.post("/api/preview", {"content": document, "editor": True, "check_export": True}).json()
        self.assertNotIn("copy_html", check)
        self.assertIn("public HTTPS image origin", check["copy_issue"])

    def test_sections_validate_children_and_published_urls(self):
        section = {"type": "section", "columns": [[], []]}
        for block in (
            section,
            {"type": "image", "url": "/media/" + "a" * 32 + ".png"},
            {"type": "social", "links": {"x": "javascript:alert(1)"}},
        ):
            content = {"blocks": [{**section, "columns": [[block], []]}]}
            self.assertEqual(self.post("/api/records", {"content": content, "publish": True}).status_code, 400)
        self.assertEqual(self.post("/api/records", {"content": {"blocks": [section]}, "publish": True}).status_code, 400)

    def test_fonts_inherit_through_sections_and_use_safe_fallbacks(self):
        document = {"font": "Georgia", "blocks": [{"type": "section", "columns": [
            [{"text": "Inherited"}],
            [{"text": "Custom", "font": "Avenir Next"}],
        ]}]}
        response = self.post("/api/preview", {"content": document})
        self.assertEqual(response.status_code, 200)
        self.assertIn("font-family:Georgia,Times New Roman,serif", response.json()["html"])
        self.assertIn("font-family:'Avenir Next',Arial,sans-serif", response.json()["html"])
        document["font"] = 'Arial; background:url(https://example.test)'
        self.assertEqual(self.post("/api/preview", {"content": document}).status_code, 400)

    def test_visual_rows_include_four_columns_and_linked_icon_tiles(self):
        social = {"type": "social", "links": {"youtube": "https://www.youtube.com/@example"}}
        document = {"blocks": [
            {"type": "section", "columns": [[{"text": str(i)}] for i in range(4)]},
            {"type": "section", "columns": [[social]]},
        ]}
        preview = self.post("/api/preview", {"content": document, "editor": True})
        self.assertEqual(preview.status_code, 200, preview.text)
        result = preview.json()
        self.assertEqual(result["html"].count('<td valign="top">'), 5)
        self.assertIn(">3</td>", result["tiles"]["0.3.0"])
        self.assertIn('href="https://www.youtube.com/@example"', result["tiles"]["1.0.0"])
        self.assertIn('src="/media/social/youtube.png"', result["tiles"]["1.0.0"])
        with TestClient(self.main.app) as anonymous:
            self.assertEqual(anonymous.get("/media/social/youtube.png").headers["content-type"], "image/png")
            self.assertEqual(anonymous.get("/media/social/unknown.png").status_code, 404)
        with patch.dict(os.environ, {"PUBLIC_BASE_URL": "https://images.example.test"}):
            exported = self.post("/api/preview", {"content": document}).json()["html"]
            self.assertIn('src="https://images.example.test/media/social/youtube.png"', exported)

    def test_compact_rows_export_widths_gap_and_contact_link_styles(self):
        document = {"blocks": [{
            "type": "section", "column_gap": 5, "column_widths": [90, None, 120],
            "columns": [[{"text": "Studio"}], [{
                "type": "email", "href": "taylor+studio@example.test", "link_color": "#0B0F14",
                "underline": False, "font_size": 13, "line_height": 20, "padding_top": 0,
                "padding_bottom": 2,
            }], [{
                "type": "phone", "href": "(804) 555-0123", "country_code": "+1",
                "link_color": "#123456",
            }]],
        }]}
        result = self.post("/api/preview", {"content": document})
        self.assertEqual(result.status_code, 200, result.text)
        output = result.json()["html"]
        self.assertIn('valign="top" width="90" style="width:90px"', output)
        self.assertIn('valign="top" width="120" style="width:120px"', output)
        self.assertEqual(output.count('width="5"'), 2)
        self.assertIn('line-height:20px;', output)
        self.assertIn('padding:0px 0 2px', output)
        self.assertIn('href="mailto:taylor+studio@example.test" style="color:#0B0F14;text-decoration:none"', output)
        self.assertIn('href="tel:+18045550123" style="color:#123456;text-decoration:underline">(804) 555-0123', output)
        document["blocks"][0]["column_gap"] = 0
        compact = self.post("/api/preview", {"content": document}).json()["html"]
        self.assertNotIn('font-size:1px', compact)
        self.assertEqual(self.post("/api/records", {"content": document, "publish": True}).status_code, 200)

    def test_phone_accepts_an_international_profile_number_and_rejects_missing_code(self):
        profile = self.post("/api/profiles", {"name": "International", "fields": {"phone": "+44 (0)20 7946 0958"}})
        self.assertEqual(profile.status_code, 200)
        doc = {"profile_id": profile.json()["id"], "blocks": [
            {"type": "phone", "href": "{{phone}}", "country_code": "+1"},
        ]}
        result = self.post("/api/preview", {"content": doc})
        self.assertEqual(result.status_code, 200)
        self.assertIn('href="tel:+442079460958"', result.json()["html"])
        doc["blocks"][0] = {"type": "phone", "href": "555-0123"}
        failed = self.post("/api/records", {"content": doc, "publish": True})
        self.assertEqual(failed.status_code, 400)
        self.assertIn("country calling code", failed.json()["detail"])

    def test_bundle_contains_only_referenced_local_images_and_icons(self):
        name = "c" * 32 + ".png"
        local = self.main.MEDIA / name
        with local.open("wb") as output:
            Image.new("RGB", (1, 1)).save(output, "PNG")
        content = {"blocks": [
            {"type": "image", "url": f"/media/{name}", "width": 160, "contact_qr": True},
            {"type": "social", "links": {"linkedin": "https://www.linkedin.com/in/example"}},
            {"type": "image", "url": "https://example.test/hosted.png"},
        ]}
        result = self.post("/api/export/bundle", {"content": content})
        self.assertEqual(result.status_code, 200, result.text if result.status_code != 200 else "")
        with zipfile.ZipFile(io.BytesIO(result.content)) as bundle:
            self.assertEqual(set(bundle.namelist()), {
                "signature.html", "README.txt", f"media/{name}", "media/social/linkedin.png",
            })
            markup = bundle.read("signature.html").decode()
            self.assertTrue(markup.startswith("<!doctype html>"))
            self.assertIn(f'<a href="./media/{name}"><img src="./media/{name}"', markup)
            self.assertIn('width="100"', markup)
            self.assertIn('src="./media/social/linkedin.png"', markup)
            self.assertIn('src="https://example.test/hosted.png"', markup)
        published = self.post("/api/records", {"content": content, "publish": True})
        self.assertEqual(published.status_code, 200, published.text)
        record_id = published.json()["id"]
        self.post("/api/records", {"id": record_id, "content": {"blocks": [{"text": "New draft"}]}})
        snapshot = self.client.get(f"/api/render/{record_id}?published=true").json()
        self.assertTrue(snapshot["has_local_images"])
        self.assertIn(f'src="/media/{name}"', snapshot["html"])
        saved_bundle = self.post("/api/export/bundle", {"published_id": record_id})
        self.assertEqual(saved_bundle.status_code, 200, saved_bundle.text if saved_bundle.status_code != 200 else "")
        with zipfile.ZipFile(io.BytesIO(saved_bundle.content)) as bundle:
            markup = bundle.read("signature.html").decode()
            self.assertIn(f'<a href="./media/{name}"><img src="./media/{name}"', markup)
            self.assertIn('width="100"', markup)
            self.assertIn('src="./media/social/linkedin.png"', markup)
            self.assertNotIn("New draft", markup)

    def test_template_strips_contact_qr_from_blocks_and_guided_fields(self):
        qr = {"type": "image", "url": "/media/" + "c" * 32 + ".png", "contact_qr": True}
        text = {"type": "text", "text": "Template text"}
        content = {"blocks": [qr, {"type": "section", "columns": [[qr, text]]}],
                   "guided": {"version": 1, "qrUrl": qr["url"]}}
        template = self.post("/api/records", {"kind": "template", "content": content})
        self.assertEqual(template.status_code, 200, template.text)
        record = next(record for record in self.client.get("/api/records").json()
                      if record["id"] == template.json()["id"])
        self.assertEqual(record["content"]["blocks"], [{"type": "section", "columns": [[text]]}])
        self.assertEqual(record["content"]["guided"]["qrUrl"], "")

    def test_saved_bundle_includes_images_from_configured_https_origin(self):
        name = "b" * 32 + ".png"
        Image.new("RGB", (1, 1)).save(self.main.MEDIA / name, "PNG")
        origin = "https://images.example.test"
        url = f"{origin}/media/{name}"
        with patch.dict(os.environ, {"PUBLIC_BASE_URL": origin}):
            published = self.post("/api/records", {"publish": True, "content": {
                "blocks": [{"type": "image", "url": url, "contact_qr": True}],
            }})
            self.assertEqual(published.status_code, 200, published.text)
            result = self.post("/api/export/bundle", {"published_id": published.json()["id"]})
        self.assertEqual(result.status_code, 200, result.text if result.status_code != 200 else "")
        with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
            self.assertIn(f"media/{name}", archive.namelist())
            self.assertIn(f'<a href="./media/{name}"><img src="./media/{name}"',
                          archive.read("signature.html").decode())

    def test_delete_profile_protects_references(self):
        profile = {"name": "Contact", "fields": {"name": "Example"}}
        profile_id = self.post("/api/profiles", profile).json()["id"]
        profile_url = f"/api/profiles/{profile_id}"
        self.assertEqual(self.client.delete(profile_url).status_code, 403)
        for kind in ("signature", "template"):
            with self.subTest(kind=kind):
                record = {"kind": kind, "name": "Saved item", "content": {"profile_id": profile_id}}
                record_id = self.post("/api/records", record).json()["id"]
                blocked = self.client.delete(profile_url, headers=self.headers)
                self.assertEqual(blocked.status_code, 409)
                self.assertIn(f'{kind} “Saved item”', blocked.json()["detail"])
                detached = self.post("/api/records", {**record, "id": record_id, "content": {}})
                self.assertEqual(detached.status_code, 200)
        self.assertEqual(self.client.delete(profile_url, headers=self.headers).status_code, 200)
        self.assertNotIn(profile_id, {row["id"] for row in self.client.get("/api/profiles").json()})
        self.assertEqual(self.post("/api/profiles", {**profile, "id": profile_id}).status_code, 404)
        self.assertEqual(self.post("/api/records", {"content": {"profile_id": profile_id}}).status_code, 400)

    def test_delete_signature_and_template(self):
        template_id = self.post("/api/records", {"kind": "template", "name": "Layout"}).json()["id"]
        signature_id = self.post("/api/records", {
            "name": "From layout",
            "content": {"blocks": [{"type": "text", "text": "Example"}]},
            "publish": True,
        }).json()["id"]
        template_url = f"/api/records/{template_id}"
        self.assertEqual(self.client.delete(template_url).status_code, 403)
        self.assertEqual(self.client.delete(template_url, headers=self.headers).status_code, 200)
        records = {record["id"] for record in self.client.get("/api/records").json()}
        self.assertNotIn(template_id, records)
        self.assertIn(signature_id, records)
        self.assertEqual(
            self.client.delete(f"/api/records/{signature_id}", headers=self.headers).status_code, 200
        )
        self.assertEqual(self.client.get(f"/api/render/{signature_id}?published=true").status_code, 404)
        self.assertEqual(self.post("/api/records", {"id": signature_id, "name": "Stale draft"}).status_code, 404)

    def test_validation_and_private_routes(self):
        with TestClient(self.main.app) as anonymous:
            self.assertEqual(anonymous.get("/api/records").status_code, 401)
            self.assertEqual(anonymous.get("/docs").status_code, 404)
        self.assertEqual(self.client.post("/api/profiles", json={}).status_code, 403)
        self.assertEqual(self.post("/api/profiles", {"name": "Person", "fields": {"name": []}}).status_code, 400)
        self.assertEqual(self.post("/api/preview", {"content": {"blocks": [None]}}).status_code, 400)
        self.assertEqual(self.post("/api/records", {"content": {"profile_id": "missing"}}).status_code, 400)
        self.assertEqual(self.post("/api/records", {"kind": "template", "publish": True}).status_code, 400)
        malformed = self.post("/api/preview", {"content": {"blocks": [{"type": "link", "href": "https://["}]}})
        self.assertEqual(malformed.status_code, 200)
        self.assertNotIn("href=", malformed.json()["html"])

    def test_public_images_are_limited_to_generated_paths(self):
        data = io.BytesIO()
        Image.new("RGB", (1, 1)).save(data, "PNG")
        upload = self.client.post("/api/assets", files={
            "file": ("logo.png", data.getvalue(), "image/png"),
        }, headers=self.headers)
        self.assertEqual(upload.status_code, 200)
        url = upload.json()["url"]
        self.assertTrue(re.fullmatch(r"/media/[a-f0-9]{32}\.png", url))
        (self.main.MEDIA / "private.txt").write_text("fixture")
        with TestClient(self.main.app) as anonymous:
            image = anonymous.get(url)
            self.assertEqual(image.headers["content-type"], "image/png")
            self.assertEqual(image.headers["x-content-type-options"], "nosniff")
            self.assertEqual(image.content, data.getvalue())
            self.assertEqual(anonymous.head(url).status_code, 200)
            self.assertEqual(anonymous.get("/media/private.txt").status_code, 404)
        record = {"content": {"blocks": [{"type": "image", "url": url}]}, "publish": True}
        self.assertEqual(self.post("/api/records", record).status_code, 200)
        with patch.dict(os.environ, {"PUBLIC_BASE_URL": "https://images.example.test"}):
            response = self.post("/api/records", record)
            self.assertEqual(response.status_code, 200, response.text)
        record_id = response.json()["id"]
        snapshot = self.client.get(f"/api/render/{record_id}?published=true").json()["html"]
        self.assertIn("https://images.example.test" + url, snapshot)
