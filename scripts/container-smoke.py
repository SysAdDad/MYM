"""Exercise a disposable CI container, including setup and restart persistence."""
import http.cookiejar
import json
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = 'http://127.0.0.1:18080'
CONTAINER = 'mym-ci'
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(path, data=None, csrf=None, form=False):
    headers = {}
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    if csrf:
        headers['X-CSRF-Token'] = csrf
    with client.open(urllib.request.Request(BASE + path, data=body, headers=headers), timeout=10) as response:
        return response.read().decode()


def wait_for_health():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if json.loads(request('/health')) == {'status': 'ok'}:
                return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(1)
    raise RuntimeError('Container did not become healthy')


wait_for_health()
page = request('/login')
assert 'Create your administrator' in page
csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
token = subprocess.check_output(['docker', 'exec', CONTAINER, 'cat', '/data/setup-token'], text=True).strip()
password = secrets.token_urlsafe(32)
request('/setup', {'token': token, 'csrf': csrf, 'username': 'ci-owner', 'password': password}, form=True)
request('/login', {'username': 'ci-owner', 'password': password}, form=True)
session = json.loads(request('/api/session'))
assert session['can_manage_users'] is True
csrf = session['csrf']
record = json.loads(request('/api/records', {
    'name': 'Container persistence check', 'content': {'blocks': [{'type': 'text', 'text': 'CI signature'}]},
}, csrf=csrf))
settings = json.loads(request('/api/admin/settings'))
request('/api/admin/settings', {'revision': settings['revision'], 'organization': 'CI organization'}, csrf=csrf)
subprocess.run(['docker', 'exec', CONTAINER, 'python', '-c',
                'import os,stat; assert os.getuid() == 10001; '
                'assert stat.S_IMODE(os.stat("/data/.settings-key").st_mode) == 0o600'], check=True)
subprocess.run(['docker', 'restart', CONTAINER], check=True, stdout=subprocess.DEVNULL)
wait_for_health()
assert json.loads(request('/api/session'))['user']['name'] == 'ci-owner'
assert any(item['id'] == record['id'] for item in json.loads(request('/api/records')))
assert json.loads(request('/api/admin/settings'))['organization'] == 'CI organization'
assert 'Create your administrator' not in request('/setup')
print('Container setup, non-root execution, and restart persistence checks passed.')
