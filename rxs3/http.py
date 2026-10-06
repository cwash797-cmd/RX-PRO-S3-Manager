import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .errors import ManagerError, RemoteError, S3_ERROR_CODES
from .profiles import safe_name


def managed_comment(user):
    return 'RXS3 managed | ' + safe_name(user['name'])


def safe_s3_error(data):
    """Discard Message, RequestId, StringToSign, credentials and unknown codes."""
    if len(data) > 16384 or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        return b''
    try:
        root = ET.fromstring(data)
        codes = [e.text for e in root.iter() if e.tag.rsplit('}', 1)[-1] == 'Code']
        if len(codes) == 1 and codes[0] in S3_ERROR_CODES:
            return ('<Error><Code>' + codes[0] + '</Code></Error>').encode()
    except (ET.ParseError, ValueError):
        pass
    return b''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_panel_url(url):
    p = urllib.parse.urlsplit(url)
    if p.username or p.password or p.query or p.fragment or not p.hostname:
        raise ManagerError("URL панели не должен содержать логин, пароль, query или fragment")
    local = p.hostname == 'localhost'
    try: local |= ipaddress.ip_address(p.hostname).is_loopback
    except ValueError: pass
    if p.scheme != 'https' and not (p.scheme == 'http' and local):
        raise ManagerError("HTTP разрешён только для localhost; для удалённой панели нужен HTTPS")
    return url.rstrip('/')


def request(url, method='GET', headers=None, body=None, system='HTTP', timeout=20):
    # Ignore proxy environment variables: never send credentials to an implicit proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with opener.open(req, timeout=timeout) as response:
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024: raise RemoteError(system)
            return response.status, data
    except urllib.error.HTTPError as error:
        try:
            data = safe_s3_error(error.read(16385)) if system == 'VK S3' else b''
            return error.code, data
        finally:
            error.close()
    except (OSError, ValueError, urllib.error.URLError):
        raise RemoteError(system) from None


class Panel:
    def __init__(self, url, token):
        self.url = validate_panel_url(url)
        self.token = token

    def call(self, path, data=None):
        body = json.dumps(data).encode() if data is not None else None
        status, content = request(self.url + '/panel/api/' + path,
            'POST' if data is not None else 'GET',
            {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'}, body, '3x-ui')
        if status != 200: raise RemoteError('3x-ui', status)
        try:
            result = json.loads(content)
            if result.get('success') is not True: raise RemoteError('3x-ui', status)
            return result.get('obj')
        except (ValueError, AttributeError): raise RemoteError('3x-ui') from None

    def inbounds(self):
        result = self.call('inbounds/list')
        if not isinstance(result, list): raise RemoteError('3x-ui')
        return result

    def clients(self):
        # The list endpoint embeds ClientRecord flat; GET /get uses a nested
        # `client` envelope. Reject malformed rows rather than implying absence.
        result = self.call('clients/list')
        if not isinstance(result, list): raise RemoteError('3x-ui')
        records = []
        for row in result:
            if (not isinstance(row, dict) or not isinstance(row.get('email'), str)
                    or not isinstance(row.get('uuid'), str)
                    or not isinstance(row.get('enable'), bool)
                    or not isinstance(row.get('inboundIds'), (list, type(None)))):
                raise RemoteError('3x-ui')
            traffic = row.get('traffic') or {}
            if not isinstance(traffic, dict): raise RemoteError('3x-ui')
            used = traffic.get('up', 0) + traffic.get('down', 0)
            if not isinstance(used, int) or used < 0: raise RemoteError('3x-ui')
            records.append({'client': row, 'inboundIds': row['inboundIds'] or [],
                            'usedTraffic': used})
        return records

    def client(self, email):
        # A failed API request is NEVER interpreted as a missing user.
        matches = [u for u in self.clients() if u.get('client', {}).get('email') == email]
        if len(matches) > 1: raise ManagerError("Дублирующиеся клиенты в панели")
        return matches[0] if matches else None

    def create_client(self, user, inbound):
        self.call('clients/add', {'client': {'email': user['email'], 'id': user['uuid'],
            'subId': user['sub_id'], 'enable': True, 'flow': '', 'totalGB': user['quota'],
            'expiryTime': user['expires'], 'comment': managed_comment(user), 'limitIp': 0,
            'tgId': 0, 'reset': 0, 'trafficReset': 'never'}, 'inboundIds': [inbound]})

    def update_client(self, record, **changes):
        # v3.9.0 returns ClientRecord.id (integer) and uuid; update expects Client.id (UUID).
        source = record['client']
        keep = ['email','enable','expiryTime','flow','totalGB','limitIp','limitHwid','tgId',
                'comment','subId','reset','resetDay','resetMax','resetWeekday','trafficReset',
                'trafficResetDay','security','group','reverse']
        payload = {k: source[k] for k in keep if k in source}
        payload['id'] = source['uuid']
        payload.update(changes)
        self.call('clients/update/' + urllib.parse.quote(source['email'], safe=''), payload)

    def set_inbound_encryption(self, record, encryption):
        # 3x-ui stores this public client-side value in settings for its UI/link
        # generator. Keep the server decryption key and all existing clients.
        payload = json.loads(json.dumps(record))
        settings = payload['settings']
        if isinstance(settings, str): settings = json.loads(settings)
        settings['encryption'] = encryption
        payload['settings'] = settings
        self.call('inbounds/update/' + str(record['id']), payload)

    def delete_client(self, email):
        self.call('clients/del/' + urllib.parse.quote(email, safe='') + '?keepTraffic=1', {})
