"""VK-specific Prefix Access Keys (PAK), not AWS IAM. SigV4 without SDK credential discovery."""
import datetime
import hashlib
import hmac
import re
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

from .http import request
from .errors import ManagerError, RemoteError, CloudError

HOSTS = {'https://hb.ru-msk.vkcloud-storage.ru', 'https://hb.vkcloud-storage.ru'}


def local(tag): return tag.rsplit('}', 1)[-1]


def parse_xml(data):
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise RemoteError('VK XML')
    try: return ET.fromstring(data)
    except ET.ParseError: raise RemoteError('VK XML') from None


def fields(root): return {local(e.tag): e.text or '' for e in root.iter() if len(e) == 0}


def validate_bucket(name):
    if (not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', name)
            or name.startswith('xn--')):
        raise ManagerError("Бакет: 3–63 строчных латинских символа/цифры/дефисы, без точек")
    return name


def sigv4(method, url, query, body, access, secret, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime('%Y%m%dT%H%M%SZ'); day = stamp[:8]
    p = urllib.parse.urlsplit(url)
    enc = lambda s: urllib.parse.quote(str(s), safe='-_.~')
    canonical_query = '&'.join(k+'='+v for k,v in sorted((enc(k),enc(v)) for k,v in query.items()))
    payload = hashlib.sha256(body).hexdigest()
    headers = {'host': p.netloc, 'x-amz-content-sha256': payload, 'x-amz-date': stamp}
    signed = ';'.join(sorted(headers))
    canonical = '\n'.join([method, p.path or '/', canonical_query,
        ''.join(k+':'+headers[k]+'\n' for k in sorted(headers)), signed, payload])
    scope = day+'/ru-msk/s3/aws4_request'
    message = 'AWS4-HMAC-SHA256\n'+stamp+'\n'+scope+'\n'+hashlib.sha256(canonical.encode()).hexdigest()
    key = ('AWS4'+secret).encode()
    for value in [day,'ru-msk','s3','aws4_request']:
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key,message.encode(),hashlib.sha256).hexdigest()
    headers['Authorization'] = f'AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={signature}'
    return url + ('?'+canonical_query if canonical_query else ''), headers


class S3:
    def __init__(self, endpoint, bucket, access, secret):
        if endpoint not in HOSTS: raise ManagerError("Поддерживается только VK Object Storage Москва")
        self.endpoint, self.bucket = endpoint, validate_bucket(bucket)
        self.access, self.secret = access, secret

    def call(self, method, key='', query=None, body=b'', expected=(200,204), account=False):
        path = '/' if account else '/' + self.bucket
        if key: path += '/' + urllib.parse.quote(key, safe='/-_.~')
        url, headers = sigv4(method,self.endpoint+path,query or {},body,self.access,self.secret)
        operation = 'ListBuckets' if account else self.operation(method, key, query or {})
        try:
            status, data = request(url,method,headers,body,'VK S3')
        except RemoteError:
            raise CloudError(operation) from None
        if status not in expected:
            code = ''
            if data:
                try: code = fields(parse_xml(data)).get('Code', '')
                except RemoteError: pass
            raise CloudError(operation, status, code)
        return data if status < 400 else b''

    @staticmethod
    def operation(method, key, query):
        if 'pak' in query:
            return {'GET': 'ListPrefixKeys', 'PUT': 'CreatePrefixKey', 'DELETE': 'DeletePrefixKey'}.get(method, 'PAK')
        for field, name in {'versioning': 'GetBucketVersioning', 'object-lock': 'GetObjectLockConfiguration',
                            'acl': 'GetBucketAcl', 'policy': 'GetBucketPolicy', 'website': 'GetBucketWebsite',
                            'list-type': 'ListObjectsV2'}.items():
            if field in query: return name
        if key: return {'GET': 'GetObject', 'PUT': 'PutObject', 'DELETE': 'DeleteObject'}.get(method, 'ObjectRequest')
        return {'HEAD': 'HeadBucket', 'PUT': 'CreateBucket'}.get(method, 'BucketRequest')

    def check_account(self):
        # Read-only account-scope request: useful error XML, unlike HEAD, and
        # distinguishes account credentials from bucket/prefix-only credentials.
        root = parse_xml(self.call('GET', account=True))
        if local(root.tag) != 'ListAllMyBucketsResult': raise RemoteError('VK ListBuckets XML')

    def create_bucket(self): self.call('PUT')

    def check_bucket(self):
        self.call('HEAD')
        version = fields(parse_xml(self.call('GET',query={'versioning':''})))
        if version.get('Status') in ('Enabled','Suspended'):
            raise ManagerError("Для транспорта нужен новый бакет без истории версионирования")
        # Even enabled-but-unused Object Lock is rejected; no destructive policy changes.
        data = self.call('GET',query={'object-lock':''},expected=(200,404))
        if data and fields(parse_xml(data)).get('ObjectLockEnabled') == 'Enabled':
            raise ManagerError("Бакет с Object Lock не поддерживается")
        acl = parse_xml(self.call('GET', query={'acl': ''}))
        owners = [fields(e).get('ID') for e in acl if local(e.tag) == 'Owner']
        if len(owners) != 1 or not owners[0]: raise RemoteError('VK ACL')
        grants = [fields(e) for e in acl.iter() if local(e.tag) == 'Grant']
        if not grants or any(g.get('ID') != owners[0] or 'URI' in g for g in grants):
            raise ManagerError("Нужен приватный бакет: ACL разрешает доступ не только владельцу")
        # A dedicated bucket needs no bucket policy or website. Reject even a
        # restrictive policy: do not try to implement a partial IAM evaluator.
        policy = self.call('GET', query={'policy': ''}, expected=(200, 404))
        if policy:
            raise ManagerError("Для первой версии нужен отдельный бакет без bucket policy")
        website = self.call('GET', query={'website': ''}, expected=(200, 404))
        if website: raise ManagerError("Бакет с website hosting не поддерживается")

    def list_keys(self):
        result=[]; marker=''; seen=set()
        for _ in range(1000):
            query={'pak':'','max-keys':'1000'}
            if marker: query['marker']=marker
            root=parse_xml(self.call('GET',query=query))
            meta = fields(root)
            if meta.get('BucketName') != self.bucket or meta.get('IsTruncated') not in ('true', 'false'):
                raise RemoteError('VK PAK list')
            page=[]
            for item in root.iter():
                if local(item.tag)=='Contents':
                    entry=fields(item)
                    if not entry.get('UserName') or not entry.get('Prefix'):
                        raise RemoteError('VK PAK list')
                    page.append(entry)
            result.extend(page)
            if fields(root).get('IsTruncated','false').lower()!='true': return result
            if not page: raise RemoteError('VK pagination')
            marker=page[-1]['UserName']
            if marker in seen: raise RemoteError('VK pagination')
            seen.add(marker)
        raise ManagerError("Слишком большой список ключей VK")

    def create_key(self, name, prefix):
        root=parse_xml(self.call('PUT',query={'pak':'','username':name,'prefix':prefix}))
        data=fields(root)
        if data.get('Prefix') != prefix or data.get('UserName') != name or data.get('BucketName') != self.bucket:
            raise ManagerError("VK вернул неожиданный scope ключа; операция требует восстановления")
        if not data.get('AccessKey') or not data.get('SecretKey'): raise RemoteError('VK PAK')
        return {'accessKey': data['AccessKey'], 'secretKey': data['SecretKey']}

    def revoke_key(self, name, prefix):
        matches=[k for k in self.list_keys() if k['UserName']==name]
        if not matches: return
        if len(matches)!=1 or matches[0]['Prefix']!=prefix:
            raise ManagerError("Отказ удаления: scope ключа VK не совпадает с реестром")
        self.call('DELETE',query={'pak':'','username':name,'prefix':prefix})
        if any(k['UserName']==name for k in self.list_keys()): raise ManagerError("VK ещё не подтвердил отзыв ключа")

    def scoped(self, key): return S3(self.endpoint,self.bucket,key['accessKey'],key['secretKey'])

    def confirm_revoked(self, key, prefix):
        # A disappeared PAK listing alone is not enough if authorization caches
        # have not expired. Keep the ledger pending until the old key is denied.
        name = prefix + 'revocation-check-' + uuid.uuid4().hex
        try:
            self.scoped(key).call('PUT', name, body=b'revocation-check')
        except RemoteError as error:
            if error.status in (401, 403): return
            raise
        self.call('DELETE', name)
        raise ManagerError('Отозванный ключ пока ещё принимается VK; повторите синхронизацию')

    def probe(self, prefix):
        name=prefix+'probe-'+uuid.uuid4().hex
        data=b'RX-PRO S3 permission probe'
        self.call('PUT',name,body=data)
        try:
            if self.call('GET',name)!=data: raise ManagerError("S3: данные проверки не совпали")
            root=parse_xml(self.call('GET',query={'list-type':'2','prefix':name,'max-keys':'10'}))
            if not any(local(e.tag)=='Key' and e.text==name for e in root.iter()): raise ManagerError("S3 LIST не видит проверочный объект")
        finally: self.call('DELETE',name)

    def purge(self, prefix, limit=10000):
        if not re.fullmatch(r'rxs3/[a-f0-9]{24}/[a-f0-9]{24}/g[0-9]+/', prefix):
            raise ManagerError("Очистка разрешена только для точного управляемого префикса поколения")
        removed=0
        while True:
            root=parse_xml(self.call('GET',query={'list-type':'2','prefix':prefix,'max-keys':'1000'}))
            keys=[e.text for e in root.iter() if local(e.tag)=='Key']
            if not keys: return removed
            for key in keys:
                if not key or not key.startswith(prefix): raise ManagerError("VK вернул объект вне префикса")
                if removed>=limit: raise ManagerError("Лимит очистки достигнут; повторите операцию")
                self.call('DELETE',key);removed+=1
