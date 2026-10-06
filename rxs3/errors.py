class ManagerError(Exception):
    """Only static, non-secret messages may be displayed to the operator."""


class RemoteError(ManagerError):
    def __init__(self, system, status=0):
        self.system, self.status = system, status
        super().__init__(f"{system}: HTTP {status}" if status else f"{system}: сеть/TLS/формат ответа")


S3_ERROR_CODES = frozenset({
    'AccessDenied', 'InvalidAccessKeyId', 'SignatureDoesNotMatch',
    'RequestTimeTooSkewed', 'RequestExpired', 'AuthorizationHeaderMalformed',
    'InvalidToken', 'ExpiredToken', 'NoSuchBucket', 'NoSuchBucketPolicy',
    'NoSuchWebsiteConfiguration', 'ObjectLockConfigurationNotFoundError',
    'BucketAlreadyExists', 'BucketAlreadyOwnedByYou', 'NotImplemented',
    'InvalidArgument', 'InvalidRequest', 'ServiceUnavailable', 'SlowDown',
})


class CloudError(RemoteError):
    """Only a local operation label and an allowlisted provider code are exposed."""
    def __init__(self, operation, status=0, code=''):
        self.operation = operation
        self.code = code if code in S3_ERROR_CODES else ''
        super().__init__('VK S3', status)
        details = f'HTTP {status}' if status else 'сеть/TLS/таймаут'
        self.args = (f'VK S3: {operation}: {details}' + (f' ({self.code})' if self.code else ''),)

    def hint(self):
        if self.code == 'InvalidAccessKeyId':
            return 'VK не распознал Access Key ID. Проверьте действующий ключ аккаунта Object Storage и регион Москва.'
        if self.code == 'SignatureDoesNotMatch':
            return 'Подпись не совпала. Проверьте, что Access Key ID и Secret Key скопированы из одной пары; также проверьте время VPS.'
        if self.code in ('RequestTimeTooSkewed', 'RequestExpired'):
            return 'Проверьте дату и синхронизацию времени VPS: timedatectl status.'
        if self.status == 403:
            return ('VK отказал именно этому запросу. Нужна активная пара из Object Storage → Аккаунты, '
                    'не ключ из вкладки бакета. Проверьте проект, регион Москва и доступ аккаунта к бакету. '
                    '403 не доказывает, что бакета нет; приватность бакета не отключайте.')
        if self.status == 404:
            return 'Проверьте точное имя бакета и регион Москва. При создании вручную используйте раздел Object Storage → Бакеты.'
        if not self.status:
            return 'Проверьте доступ VPS к VK по HTTPS, DNS и системное время. Секреты в сообщения поддержки не присылайте.'
        return 'Проверьте этот API-запрос и настройки доступа в VK. Публичный доступ включать не нужно.'
