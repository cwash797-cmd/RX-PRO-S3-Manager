class ManagerError(Exception):
    """Only static, non-secret messages may be displayed to the operator."""


class RemoteError(ManagerError):
    def __init__(self, system, status=0):
        self.system, self.status = system, status
        super().__init__(f"{system}: HTTP {status}" if status else f"{system}: сеть/TLS/формат ответа")
