class OpenIDError(Exception):
    def __init__(self, message, response_status, response_body):
        self.message = message
        self.response_status = response_status
        self.response_body = response_body
