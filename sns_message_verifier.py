import re
import base64
import requests

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.exceptions import InvalidSignature

from sns_message_type import SNSMessageType
from exceptions import (
    InvalidSignatureVersionException,
    InvalidCertURLException,
    InvalidMessageTypeException,
    SignatureVerificationFailureException,
)

_DEFAULT_CERTIFICATE_URL_REGEX = r'^https://sns\.[-a-z0-9]+\.amazonaws\.com/'


class SNSMessageVerifier:
    def __init__(self,
                 cert_url_regex=_DEFAULT_CERTIFICATE_URL_REGEX,
                 signature_version='1'):
        self._cert_url_regex = cert_url_regex
        self._signature_version = signature_version

    @staticmethod
    def _get_public_key(cert_url):
        """Fetch and load AWS SNS public key from SigningCertURL"""
        response = requests.get(cert_url)
        response.raise_for_status()
        return response.content

    def _validate_signature_version(self, message):
        if message.get('SignatureVersion') != self._signature_version:
            raise InvalidSignatureVersionException('Invalid signature version. Unable to verify signature.')

    def _validate_cert_url(self, message):
        cert_url = message.get('SigningCertURL')
        if not cert_url:
            raise InvalidCertURLException('Could not find SigningCertURL field in message.')
        if not re.search(self._cert_url_regex, cert_url):
            raise InvalidCertURLException('Invalid certificate URL.')

    @staticmethod
    def _get_plaintext_to_sign(message):
        message_type = message.get('Type')
        keys = ['Message', 'MessageId', 'Timestamp', 'TopicArn', 'Type']
        if message_type in [
            SNSMessageType.SubscriptionConfirmation.value,
            SNSMessageType.UnsubscribeConfirmation.value,
        ]:
            keys += ['SubscribeURL', 'Token']

        elif message_type == SNSMessageType.Notification.value and message.get('Subject'):
            keys += ['Subject']

        pairs = [f'{key}\n{message.get(key)}' for key in keys]
        return '\n'.join(pairs) + '\n'

    def _verify_signature(self, message):
        try:
            pem = self._get_public_key(message.get("SigningCertURL"))
        except Exception as e:
            raise SignatureVerificationFailureException(
                'Failed to fetch cert file.'
            ) from e

        cert = x509.load_pem_x509_certificate(pem, default_backend())
        public_key = cert.public_key()
        plaintext = self._get_plaintext_to_sign(message).encode()
        signature = base64.b64decode(message.get('Signature'))
        try:
            public_key.verify(
                signature,
                plaintext,
                PKCS1v15(),
                SHA1(),
            )
        except InvalidSignature as e:
            raise SignatureVerificationFailureException('Invalid signature.') from e

    @staticmethod
    def validate_message_type(message_type: str):
        try:
            sns_message_type: SNSMessageType = SNSMessageType(message_type)
        except ValueError as e:
            raise InvalidMessageTypeException(
                f'{message_type} is not a valid message type.'
            ) from e

    def validate_message(self, message):
        self.validate_message_type(message.get('Type'))
        self._validate_signature_version(message)
        self._validate_cert_url(message)
        self._verify_signature(message)
