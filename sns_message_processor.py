from exceptions import (
    InvalidMessageTypeException, 
    InvalidCertURLException, 
    InvalidSignatureVersionException, 
    SignatureVerificationFailureException
)
from sns_message_verifier import SNSMessageVerifier


sns_message_validator = SNSMessageVerifier()


class SNSMessageProcessor:
    """Handles AWS SNS message validation & processing."""

    def __init__(self, request, message):
        """Initialize validator with request."""
        self.request = request
        self.message = message
        self.message_type = self.get_message_type()

    def get_message_type(self):
        """Extract and validate SNS message type from headers."""
        message_type = self.request.headers.get("x-amz-sns-message-type")
        try:
            sns_message_validator.validate_message_type(message_type)
        except InvalidMessageTypeException as ex:
            raise InvalidMessageTypeException(
                f"Invalid SNS message type: {message_type}"
            ) from ex

        return message_type

    def validate_topic_arn(self):
        """Validate that the SNS message comes from an expected TopicArn."""
        topic_arn = self.message.get("TopicArn")
        allowed_topic_arn = settings.SCHEDULE_SIGNUP_EMAIL_TOPIC_ARN

        if not topic_arn or topic_arn != allowed_topic_arn:
            raise ValidationError({
                "error": f"Unauthorized SNS topic: {topic_arn}."
            })

    def validate_message(self):
        """Perform SNS message validation (e.g., certificate URL, signature)."""
        try:
            # Validate SigningCertURL, SignatureVersion, and Signature
            sns_message_validator.validate_message(message=self.message)

        except InvalidCertURLException as ex:
            raise ValidationError({"error": "Invalid certificate URL."}) from ex

        except InvalidSignatureVersionException as ex:
            raise ValidationError({"error": "Unexpected signature version."}) from ex

        except SignatureVerificationFailureException as ex:
            raise ValidationError({"error": "Failed to verify signature."}) from ex

    def process_message(self):
        """Process SNS message based on its type."""
        self.validate_message()

        if self.message_type == "SubscriptionConfirmation":
            return self.confirm_subscription()
        elif self.message_type == "UnsubscribeConfirmation":
            return self.confirm_unsubscription()

        print("SNS message processed successfully.")

    def confirm_subscription(self):
        """Confirm SNS subscription."""
        subscribe_url = self.message.get("SubscribeURL")
        response = requests.get(subscribe_url)
        if response.status_code != 200:
            raise ValidationError({"error": "Request to SubscribeURL failed. Unable to confirm subscription."})

    def confirm_unsubscription(self):
        """Confirm SNS unsubscription."""
        unsubscribe_url = self.message.get("UnsubscribeURL")
        response = requests.get(unsubscribe_url)
        if response.status_code != 200:
            raise ValidationError({"error": "Request to UnsubscribeURL failed. Unable to unsubscribe subscription."})
