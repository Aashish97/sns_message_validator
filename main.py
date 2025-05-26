from rest_framework.exceptions import ValidationError
from rest_framework.request import Request

from exceptions import InvalidMessageTypeException
from sns_message_processor import SNSMessageProcessor


def validate_sns_message(request: Request, message: dict):
  """Main method to validate sns message from aws
  
  :param request: request from django view
  :param message: message sent by the aws sns
    Note: make sure you convert it to dict first (eg: json.loads(request.body)) to check
          if valid request body is provided or not
  """
  try:
      validator = SNSMessageProcessor(request, message)
      validator.process_message()

  except InvalidMessageTypeException as ex:
      # log exception here
      print("Something went wrong, error:", str(ex))
      raise ex

  except ValidationError as ex:
      # log exception here
      print("Something went wrong, error:", str(ex))
      raise ex
