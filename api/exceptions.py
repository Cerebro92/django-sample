from django.conf import settings
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.http import Http404
from rest_framework.views import exception_handler
from rest_framework import exceptions, serializers, status


def custom_exception_handler(exc, context):
    print(exc)
    # Get correct custom exception
    for entry in exceptions_map:
        if isinstance(exc, entry['exception']):
            # Catch special cases for ValidationError and MethodNotAllowed
            if entry['exception'] == exceptions.ValidationError:
                exc = ValidationError(errors=exc.detail)
            elif entry['exception'] == exceptions.MethodNotAllowed:
                exc = MethodNotAllowed(detail=exc.detail)
            else:
                exc = entry['custom_exception']()
            break

    # Get standard error response
    response = exception_handler(exc, context)

    if response is not None:
        response.data['code'] = exc.detail.code
        if hasattr(exc, 'errors'):
            response.data['errors'] = exc.errors

    return response


class BadRequest(exceptions.APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Bad Request.'
    default_code = 4001


class ValidationError(exceptions.APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Field(s) missing or invalid.'
    default_code = 4002

    def __init__(self, detail=None, code=None, errors=None):
        super().__init__(detail, code)

        if errors:
            self.errors = errors


class ParseError(exceptions.ParseError):
    default_code = 4003


class AuthenticationFailed(exceptions.AuthenticationFailed):
    default_code = 4011


class NotAuthenticated(exceptions.NotAuthenticated):
    default_code = 4012


class VerificationFailed(exceptions.APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Verification code invalid or expired.'
    default_code = 4013


class NotVerified(exceptions.APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'User not verified.'
    default_code = 4014


class PermissionDenied(exceptions.PermissionDenied):
    default_code = 4031


class NotFound(exceptions.NotFound):
    default_code = 4041


class MethodNotAllowed(exceptions.APIException):
    status_code = status.HTTP_405_METHOD_NOT_ALLOWED

    def __init__(self, detail):
        super().__init__(detail=detail)
        self.detail.code = 4051


class InternalServerError(exceptions.APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Internal Server Error.'
    default_code = 5001


class EmailError(exceptions.APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Error sending email.'
    default_code = 5002


class ExternalServiceUnavailable(exceptions.APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'Error connecting to external resource.'
    default_code = '5031'


exceptions_map = [
    {
        'exception': serializers.ValidationError,
        'custom_exception': ValidationError
    },
    {
        'exception': exceptions.ParseError,
        'custom_exception': ParseError
    },
    {
        'exception': exceptions.AuthenticationFailed,
        'custom_exception': AuthenticationFailed
    },
    {
        'exception': exceptions.NotAuthenticated,
        'custom_exception': NotAuthenticated
    },
    {
        'exception': exceptions.PermissionDenied,
        'custom_exception': PermissionDenied
    },
    {
        'exception': DjangoPermissionDenied,
        'custom_exception': PermissionDenied
    },
    {
        'exception': exceptions.NotFound,
        'custom_exception': NotFound
    },
    {
        'exception': Http404,
        'custom_exception': NotFound
    },
    {
        'exception': exceptions.MethodNotAllowed,
        'custom_exception': MethodNotAllowed
    },
    {
        'exception': AssertionError,
        'custom_exception': BadRequest
    }
]

# If debug is false, catch all errors and return formatted error
if not settings.DEBUG:
    exceptions_map.append({
        'exception': Exception,
        'custom_exception': InternalServerError
    })
