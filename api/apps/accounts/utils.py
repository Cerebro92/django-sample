import os
import uuid
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from ...exceptions import InternalServerError, NotFound, VerificationFailed
from .models import VerificationToken
from .serializers import UserSerializer


WEB_BASE_URL = os.environ.get('WEB_BASE_URL')


def get_auth_token(user):
    """
    Retrieve an auth_token for the specified user.
    """
    try:
        token = Token.objects.get(user=user)
    except (Token.DoesNotExist, Token.MultipleObjectsReturned):
        raise InternalServerError
    else:
        return token


def update_or_create_auth_token(user):
    """
    Update or create an auth_token for the specified user.
    """
    try:
        token, created = Token.objects.get_or_create(user=user)
    except Token.MultipleObjectsReturned:
        raise InternalServerError
    else:
        if not created:
            token.delete()
            token = Token.objects.create(user=user)
        return token


def update_or_create_verification_token(user):
    """
    Update or create a new verification token for a user.
    """
    verification_token, _ = VerificationToken.objects.update_or_create(
        user=user,
        defaults={'token': uuid.uuid4(), 'is_active': True}
    )
    return verification_token


def create_user(data):
    serializer = UserSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    update_or_create_auth_token(user)
    update_or_create_verification_token(user)

    return user


def check_verification_token(submitted_token, user):
    """
    Check that verification token belongs to user and is active.
    """
    try:
        verification_token = VerificationToken.objects.get(user=user)
    except (
        VerificationToken.DoesNotExist,
        VerificationToken.MultipleObjectsReturned
    ):
        raise NotFound
    else:
        if (
            verification_token.token != uuid.UUID(submitted_token)
            or not verification_token.is_valid()
        ):
            raise VerificationFailed
        else:
            return verification_token


def get_logged_in_user_response(user, status):
    """
    Form a response object for a logged in user.
    """
    token = get_auth_token(user)
    user_data = UserSerializer(user).data

    return Response({
        'user': user_data,
        'token': token.key,
    }, status=status)
