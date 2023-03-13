from django.contrib.auth import authenticate, get_user_model
from rest_framework import generics, permissions, status, views
from rest_framework.response import Response
from ...exceptions import (
    AuthenticationFailed,
    NotFound,
    PermissionDenied
)
from ...utils import validate_required_fields
from .serializers import UserSerializer,InviteSerializer
from .utils import (
    check_verification_token,
    create_user,
    get_logged_in_user_response,
    update_or_create_auth_token,
    update_or_create_verification_token,
)
from .models import Invite



class LogInView(views.APIView):
    """
    View to log in a user and obtain an auth token.

    * No authentication.
    * Requires email and password.
    * Returns user object and token.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        password = request.data.get('password')
        print(email,password)
        validate_required_fields({'email': email, 'password': password})

        user = authenticate(username=email, password=password)
        if user is None:
            raise AuthenticationFailed
        else:
            return get_logged_in_user_response(user, status.HTTP_200_OK)


class CreateUserView(generics.CreateAPIView):
    """
    View to create a new user and send verification email.

    * No authentication.
    * Requires email, password, first_name, last_name.
    * Returns user object and token.
    """
    User = get_user_model()
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        user = create_user(request.data)

        return get_logged_in_user_response(user, status=status.HTTP_201_CREATED)


class RetrieveUserView(views.APIView):
    """
    View to retrieve a user's information with an auth token.

    * Authentication required.
    * Returns user object and token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return get_logged_in_user_response(
            request.user,
            status=status.HTTP_200_OK,
        )


class VerifyUserView(views.APIView):
    """
    View to verify a user account.

    * Authentication required.
    * Requires verification_token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        submitted_token = request.data.get('verification_token', '').strip()
        validate_required_fields({'verification_token': submitted_token})

        user = request.user
        verified_token = check_verification_token(submitted_token, user)

        user.is_verified = True
        user.save()
        verified_token.is_active = False
        verified_token.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class ResendVerificationEmailView(views.APIView):
    """
    View to request an account verification email to be resent.

    * Authentication required.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        verification_token = update_or_create_verification_token(request.user)
        print(verification_token)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ForgotPasswordView(views.APIView):
    """
    View to request a reset password email to be sent.

    * Requires email.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        validate_required_fields({'email': email})
        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            print('User not found.')
        else:
            verification_token = update_or_create_verification_token(user)
            print(verification_token)

        return Response(status=status.HTTP_204_NO_CONTENT)


class ResetPasswordView(views.APIView):
    """
    View to reset a password using a token from email.

    * Requires email, password, verification_token.
    * Returns user object and token.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        password = request.data.get('password')
        submitted_token = request.data.get('verification_token', '').strip()
        validate_required_fields({
            'email': email,
            'password': password,
            'verification_token': submitted_token,
        })

        User = get_user_model()

        try:
            user = User.objects.get(email=email)
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            raise NotFound
        else:
            verified_token = check_verification_token(submitted_token, user)
            user.set_password(password)
            user.save()

            verified_token.is_active = False
            verified_token.save()
            update_or_create_auth_token(user)

            return get_logged_in_user_response(user, status.HTTP_200_OK)


class ChangePasswordView(views.APIView):
    """
    View to change a user's password.

    * Authentication required.
    * Requires current_password and new_password.
    * Returns token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        validate_required_fields({
            'current_password': current_password,
            'new_password': new_password,
        })

        user = authenticate(
            username=request.user.email,
            password=current_password,
        )
        if user is None:
            raise AuthenticationFailed
        elif user != request.user:
            raise PermissionDenied
        else:
            user.set_password(new_password)
            user.save()

            update_or_create_auth_token(user)

            return get_logged_in_user_response(
                user,
                status=status.HTTP_200_OK,
            )


class ChangeEmailView(views.APIView):
    """
    View to change a user's email.

    * Authentication required.
    * Requires email.
    * Returns user object and token.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        email = request.data.get('email', '').strip().lower()
        validate_required_fields({'email': email})

        serializer = UserSerializer(
            request.user,
            data={'email': email},
            partial=True
        )
        serializer.is_valid(raise_exception=True)

        request.user.email = email
        request.user.username = email
        request.user.is_verified = False
        request.user.save()
        update_or_create_auth_token(request.user)

        verification_token = update_or_create_verification_token(request.user)
        print(verification_token)

        return get_logged_in_user_response(
            request.user,
            status=status.HTTP_200_OK,
        )


class UpdateUserView(views.APIView):
    """
    View to update a user's profile.

    * Authentication required.
    * Returns user object.
    """
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return get_logged_in_user_response(
            request.user,
            status=status.HTTP_200_OK,
        )

class CreateInviteView(views.APIView):
    """
    View to create an invite for a new user.

    * Authentication required.
    * Returns the unique id for the new invite.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = InviteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        invite = serializer.save()
        return Response({'id': str(invite.id)}, status=status.HTTP_201_CREATED)

class AcceptInviteView(views.APIView):
    """
    View to accept an invite and create a new user.

    * Authentication required.
    * Expects the invite id in the URL (e.g. /invites/accept/1234/)
    * Returns the new user object.
    """
    permission_classes = [permissions.AllowAny] # allowing any since the invited person is not yet a user..

    def post(self, request, invite_id, *args, **kwargs):
        invite = Invite.objects.get(id=invite_id, is_active=True)
        user_data = {
            'email': invite.email,
            'first_name': invite.first_name,
            'last_name': invite.last_name,
            'password':"123456" # assigning a random password for now...
        }
        serializer = UserSerializer(data=user_data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        invite.is_active = False
        invite.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class RetrieveInviteView(views.APIView):
    """
    View to retrieve an invite's details given an ID.

    * Authentication required.
    * Returns the invite object.
    """
    permission_classes = [permissions.AllowAny] 

    def get(self, request, invite_id, *args, **kwargs):
        invite = Invite.objects.filter(id=invite_id).first()
        if invite is None:
            return Response({'error': 'Invite not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = InviteSerializer(invite)
        return Response(serializer.data, status=status.HTTP_200_OK)