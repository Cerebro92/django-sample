from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.response import Response
from .models import Invites
from uuid import uuid4
from rest_framework.serializers import ModelSerializer


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for custom user model.
    """

    full_name = serializers.SerializerMethodField()

    class Meta:
        User = get_user_model()
        model = User
        fields = [
            "id",
            "email",
            "password",
            "first_name",
            "last_name",
            "full_name",
            "is_verified",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def create(self, validated_data):
        User = get_user_model()

        # Add username to the objects before creation
        validated_data["username"] = validated_data["email"]
        return User.objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        # Ensure that the email and password never get updated this way
        validated_data.pop("email", None)
        validated_data.pop("password", None)
        return super().update(instance, validated_data)

    def get_full_name(self, obj):
        return obj.get_full_name()


class InvitesSeirializer(ModelSerializer):
    def update(self, instance, validated_data):
        user_data = instance.__dict__
        user_data["password"] = uuid4().__str__()
        serializer = UserSerializer(data=user_data)
        serializer.is_valid(raise_exception=True)  # Validation of User Data
        user_obj = serializer.create(
            {
                "email": user_data["email"],
                "password": user_data["password"],
                "first_name": user_data["first_name"],
                "last_name": user_data["last_name"],
            }
        )  # User Creation
        validated_data["is_active"] = False  # Updating is_active to False of the Invite
        return super().update(instance, validated_data)

    class Meta:
        model = Invites
        fields = "__all__"
