from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Invite


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for custom user model.
    """
    full_name = serializers.SerializerMethodField()

    class Meta:
        User = get_user_model()
        model = User
        fields = [
            'id',
            'email',
            'password',
            'first_name',
            'last_name',
            'full_name',
            'is_verified',
        ]
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        User = get_user_model()

        # Add username to the objects before creation
        validated_data['username'] = validated_data['email']
        return User.objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        # Ensure that the email and password never get updated this way
        validated_data.pop('email', None)
        validated_data.pop('password', None)
        return super().update(instance, validated_data)

    def get_full_name(self, obj):
        return obj.get_full_name()

class InviteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invite
        fields = ['email', 'first_name', 'last_name','is_active']

    def create(self, validated_data):
        return Invite.objects.create(**validated_data)
