from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import *


class EncryptedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptedFile
        fields = '__all__'

    def create(self, validated_data):
        # Ensure 'user' is set during the creation of the EncryptedFile instance
        user = self.context.get('user')
        validated_data['user'] = user
        return super().create(validated_data)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = get_user_model().objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    username = models.CharField()
    password = models.CharField()