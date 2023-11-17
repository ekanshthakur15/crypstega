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

class SteganographyImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = SteganographyImage
        fields = '__all__'
