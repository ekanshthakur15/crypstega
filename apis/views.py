
from cryptography.fernet import Fernet
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import *
from .serializers import *


# Working API
class FileListView(APIView):
    def get(self, request):
        try:
            query_set = EncryptedFile.objects.filter(user = request.user)
        except EncryptedFile.DoesNotExist:
            return Response(status= status.HTTP_404_NOT_FOUND)
        files = []
        for file in query_set:
            data = {
                "file_name" : file.file_name,
                "upload_date": file.uploaded_at
            }
            files.append(data)
        return Response(files, status= status.HTTP_200_OK)
    

class Encryption(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        user = request.user
        original_file = request.data.get('file')
        if not original_file:
            return Response({'error': 'File is required'}, status= status.HTTP_400_BAD_REQUEST)
    


        #image = request.FILES.image('image')

        original_data = original_file.read()

        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(original_data)
        
        original_file.seek(0)  # Reset file pointer to the beginning
        original_file.write(encrypted_data)

        # Create a new EncryptedFile instance with the original file
        encrypted_file = EncryptedFile(
            user=user,
            # Assuming you have 'file_name' in your request data
            file_name=request.data.get('file_name'),
            file=original_file  # Store the original file
        )
        encrypted_file.save()

        return Response({"key": key, 'file_id': encrypted_file.id}, status= status.HTTP_201_CREATED)
        #return Response(serializer.errors, status= status.HTTP_400_BAD_REQUEST)

class Decryption(APIView):

    def post(self, request, *args, **kwargs):
        file_id = request.data.get('file_id')
        key = request.data.get('key')
        try:
            if not key:
                return Response({"error": "Key is required"}, status= status.HTTP_400_BAD_REQUEST)
            try:
                encrypted_file = EncryptedFile.objects.get(id = file_id)
            except EncryptedFile.DoesNotExist:
                return Response({'detail': "The requested File doesn't exist"}, status= status.HTTP_404_NOT_FOUND)
            
            encrypted_data = encrypted_file.file.read()

            cipher = Fernet(key)
            decrypted_data = cipher.decrypt(encrypted_data)

            filename = f"{encrypted_file.file_name}_decrypted.txt"
            with open(filename, 'w') as file:
                file.write(decrypted_data.decode('utf-8'))

            # Return the file for download
            with open(filename, 'rb') as response_file:
                response = Response(response_file.read(),
                                    content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename={filename}'

            return response
        
        except Exception as e:
            return Response({'details': e}, status= status.HTTP_400_BAD_REQUEST)
        #return Response({"encrypted_data": encrypted_data,"decrypted_data":decrypted_data}, status= status.HTTP_200_OK)


