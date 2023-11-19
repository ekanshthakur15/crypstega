
import os

from cryptography.fernet import Fernet
from django.contrib.auth import authenticate, get_user_model, login
from django.views.decorators.csrf import csrf_exempt
from PIL import Image
from rest_framework import generics, permissions, status
from rest_framework.authentication import BasicAuthentication
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import *
from .serializers import *
from .utils import *


class RegisterUserView(generics.CreateAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    permission_classes = (permissions.AllowAny,)


class LoginView(APIView):
    authentication_classes = [BasicAuthentication]

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        login(request, user)  # Perform the login

        return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)

class SharedFileListView(APIView):
    def get(self, request):
        try:
            query_set = EncryptedFile.objects.filter(user = request.user)
        except EncryptedFile.DoesNotExist:
            return Response(status= status.HTTP_404_NOT_FOUND)
        files = []
        for file in query_set:
            data = {
                "file_name" : file.file_name,
                "upload_date": file.uploaded_at,
                "to": file.recepient.username
            }
            files.append(data)
        return Response(files, status= status.HTTP_200_OK)
    

class ReceivedFileListView(APIView):
    def get(self, request):
        try:
            query_set = EncryptedFile.objects.filter(recepient=request.user)
        except EncryptedFile.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        files = []
        for file in query_set:
            data = {
                "file_name": file.file_name,
                "upload_date": file.uploaded_at,
                "from": file.user.username
            }
            files.append(data)
        return Response(files, status=status.HTTP_200_OK)

class SteganoEncryption(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        user = request.user
        receiver_name = request.data.get('username')
        original_file = request.data.get('file')
        if not original_file:
            return Response({'error': 'File is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            receiver = User.objects.get(username =receiver_name)
        except User.DoesNotExist:
            return Response({"error": "Receiver doesn't exist"}, status=status.HTTP_404_NOT_FOUND)


        original_data = original_file.read()

        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(original_data)

        original_file.seek(0)
        original_file.write(encrypted_data)


        image_file = request.FILES.get('image')
        if not image_file:
            return Response({'error': 'Image is required'}, status=status.HTTP_400_BAD_REQUEST)

        key_image = Image.open(image_file)
        encrypted_image = hide_text_data(key_image, text=key)

        media_directory = 'media/encrypted_images'
        if not os.path.exists(media_directory):
            os.makedirs(media_directory)

        encrypted_image_path = os.path.join( media_directory, 'new_' + image_file.name)
        encrypted_image.save(encrypted_image_path)

        
        subject = "File sharedon CryptoKun"
        message = f"A file has been securely shared with you by {request.user.username} and the key to see it's content is the image. Thank you"
        to_email = request.data.get('receiver')
        recipient_list = []
        recipient_list.append(to_email)

        send_email_with_image(subject, message, recipient_list, encrypted_image_path)

        encrypted_file = EncryptedFile(
            user=user,
            recepient=receiver,
            file_name=request.data.get('file_name'),
            file=original_file
        )
        encrypted_file.save()



        return Response({"key": key, 'file_id': encrypted_file.id}, status=status.HTTP_201_CREATED)



class SteganoDecryption(APIView):

    def post(self, request, format = None):

        file_id = request.data.get('file_id')
        image_file = request.data.get('image')

        try:
            if not image_file:
                return Response({"error":"Image is required"}, status= status.HTTP_400_BAD_REQUEST)
            try:
                encrypted_file = EncryptedFile.objects.get(id = file_id)
            except EncryptedFile.DoesNotExist:
                return Response({"error":"File does not exist"}, status= status.HTTP_404_NOT_FOUND)
            
            key_image = Image.open(image_file)
            key = extract_key(key_image)
            
            cipher = Fernet(key)
            encrypted_data = encrypted_file.file.read()
            decrypted_data = cipher.decrypt(encrypted_data)

            filename = f"{encrypted_file.file_name}_decrypted.txt"
            with open(filename, 'wb') as file:
                file.write(decrypted_data)

            with open(filename, 'rb') as response_file:
                response = Response(response_file.read(), content_type= 'application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename={filename}'

            return response
        
        except Exception as e:
            return Response({"errors": str(e)} ,  status= status.HTTP_400_BAD_REQUEST)
        

