import base64
import os
from datetime import datetime

from Crypto.Protocol.KDF import PBKDF2
from cryptography.fernet import Fernet
from django.contrib.auth import authenticate, login
from PIL import Image
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import *
from .serializers import *
from .utils import *

current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class RegisterUserView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            return Response({'message': 'Registration successful and user logged in'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'error': 'Registration successful but login failed'}, status=status.HTTP_401_UNAUTHORIZED)


class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request, format=None):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class SharedFileListView(APIView):
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            query_set = EncryptedFile.objects.filter(recepient=request.user)
        except EncryptedFile.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        files = []
        for file in query_set:
            data = {
                "file_id":file.pk,
                "file_name": file.file_name,
                "upload_date": file.uploaded_at,
                "from": file.user.username
            }
            files.append(data)
        return Response(files, status=status.HTTP_200_OK)

class SteganoEncryption(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        receiver_name = request.data.get('username')
        original_file = request.data.get('file')
        safe_code = request.data.get('safe_code')
        file_name = request.data.get('file_name')

        if not original_file:
            return Response({'error': 'File is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            receiver = User.objects.get(username =receiver_name)
        except User.DoesNotExist:
            return Response({"error": "Receiver doesn't exist"}, status=status.HTTP_404_NOT_FOUND)


        original_data = original_file.read()
        safe_code = safe_code.encode('utf-8')

        # Generate a random key for AES encryption
        key = Fernet.generate_key()
        
        # Combine safe_code and aes_key to create the final encryption key
        encryption_key = PBKDF2(safe_code, key, dkLen=32, count=100000)
        encryption_key = base64.urlsafe_b64encode(encryption_key)

        cipher = Fernet(encryption_key)
        encrypted_data = cipher.encrypt(original_data)

        original_file.seek(0)
        original_file.write(encrypted_data)

        # For hiding the partial key in the image
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

        #For sending email to the receiver
        subject = "New File Alert from CrypStega!"
        message = f"""Hey {receiver_name},

Exciting news! Someone just shared a file with you via CrypStega. Here are the deets:

📁 File Name: {file_name}
👤 Sender: {user.username}
📅 Date and Time: {current_time}

To snag your file:

Hop on over to CrypStega.
Check out "Received Files."
Find the file, fill in the details and click download download.
Download the image attached and use it to get your image.
Don't forget to ask the sender about the safe code.

Cheers,
CrypStega Squad"""

        to_email = receiver.email
        recipient_list = []
        recipient_list.append(to_email)

        send_email_with_image(subject, message, recipient_list, encrypted_image_path)
        os.remove(encrypted_image_path)
        encrypted_file = EncryptedFile(
            user=user,
            recepient=receiver,
            file_name=file_name,
            file=original_file,
        )
        encrypted_file.save()

        return Response({ 'file_id': encrypted_file.id}, status=status.HTTP_201_CREATED)



class SteganoDecryption(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format = None):

        file_id = request.data.get('file_id')
        image_file = request.data.get('image')
        safe_code = request.data.get('safe_code')
        safe_code = safe_code.encode('utf-8')
        

        try:
            if not image_file:
                return Response({"error":"Image is required"}, status= status.HTTP_400_BAD_REQUEST)
            try:
                encrypted_file = EncryptedFile.objects.get(id = file_id)
            except EncryptedFile.DoesNotExist:
                return Response({"error":"File does not exist"}, status= status.HTTP_404_NOT_FOUND)
            
            #extracting key from the image
            key_image = Image.open(image_file)
            key = extract_data(key_image)

            #Creating the key to decrypt the file
            decryption_key = PBKDF2(safe_code, key.encode('utf-8'), dkLen=32, count=100000)

            decryption_key = base64.urlsafe_b64encode(decryption_key)
            
            #Decryption
            cipher = Fernet(decryption_key)
            encrypted_data = encrypted_file.file.read()
            decrypted_data = cipher.decrypt(encrypted_data)
            print(decryption_key)
            return Response({'content': decrypted_data, "filename":encrypted_file.file_name}, status= status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"errors": str(e)} ,  status= status.HTTP_400_BAD_REQUEST)
        

