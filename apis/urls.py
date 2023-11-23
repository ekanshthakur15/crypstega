from django.urls import path
from rest_framework_simplejwt.views import (TokenObtainPairView,
                                            TokenRefreshView, TokenVerifyView)

from .views import *

urlpatterns = [

    path("sent_files/", SharedFileListView.as_view()),
    path("received_files/", ReceivedFileListView.as_view()),
    path("encrypt/", SteganoEncryption.as_view()),
    path("decrypt/", SteganoDecryption.as_view(), name = 'decrypt_view'),

    #authentication
    path('register/', RegisterUserView.as_view()),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh-token/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token-verify/', TokenVerifyView.as_view(), name='token_verify'),
]