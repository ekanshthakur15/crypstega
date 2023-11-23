from django.contrib.auth.views import LogoutView
from django.urls import path

from .views import *

urlpatterns = [

    path("sent_files/", SharedFileListView.as_view()),
    path("received_files/", ReceivedFileListView.as_view()),
    path("encrypt/", SteganoEncryption.as_view()),
    path("decrypt/", SteganoDecryption.as_view(), name = 'decrypt_view'),

    #authentication
    path('register/', RegisterUserView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
]