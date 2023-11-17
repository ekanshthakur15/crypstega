from django.urls import path

from .views import *

urlpatterns = [
    path("upload/",Encryption.as_view()),
    path("decrypt/", Decryption.as_view()),
    path("files_list/", FileListView.as_view()),
]