from django.urls import path

from .views import *

urlpatterns = [

    path("files_list/", FileListView.as_view()),
    path("stegno/", SteganoEncryption.as_view()),
    path("stegno_dec/", SteganoDecryption.as_view()),
]