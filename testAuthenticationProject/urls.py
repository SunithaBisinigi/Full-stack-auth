from django.contrib import admin
from django.urls import path, include
from authenticationApiApp.views import registration, login_view


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('authenticationApiApp.urls')),
    path('registration/', registration, name='registration'),
]