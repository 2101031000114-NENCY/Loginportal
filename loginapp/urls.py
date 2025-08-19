from django.contrib.auth import views as auth_views
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import reverse_lazy

urlpatterns = [
    path('', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('home/', views.home_view, name='home'),
    path('profile/', views.profile_view, name='profile'),
    path('change_password/', views.change_password_view, name='change_password'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('reset_password/', views.reset_password, name='reset_password'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)