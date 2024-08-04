
from django.contrib import admin
from django.urls import path,include
from django.contrib.auth import views as auth_views
from app1 import views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('app1.urls')),
    path('signup/',views.SignupPage,name='signup'),
    path('login/',views.LoginPage,name='login'),
    path('home2/',views.HomePage,name='home2'),
    path('logout/',views.LogoutPage,name='logout'),
    path('req/',views.req_view,name='req'),
        path('join_course/', views.join_course, name='join_course'),

]







