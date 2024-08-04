from django.urls import path, reverse_lazy
from django.contrib.auth import views as auth_views
from .views import CustomPasswordResetView
from . import views

urlpatterns = [
    path('payment-status', views.payment_status, name='payment-status'),
    path('download_invoice', views.download_invoice_view,name='download_invoice'),
    path('', views.landingpage, name='landingpage'),
    path('payment_form/', views.add_record_landingpage, name='payment_form'),
    path('contactus/', views.contactus, name='contactus'),
    path('terms/', views.terms, name='terms'),
    path('home/', views.home, name='home'),
    path('logout/', views.logout_user, name='logout'),
    path('register/', views.register_user, name='register'),


    path('generate_otp/', views.generate_otp, name='generate_otp'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),




    path('password_reset/', CustomPasswordResetView.as_view(template_name='password_reset_form.html'), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html', success_url=reverse_lazy('password_reset_complete')), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),




    #python course
    path('record/<int:pk>', views.customer_record, name='record'),
    path('delete_record/<int:pk>', views.delete_record, name='delete_record'),
    path('add_record_python/', views.add_record, name='add_record'),
    path('update_record/<int:pk>', views.update_record, name='update_record'),

    path('python/', views.python, name='python'),

    #java course
    path('record_java/<int:pk>', views.customer_record_java, name='record_java'),
    path('delete_record_java/<int:pk>', views.delete_record_java, name='delete_record_java'),
    path('add_record_java/', views.add_record_java, name='add_record_java'),
    path('update_record_java/<int:pk>', views.update_record_java, name='update_record_java'),
    path('java/', views.java, name='java'),

    #community
    path('record_community/<int:pk>', views.customer_record_community, name='record_community'),
    path('delete_record_community/<int:pk>', views.delete_record_community, name='delete_record_community'),
    path('add_record_community/', views.add_record_community, name='add_record_community'),
    path('update_record_community/<int:pk>', views.update_record_community, name='update_record_community'),
    path('community/', views.community, name='community'),



    path('generate_otp_community/', views.generate_otp_community, name='generate_otp_community'),
    path('verify_otp_community/', views.verify_otp_community, name='verify_otp_community'),





    #basic_python_certificate
    path('record_basic_python_certificates/<int:pk>', views.customer_record_basic_python_certificates, name='record_basic_python_certificates'),
    path('delete_record_basic_python_certificates/<int:pk>', views.delete_record_basic_python_certificates, name='delete_record_basic_python_certificates'),
    path('add_record_basic_python_certificates/', views.add_record_basic_python_certificates, name='add_record_basic_python_certificates'),
    path('update_record_basic_python_certificates/<int:pk>', views.update_record_basic_python_certificates, name='update_record_basic_python_certificates'),
    path('basic_python_certificates/', views.basic_python_certificates, name='basic_python_certificates'),
    path('generate_otp_basic_python_certificates/', views.generate_otp_basic_python_certificates, name='generate_otp_basic_python_certificates'),
    #basic_java_certificate

    path('record_basic_java_certificates/<int:pk>', views.customer_record_basic_java_certificates, name='record_basic_java_certificates'),
    path('delete_record_basic_java_certificates/<int:pk>', views.delete_record_basic_java_certificates, name='delete_record_basic_java_certificates'),
    path('add_record_basic_java_certificates/', views.add_record_basic_java_certificates, name='add_record_basic_java_certificates'),
    path('update_record_basic_java_certificates/<int:pk>', views.update_record_basic_java_certificates, name='update_record_basic_java_certificates'),
    path('basic_java_certificates/', views.basic_java_certificates, name='basic_java_certificates'),
    path('generate_otp_basic_java_certificates/', views.generate_otp_basic_java_certificates, name='generate_otp_basic_java_certificates'),



    path('search_certificate/', views.search_certificate, name='search_certificate'),

    #advance_python_reg
    path('record_advance_python_reg/<int:pk>', views.customer_record_advance_python_reg, name='record_advance_python_reg'),
    path('delete_record_advance_python_reg/<int:pk>', views.delete_record_advance_python_reg, name='delete_record_advance_python_reg'),
    path('add_record_advance_python_reg/', views.add_record_advance_python_reg, name='add_record_advance_python_reg'),
    path('update_record_advance_python_reg/<int:pk>', views.update_record_advance_python_reg, name='update_record_advance_python_reg'),
    path('advance_python_reg/', views.advance_python_reg, name='advance_python_reg'),

    path('thank_you_for_reg/', views.thank_you_for_reg, name='thank_you_for_reg'),

    #advance_python_certificate
    path('record_advance_python_certificates/<int:pk>', views.customer_record_advance_python_certificates, name='record_advance_python_certificates'),
    path('delete_record_advance_python_certificates/<int:pk>', views.delete_record_advance_python_certificates, name='delete_record_advance_python_certificates'),
    path('add_record_advance_python_certificates/', views.add_record_advance_python_certificates, name='add_record_advance_python_certificates'),
    path('update_record_advance_python_certificates/<int:pk>', views.update_record_advance_python_certificates, name='update_record_advance_python_certificates'),
    path('advance_python_certificates/', views.advance_python_certificates, name='advance_python_certificates'),
    path('generate_otp_advance_python_certificates/', views.generate_otp_advance_python_certificates, name='generate_otp_advance_python_certificates'),


    #advance_java_reg
    path('record_advance_java_reg/<int:pk>', views.customer_record_advance_java_reg, name='record_advance_java_reg'),
    path('delete_record_advance_java_reg/<int:pk>', views.delete_record_advance_java_reg, name='delete_record_advance_java_reg'),
    path('add_record_advance_java_reg/', views.add_record_advance_java_reg, name='add_record_advance_java_reg'),
    path('update_record_advance_java_reg/<int:pk>', views.update_record_advance_java_reg, name='update_record_advance_java_reg'),
    path('advance_java_reg/', views.advance_java_reg, name='advance_java_reg'),


    #advance_java_certificate
    path('record_advance_java_certificates/<int:pk>', views.customer_record_advance_java_certificates, name='record_advance_java_certificates'),
    path('delete_record_advance_java_certificates/<int:pk>', views.delete_record_advance_java_certificates, name='delete_record_advance_java_certificates'),
    path('add_record_advance_java_certificates/', views.add_record_advance_java_certificates, name='add_record_advance_java_certificates'),
    path('update_record_advance_java_certificates/<int:pk>', views.update_record_advance_java_certificates, name='update_record_advance_java_certificates'),
    path('advance_java_certificates/', views.advance_java_certificates, name='advance_java_certificates'),
    path('generate_otp_advance_java_certificates/', views.generate_otp_advance_java_certificates, name='generate_otp_advance_java_certificates'),


    #intern_reg
    path('record_intern_reg/<int:pk>', views.customer_record_intern_reg, name='record_intern_reg'),
    path('delete_record_intern_reg/<int:pk>', views.delete_record_intern_reg, name='delete_record_intern_reg'),
    path('add_record_intern_reg/', views.add_record_intern_reg, name='add_record_intern_reg'),
    path('update_record_intern_reg/<int:pk>', views.update_record_intern_reg, name='update_record_intern_reg'),
    path('intern_reg/', views.intern_reg, name='intern_reg'),

    #intern_certificate
    path('record_intern_certificates/<int:pk>', views.customer_record_intern_certificates, name='record_intern_certificates'),
    path('delete_record_intern_certificates/<int:pk>', views.delete_record_intern_certificates, name='delete_record_intern_certificates'),
    path('add_record_intern_certificates/', views.add_record_intern_certificates, name='add_record_intern_certificates'),
    path('update_record_intern_certificates/<int:pk>', views.update_record_intern_certificates, name='update_record_intern_certificates'),
    path('intern_certificates/', views.intern_certificates, name='intern_certificates'),
    path('generate_otp_intern_certificates/', views.generate_otp_intern_certificates, name='generate_otp_intern_certificates'),



    path('verify_otp_community_landingpage/', views.verify_otp_community_landingpage, name='verify_otp_community_landingpage'),
    path('advance_python_account_list/',views.advance_python_account_list,name='advance_python_account_list'),

    path('quiz/', views.quiz, name='quiz'),
    path('generate_otp_basic_java_questions/', views.generate_otp_basic_java_questions, name='generate_otp_basic_java_questions'),

    path('verify_otp_new/', views.verify_otp_new, name='verify_otp_new'),
      path('deploy/', views.deploy, name='deploy'),
]