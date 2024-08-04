from pathlib import Path
import os
from django.core.management.utils import get_random_secret_key
# settings.py
import os



# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_random_secret_key()

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['GuruTechDev.pythonanywhere.com']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'registration',  # Assuming 'website' and 'app1' are both required
    'app1',
    'crispy_forms',
    'crispy_bootstrap4',
]
CRISPY_TEMPLATE_PACK = 'bootstrap4'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'registration.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'registration.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

"""DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}"""


# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'websitedb2',
#         'USER': 'root',
#         'PASSWORD': '123456',
#         'HOST': 'localhost',   # Or an IP Address that your DB is hosted on
#         'PORT': '3306',        # Default MySQL port
#     }
# }

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'gurutech$default',
#         'USER': 'gurutech',
#         'PASSWORD': 'data@1234',
#         'HOST': 'gurutech.mysql.pythonanywhere-services.com',
#         'PORT': '3306',
#     }
# }

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'GuruTechDev$techdata',
        'USER': 'GuruTechDev',
        'PASSWORD': 'datas@1234',
        'HOST': 'GuruTechDev.mysql.pythonanywhere-services.com',
        'PORT': '3306',
    }
}





# Authentication backends
AUTHENTICATION_BACKENDS = [
    'app1.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

TIME_ZONE = 'Asia/Kolkata'
USE_TZ = True



# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = '/static/'
#STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT =  os.path.join(BASE_DIR, 'static')


# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Session settings
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'sessionid'
SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_SAVE_EVERY_REQUEST = False

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'gurutechharkscorp@gmail.com'
EMAIL_HOST_PASSWORD = 'ftbvqyhuzzgahaqx'
# EMAIL_HOST = 'smtp.zeptomail.com'
# EMAIL_PORT = 587
# EMAIL_USE_TLS = True
# EMAIL_HOST_USER = 'noreply@edugurutech.in'
# EMAIL_HOST_PASSWORD = 'wSsVR612/kbzXPguyWD5J+84y19UBFz0EEt5iQOluXL7S/nK/MdplECcDFCjG/MWQDZvEjoV9bp8mE1R1GcJiIwkyl1UXCiF9mqRe1U4J3x17qnvhDzOWGtbmhGJKYkAwgtjnmNoEckk+g=='

SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin-allow-popups"