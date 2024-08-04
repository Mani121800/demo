from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    FLAG_CHOICES = (
        (-1, '-1'),
        (0, '0'),
        (1, '1'),
        (2, '2'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    flag = models.IntegerField(choices=FLAG_CHOICES, default=0)
    # link = models.URLField(blank=True, null=True)
    batch_number = models.IntegerField(default=0)  # New field for batch number

    def __str__(self):
        return self.user.username

class CourseLinks(models.Model):
    # flag = models.IntegerField()
    link = models.URLField()  # Changed 'links' to 'link' to match the template
    details = models.TextField()
    batch_number = models.IntegerField(default=0)  # New field for batch number
    start_date = models.DateField(null=True, blank=True)  # Add start date field
    def __str__(self):
        return self.details  # Changed to return details instead of link for better context


class JoinDetails(models.Model):
    email = models.EmailField()
    join_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.email} joined on {self.join_date}'


    from django.db import models

# models.py
from django.db import models

class Contact(models.Model):
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=20)
    email = models.EmailField()
    message = models.TextField()

    def __str__(self):
        return self.name

class Batch(models.Model):
    BATCH_CHOICES = [
        ('1', '1'),
        ('2', '2'),
        ('3', '3'),
    ]

    batch_number = models.CharField(max_length=10, choices=BATCH_CHOICES, unique=True)
    fees_amount = models.PositiveIntegerField()

    def _str_(self):
        return f'{self.get_batch_number_display()} - {self.fees_amount}'

class Record_Landingpage(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    email = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    balance_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    student_batch = models.CharField(max_length=50, blank=True, null=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.name}"


class Python_otp(models.Model):
    otp = models.CharField(max_length=50, unique=True)
    def __str__(self):
        return self.otp


class Record(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    batch_number = models.CharField(max_length=50, blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    cert = models.IntegerField(choices=[(0, '0'), (1, '1'), (2, '2')], default=0)
    def __str__(self):
        return f"{self.name} "

class Python_Batch(models.Model):
    batch_number = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.batch_number


class WhatsAppLink_python(models.Model):
    link = models.URLField()

    def __str__(self):
        return self.link


class Record_java(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    batch_number = models.CharField(max_length=50, blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    cert = models.IntegerField(choices=[(0, '0'), (1, '1'), (2, '2')], default=0)

    attempt = models.IntegerField(choices=[(0, '0'), (1, '1'), (2, '2'),(4, '4')], default=0)
    def __str__(self):
        return f"{self.name} "

class Basic_JavaQuestion(models.Model):
    question_text = models.TextField()
    option_a = models.CharField(max_length=255)
    option_b = models.CharField(max_length=255)
    option_c = models.CharField(max_length=255)
    option_d = models.CharField(max_length=255)
    correct_option = models.CharField(max_length=1)  # Assuming options are 'A', 'B', 'C', 'D'

    def __str__(self):
        return self.question_text



class Java_Batch(models.Model):
    batch_number = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.batch_number

class WhatsAppLink_java(models.Model):
    link = models.URLField()

    def __str__(self):
        return self.link

from django.db import models

class random_otp(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)  # Adjust the max_length according to your OTP length
    created_at = models.DateTimeField(auto_now_add=True)






#community
class Record_community(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.name} "


class WhatsAppLink_community(models.Model):
    link = models.URLField()

    def __str__(self):
        return self.link



#basic_python_certificate

class Record_basic_python_certificates(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    review = models.TextField(blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.name} "



class Basic_python_test_link(models.Model):
    link = models.URLField()

    def __str__(self):
        return self.link


#basic_java_certificate

class Record_basic_java_certificates(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    review = models.TextField(blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.name} "



class Basic_java_test_link(models.Model):
    link = models.URLField()

    def __str__(self):
        return self.link







class Certificate(models.Model):
    name = models.CharField(max_length=255)
    certificate_id = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.certificate_id}"

#advance_python_reg
class Record_advance_python_reg(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    batch_number = models.CharField(max_length=50, blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    cert = models.IntegerField(choices=[(0, '0'), (1, '1'), (2, '2')], default=0)
    def __str__(self):
        return f"{self.name} "

class Advance_Python_Batch(models.Model):
    batch_number = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.batch_number

#advance_python_certificate

class Record_advance_python_certificates(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    review = models.TextField(blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.name} "



class Advance_python_test_link(models.Model):
    link = models.URLField()

    def __str__(self):
        return self.link


#advance_java_reg
class Record_advance_java_reg(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    batch_number = models.CharField(max_length=50, blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    cert = models.IntegerField(choices=[(0, '0'), (1, '1'), (2, '2')], default=0)
    def __str__(self):
        return f"{self.name} "

class Advance_Java_Batch(models.Model):
    batch_number = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.batch_number

#advance_java_certificate

class Record_advance_java_certificates(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    review = models.TextField(blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.name} "



class Advance_java_test_link(models.Model):
    link = models.URLField()

    def __str__(self):
        return self.link


#intern_reg
class Record_intern_reg(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    batch_number = models.CharField(max_length=50, blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    cert = models.IntegerField(choices=[(0, '0'), (1, '1'), (2, '2')], default=0)
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)
    def __str__(self):
        return f"{self.name} "

class Intern_Batch(models.Model):
    batch_number = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.batch_number

#intern_certificate

class Record_intern_certificates(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=50)

    education = models.CharField(max_length=255,blank=True, null=True)
    passed_out_year = models.CharField(max_length=4,blank=True, null=True)
    college = models.CharField(max_length=255,blank=True, null=True)
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    occupation = models.CharField(max_length=50, choices=OCCUPATION_CHOICES, blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True, default='nil')
    phone = models.CharField(max_length=15)
    email = models.CharField(max_length=100)
    father_name = models.CharField(max_length=255,blank=True, null=True)
    father_occupation = models.CharField(max_length=255,blank=True, null=True)
    mother_name = models.CharField(max_length=255,blank=True, null=True)
    mother_occupation = models.CharField(max_length=255,blank=True, null=True)
    address = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=20)
    country = models.CharField(max_length=20,blank=True, null=True)
    review = models.TextField(blank=True, null=True)
    disclaimer = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.name} "



