
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import *
from validate_email_address import validate_email
import re
from django.core.exceptions import ValidationError
class EmailLoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)




from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit



import re
from django import forms
from django.core.validators import validate_email
from .models import Record_Landingpage

# Create Add Record Form
class AddRecordLandingpageForm(forms.ModelForm):

    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control","id":"email"}),
        label=""
    )
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control","id":"name"}),
        label=""
    )
    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control","id":"phone"}),
        label=""
    )
    amount = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Amount *", "class": "form-control","id":"amount"}),
        label=""
    )


    batch_number = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Batch Number *", "class": "form-control","id":"batch_number"}),        label=""
    )

    class Meta:
        model = Record_Landingpage
        fields = ['email', 'name', 'phone', 'amount', 'batch_number']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        return email


    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\d{10}$')  # Adjust regex to allow only 10-digit numbers
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number, it should be a 10-digit number.")
        return phone



    def clean_amount(self):
        amount = self.cleaned_data.get('amount')
        email = self.cleaned_data.get('email')

        if not amount.isdigit():
            raise forms.ValidationError("Invalid amount. Please enter a valid integer amount.")

        try:
            amount_integer = int(amount)
        except ValueError:
            raise forms.ValidationError("Invalid amount. Please enter a valid integer.")

        try:
            record = Record_Landingpage.objects.get(email=email)
            Paid_amount = int(record.amount)
            valid_amount = amount_integer + Paid_amount
            total_amount = int(record.total_amount)
        except Record_Landingpage.DoesNotExist:
            Paid_amount = 0  # Assuming no previous amount
            valid_amount = amount_integer
            total_amount = 8000  # Assuming a default total amount

        if valid_amount > total_amount:
            raise forms.ValidationError("Your amount is more than the total amount")

        return amount_integer


    def clean_batch_number(self):
        batch_number = self.cleaned_data.get('batch_number')
        try:
            Batch.objects.get(batch_number=batch_number)
        except Batch.DoesNotExist:
            raise forms.ValidationError("Invalid batch number. Please select a valid batch number.")
        return batch_number


    def clean(self):
        cleaned_data = super().clean()
        return cleaned_data

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not re.match(r'^[a-zA-Z\s]+$', name):
            raise forms.ValidationError("Name can only contain letters and spaces.")
        return name



class SignUpForm(UserCreationForm):
	email = forms.EmailField(label="", widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'Email Address'}))
	first_name = forms.CharField(label="", max_length=100, widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'First Name'}))
	last_name = forms.CharField(label="", max_length=100, widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'Last Name'}))


	class Meta:
		model = User
		fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')


	def __init__(self, *args, **kwargs):
		super(SignUpForm, self).__init__(*args, **kwargs)

		self.fields['username'].widget.attrs['class'] = 'form-control'
		self.fields['username'].widget.attrs['placeholder'] = 'User Name'
		self.fields['username'].label = ''
		self.fields['username'].help_text = '<span class="form-text text-muted"><small>Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.</small></span>'

		self.fields['password1'].widget.attrs['class'] = 'form-control'
		self.fields['password1'].widget.attrs['placeholder'] = 'Password'
		self.fields['password1'].label = ''
		self.fields['password1'].help_text = '<ul class="form-text text-muted small"><li>Your password can\'t be too similar to your other personal information.</li><li>Your password must contain at least 8 characters.</li><li>Your password can\'t be a commonly used password.</li><li>Your password can\'t be entirely numeric.</li></ul>'

		self.fields['password2'].widget.attrs['class'] = 'form-control'
		self.fields['password2'].widget.attrs['placeholder'] = 'Confirm Password'
		self.fields['password2'].label = ''
		self.fields['password2'].help_text = '<span class="form-text text-muted"><small>Enter the same password as before, for verification.</small></span>'



# Create Add Record Form
class AddRecordForm(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    batch_number = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    cert_choices = [
        (0, '0'),
        (1, '1'),
        (2, '2'),
    ]
    cert = forms.ChoiceField(
        choices=cert_choices,
        initial=0,
        widget=forms.HiddenInput(),
        label=""
    )

    class Meta:
        model = Record
        exclude = ("user",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click
        try:
            latest_batch = Python_Batch.objects.latest('id')
            self.fields['batch_number'].initial = latest_batch.batch_number
        except Python_Batch.DoesNotExist:
            self.fields['batch_number'].initial = None

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year

    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        return phone

    def clean_batch_number(self):
        batch_number = self.cleaned_data.get('batch_number')
        if not Python_Batch.objects.filter(batch_number=batch_number).exists():
            raise forms.ValidationError("Batch number does not exist")
        return batch_number

    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        phone = cleaned_data.get('phone')
        email = cleaned_data.get('email')
        batch_number = cleaned_data.get('batch_number')

        if phone and batch_number:
            # Check for duplicate phone number within the same batch
            if Record.objects.filter(phone=phone, batch_number=batch_number).exists():
                self.add_error('phone', "Phone number already exists for this batch")

        if email and batch_number:
            # Check for duplicate email within the same batch
            if Record.objects.filter(email=email, batch_number=batch_number).exists():
                self.add_error('email', "Email already exists for this batch")

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data



class AddRecordForm_java(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    batch_number = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    cert_choices = [
        (0, '0'),
        (1, '1'),
        (2, '2'),
    ]
    cert = forms.ChoiceField(
        choices=cert_choices,
        initial=0,
        widget=forms.HiddenInput(),
        label=""
    )
    attempt_choices = [
        (0, '0'),
        (1, '1'),
        (2, '2'),
        (4, '4'),
    ]
    attempt = forms.ChoiceField(
        choices=attempt_choices,
        initial=0,
        widget=forms.HiddenInput(),
        label=""
    )
    class Meta:
        model = Record_java
        exclude = ("user",)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click
        try:
            latest_batch = Java_Batch.objects.latest('id')
            self.fields['batch_number'].initial = latest_batch.batch_number
        except Java_Batch.DoesNotExist:
            self.fields['batch_number'].initial = None
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        return phone

    def clean_batch_number(self):
        batch_number = self.cleaned_data.get('batch_number')
        if not Java_Batch.objects.filter(batch_number=batch_number).exists():
            raise forms.ValidationError("Batch number does not exist")
        return batch_number

    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'
        phone = cleaned_data.get('phone')
        email = cleaned_data.get('email')
        batch_number = cleaned_data.get('batch_number')

        if phone and batch_number:
            # Check for duplicate phone number within the same batch
            if Record_java.objects.filter(phone=phone, batch_number=batch_number).exists():
                self.add_error('phone', "Phone number already exists for this batch")

        if email and batch_number:
            # Check for duplicate email within the same batch
            if Record_java.objects.filter(email=email, batch_number=batch_number).exists():
                self.add_error('email', "Email already exists for this batch")
        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data


#community
class AddRecordForm_community(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )


    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )


    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    class Meta:
        model = Record_community
        exclude = ("user",)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        if Record_community.objects.filter(email=email).exists():
            raise forms.ValidationError(" email already exists.")
        return email


    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        if Record_community.objects.filter(phone=phone).exists():
            raise forms.ValidationError(" phone number already exists.")
        return phone



    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data




#basic_python_certificates
class AddRecordForm_basic_python_certificates(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    review = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"placeholder": "Please add your basic python course feedback here...", "class": "form-control"}),
        label="Feedback"
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    class Meta:
        model = Record_basic_python_certificates
        exclude = ("user",)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click


    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        if Record_basic_python_certificates.objects.filter(email=email).exists():
            raise forms.ValidationError(" email already exists.")

        return email

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        if Record_basic_python_certificates.objects.filter(phone=phone).exists():
            raise forms.ValidationError(" phone number already exists.")

        return phone
    def clean_review(self):
        review = self.cleaned_data.get('review')
        if not review:
            raise forms.ValidationError("Review field cannot be empty")

        return review




    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data


#basic_java_certificates
class AddRecordForm_basic_java_certificates(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    review = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"placeholder": "Please add your basic java course feedback here...", "class": "form-control"}),
        label="Feedback"
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    class Meta:
        model = Record_basic_java_certificates
        exclude = ("user",)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click


    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        if Record_basic_java_certificates.objects.filter(email=email).exists():
            raise forms.ValidationError(" email already exists.")

        return email
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        if Record_basic_java_certificates.objects.filter(phone=phone).exists():
            raise forms.ValidationError(" phone number already exists.")

        return phone
    def clean_review(self):
        review = self.cleaned_data.get('review')
        if not review:
            raise forms.ValidationError("Review field cannot be empty")

        return review




    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data








#advance_python_reg
class AddRecordForm_advance_python_reg(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    batch_number = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    cert_choices = [
        (0, '0'),
        (1, '1'),
        (2, '2'),
    ]
    cert = forms.ChoiceField(
        choices=cert_choices,
        initial=0,
        widget=forms.HiddenInput(),
        label=""
    )

    class Meta:
        model = Record_advance_python_reg
        exclude = ("user",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click
        try:
            latest_batch = Advance_Python_Batch.objects.latest('id')
            self.fields['batch_number'].initial = latest_batch.batch_number
        except Advance_Python_Batch.DoesNotExist:
            self.fields['batch_number'].initial = None
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        return phone

    def clean_batch_number(self):
        batch_number = self.cleaned_data.get('batch_number')
        if not Advance_Python_Batch.objects.filter(batch_number=batch_number).exists():
            raise forms.ValidationError("Batch number does not exist")
        return batch_number

    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        phone = cleaned_data.get('phone')
        email = cleaned_data.get('email')
        batch_number = cleaned_data.get('batch_number')

        if phone and batch_number:
            # Check for duplicate phone number within the same batch
            if Record_advance_python_reg.objects.filter(phone=phone, batch_number=batch_number).exists():
                self.add_error('phone', "Phone number already exists for this batch")

        if email and batch_number:
            # Check for duplicate email within the same batch
            if Record_advance_python_reg.objects.filter(email=email, batch_number=batch_number).exists():
                self.add_error('email', "Email already exists for this batch")

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data

#advance_python_certificates
class AddRecordForm_advance_python_certificates(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    review = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"placeholder": "Please add your advance python course feedback here...", "class": "form-control"}),
        label="Feedback"
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    class Meta:
        model = Record_advance_python_certificates
        exclude = ("user",)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        if Record_advance_python_certificates.objects.filter(email=email).exists():
            raise forms.ValidationError(" email already exists.")

        return email


    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        if Record_advance_python_certificates.objects.filter(phone=phone).exists():
            raise forms.ValidationError(" phone number already exists.")

        return phone
    def clean_review(self):
        review = self.cleaned_data.get('review')
        if not review:
            raise forms.ValidationError("Review field cannot be empty")

        return review




    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data




#advance_java_reg
class AddRecordForm_advance_java_reg(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    batch_number = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    cert_choices = [
        (0, '0'),
        (1, '1'),
        (2, '2'),
    ]
    cert = forms.ChoiceField(
        choices=cert_choices,
        initial=0,
        widget=forms.HiddenInput(),
        label=""
    )

    class Meta:
        model = Record_advance_java_reg
        exclude = ("user",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click
        try:
            latest_batch = Advance_Java_Batch.objects.latest('id')
            self.fields['batch_number'].initial = latest_batch.batch_number
        except Advance_Java_Batch.DoesNotExist:
            self.fields['batch_number'].initial = None
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        return phone

    def clean_batch_number(self):
        batch_number = self.cleaned_data.get('batch_number')
        if not Advance_Java_Batch.objects.filter(batch_number=batch_number).exists():
            raise forms.ValidationError("Batch number does not exist")
        return batch_number

    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        phone = cleaned_data.get('phone')
        email = cleaned_data.get('email')
        batch_number = cleaned_data.get('batch_number')

        if phone and batch_number:
            # Check for duplicate phone number within the same batch
            if Record_advance_java_reg.objects.filter(phone=phone, batch_number=batch_number).exists():
                self.add_error('phone', "Phone number already exists for this batch")

        if email and batch_number:
            # Check for duplicate email within the same batch
            if Record_advance_java_reg.objects.filter(email=email, batch_number=batch_number).exists():
                self.add_error('email', "Email already exists for this batch")

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data


#adavnce_java certificates
class AddRecordForm_advance_java_certificates(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    review = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"placeholder": "Please add your Advance java course feedback here...", "class": "form-control"}),
        label="Feedback"
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    class Meta:
        model = Record_advance_java_certificates
        exclude = ("user",)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click


    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        if Record_advance_java_certificates.objects.filter(email=email).exists():
            raise forms.ValidationError(" email already exists.")

        return email

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        if Record_advance_java_certificates.objects.filter(phone=phone).exists():
            raise forms.ValidationError(" phone number already exists.")

        return phone
    def clean_review(self):
        review = self.cleaned_data.get('review')
        if not review:
            raise forms.ValidationError("Review field cannot be empty")

        return review




    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data



#intern_reg
class AddRecordForm_intern_reg(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    batch_number = forms.CharField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    cert_choices = [
        (0, '0'),
        (1, '1'),
        (2, '2'),
    ]
    cert = forms.ChoiceField(
        choices=cert_choices,
        initial=0,
        widget=forms.HiddenInput(),
        label=""
    )
    start_date = forms.DateField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )
    end_date = forms.DateField(
        required=False,
        widget=forms.HiddenInput(),
        label=""
    )


    class Meta:
        model = Record_intern_reg
        exclude = ("user",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click
        try:
            latest_batch = Intern_Batch.objects.latest('id')
            self.fields['batch_number'].initial = latest_batch.batch_number
        except Intern_Batch.DoesNotExist:
            self.fields['batch_number'].initial = None
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year
    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        return phone

    def clean_batch_number(self):
        batch_number = self.cleaned_data.get('batch_number')
        if not Intern_Batch.objects.filter(batch_number=batch_number).exists():
            raise forms.ValidationError("Batch number does not exist")
        return batch_number

    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        phone = cleaned_data.get('phone')
        email = cleaned_data.get('email')
        batch_number = cleaned_data.get('batch_number')

        if phone and batch_number:
            # Check for duplicate phone number within the same batch
            if Record_intern_reg.objects.filter(phone=phone, batch_number=batch_number).exists():
                self.add_error('phone', "Phone number already exists for this batch")

        if email and batch_number:
            # Check for duplicate email within the same batch
            if Record_intern_reg.objects.filter(email=email, batch_number=batch_number).exists():
                self.add_error('email', "Email already exists for this batch")

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data



#intern certificates
class AddRecordForm_intern_certificates(forms.ModelForm):
    OCCUPATION_CHOICES = [
        ('working', 'Currently Working'),
        ('unemployed', 'Currently Unemployed'),
        ('still_studying', 'Currently Still Studying'),
    ]
    name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Name *", "class": "form-control"}),
        label=""
    )

    education = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Education *", "class": "form-control"}),
        label=""
    )
    passed_out_year = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Passed out year *", "class": "form-control"}),
        label=""
    )
    college = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "College Name *", "class": "form-control"}),
        label=""
    )
    occupation = forms.ChoiceField(
        required=True,
        widget=forms.RadioSelect,
        choices=OCCUPATION_CHOICES,
        label="Occupation"
    )
    company_name = forms.CharField(
        required=False,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Company Name *", "class": "form-control"}),
        label="",
    )

    phone = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Phone *", "class": "form-control"}),
        label=""
    )
    email = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Email *", "class": "form-control"}),
        label=""
    )

    address = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Address *", "class": "form-control"}),
        label=""
    )
    father_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Name *", "class": "form-control"}),
        label=""
    )
    father_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Father's Occupation *", "class": "form-control"}),
        label=""
    )
    mother_name = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Name *", "class": "form-control"}),
        label=""
    )
    mother_occupation = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Mother's Occupation *", "class": "form-control"}),
        label=""
    )
    city = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "City *", "class": "form-control"}),
        label=""
    )
    state = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "State *", "class": "form-control"}),
        label=""
    )

    zipcode = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Zipcode *", "class": "form-control"}),
        label=""
    )

    country = forms.CharField(
        required=True,
        widget=forms.widgets.TextInput(attrs={"placeholder": "Country *", "class": "form-control"}),
        label=""
    )

    review = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"placeholder": "Please add your intern feedback here...", "class": "form-control"}),
        label="Feedback"
    )
    disclaimer = forms.BooleanField(
        required=True,
        label="The above given information is true to my knowledge , you can futher verifiy it if there is a misinformation you can take action,",

    )
    class Meta:
        model = Record_intern_certificates
        exclude = ("user",)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company_name'].widget.attrs['style'] = 'display:none;'  # Hide the company name field by default
        self.fields['occupation'].widget.attrs['onclick'] = 'showCompanyInput()'  # Call JavaScript function on click

    def clean_name(self):
        name = self.cleaned_data.get('name')
        if not name.replace(' ', '').isalpha():
            raise ValidationError("Name should contain only letters and spaces")
        return name

    def clean_passed_out_year(self):
        passed_out_year = self.cleaned_data.get('passed_out_year')
        if not passed_out_year.isdigit() or len(passed_out_year) != 4:
            raise ValidationError("Passed out year should be a 4-digit number")
        return passed_out_year


    def clean_email(self):
        email = self.cleaned_data.get('email')
        validate_email(email)
        if '@' not in email or not email.lower().endswith('.com'):
            raise forms.ValidationError("Email must contain '@' and end with '.com'")
        if Record_intern_certificates.objects.filter(email=email).exists():
            raise forms.ValidationError(" email already exists.")

        return email


    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        phone_pattern = re.compile(r'^\+?1?\d{9,15}$')  # Adjust regex as needed for your phone format
        if not phone_pattern.match(phone):
            raise forms.ValidationError("Invalid phone number")
        if Record_intern_certificates.objects.filter(phone=phone).exists():
            raise forms.ValidationError(" phone number already exists.")

        return phone
    def clean_review(self):
        review = self.cleaned_data.get('review')
        if not review:
            raise forms.ValidationError("Review field cannot be empty")

        return review




    def clean(self):
        cleaned_data = super().clean()
        occupation = cleaned_data.get('occupation')
        company_name = cleaned_data.get('company_name')

        if occupation != 'working':
            cleaned_data['company_name'] = 'nil'

        disclaimer = cleaned_data.get('disclaimer')
        if not disclaimer:
            self.add_error('disclaimer', 'You must agree to the terms and conditions')


        return cleaned_data



