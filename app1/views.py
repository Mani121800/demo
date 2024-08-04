from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from .models import UserProfile, CourseLinks
from django.contrib.auth.models import User
from django.db import IntegrityError
from .forms import EmailLoginForm
import razorpay

from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.db import IntegrityError
from .models import UserProfile
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .forms import *
from .models import *
from django.views.decorators.csrf import csrf_protect
from random import choice
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
import random
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import random_otp  # Import your Python_otp model here
import random
from django.utils import timezone
from datetime import timedelta
from datetime import datetime
from django.db.models import Max
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.core.files.storage import FileSystemStorage
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
import os
from django.contrib.staticfiles import finders
def landingpage(request):
	return render(request, 'landingpage.html')


def contactus(request):
    if request.method == 'POST':
        name = request.POST.get('fname')
        phone = request.POST.get('phone')
        email = request.POST.get('email')
        message = request.POST.get('msg')

        # Server-side validation
        errors = {}
        if not name:
            errors['fname'] = 'Name is required.'
        phone_pattern = re.compile(r'^(\+?\d{1,4}[-\s]?)?\d{10}$')
        if not phone or not phone_pattern.match(phone):
            errors['phone'] = 'Enter a valid phone number (10 digits or with country code).'

        if not email:
            errors['email'] = 'Email is required.'
        if not message:
            errors['msg'] = 'Message is required.'

        if errors:
            return JsonResponse({'success': False, 'errors': errors})

        # Save data to the database
        Contact.objects.create(name=name, phone=phone, email=email, message=message)
        from_email=settings.EMAIL_HOST_USER
        email_message = f"Name: {name}\nPhone: {phone}\nEmail: {email}\nMessage:\n{message}"
        send_mail(
            f'Message from Guru Tech website users doubts {email}',
            email_message,
            from_email,
            ['haritamilhp@gmail.com'],  # Replace with the website owner's email address
        )

        return JsonResponse({'success': True, 'message': 'Thank you for your message!'})

    return render(request, 'Contact us.html')
def terms(request):
    return render(request,'terms.html')

@csrf_exempt
def payment_status(request):
    if request.method == "POST":
        response = request.POST
        params_dict = {
            'razorpay_order_id': response.get('razorpay_order_id'),
            'razorpay_payment_id': response.get('razorpay_payment_id'),
            'razorpay_signature': response.get('razorpay_signature')
        }

        client = razorpay.Client(auth=('rzp_test_I4CeG7pUY0K5BP', 'NoTvdgGVAfegBisCPePmru9t'))

        try:
            status = client.utility.verify_payment_signature(params_dict)
            if status:
                name = request.POST.get('name')
                email = request.POST.get('email')
                phone = request.POST.get('phone')
                amount = Decimal(request.POST.get('amount'))/ 100  # Convert back to main currency
                paid_amount = amount

                request.session['session_email'] = str(email)
                request.session['session_paid_amount'] = str(paid_amount)
                #Saving in Session Variable
                batch_number = request.POST.get('batch_number')
                razorpay_payment_id = response.get('razorpay_payment_id')  # Get the Razorpay payment ID

                batch = get_object_or_404(Batch, batch_number=batch_number)
                fees_amount = batch.fees_amount

                total_amount = Decimal(fees_amount)
                balance_amount = total_amount - amount

                existing_record = Record_Landingpage.objects.filter(email=email).first()
                razorpay_payment_check = Record_Landingpage.objects.filter(razorpay_payment_id=razorpay_payment_id).first()

                if existing_record and not razorpay_payment_check:
                    existing_record.amount += amount
                    existing_record.balance_amount -= amount
                    existing_record.razorpay_payment_id = razorpay_payment_id  # Update the Razorpay payment ID
                    existing_record.save()
                    record = existing_record
                elif razorpay_payment_check:
                    return render(request, 'payment_status.html', {
                        'status': 'payment_id',
                        'amount': str(razorpay_payment_check.amount),
                        'balance_amount': str(razorpay_payment_check.balance_amount),
                        'total_amount': str(razorpay_payment_check.total_amount),
                    })
                else:
                    new_record = Record_Landingpage(
                        name=name,
                        email=email,
                        phone=phone,
                        amount=amount,
                        total_amount=total_amount,
                        balance_amount=balance_amount,
                        student_batch=batch_number,
                        razorpay_payment_id=razorpay_payment_id  # Save the Razorpay payment ID
                    )
                    new_record.save()
                    record = new_record

                return render(request, 'payment_status.html', {
                    'amount': str(record.amount),
                    'balance_amount': str(record.balance_amount),
                    'total_amount': str(record.total_amount),
                    'status': 'success'
                })
            else:
                print("Payment verification failed")
                return render(request, 'payment_status.html', {
                    'status': 'Payment verification failed'
                })
        except razorpay.errors.SignatureVerificationError:
            print("Razorpay signature verification failed")
            return render(request, 'payment_status.html', {
                'status': 'Razorpay signature verification failed'
            })
        except Exception as e:
            print(f"An error occurred: {e}")
            return render(request, 'payment_status.html', {'status': False})

    return render(request, 'payment_status.html', {
        'status': 'Invalid request method'
    })


def add_record_landingpage(request):
    if request.method == "POST":
        form = AddRecordLandingpageForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            phone = form.cleaned_data['phone']
            batch_number = form.cleaned_data['batch_number']
            try:
                amount = int(form.cleaned_data['amount']) * 100
                #amount = int(request.POST.get('amount')) * 100
                print(amount, type(amount))
            except InvalidOperation:
                messages.error(request, "Invalid amount. Please enter a valid number.")
                return render(request, 'add_record_landingpage.html', {'form': form})
            try:
                record = Record_Landingpage.objects.get(email=email)
                paid_amount = Decimal(record.amount)
            except Record_Landingpage.DoesNotExist:
                paid_amount = Decimal(0)  # Assuming no previous amount

            batch = Batch.objects.get(batch_number=batch_number)
            total_amount = Decimal(batch.fees_amount)
            correct_amount = int(form.cleaned_data['amount'])

            if paid_amount + correct_amount > total_amount:
                form.add_error('amount', "Your amount exceeds the total amount.")
                return render(request, 'add_record_landingpage.html', {'form': form})


            try:
                # client = razorpay.Client(auth=('rzp_test_I4CeG7pUY0K5BP', 'NoTvdgGVAfegBisCPePmru9t'))
                # # Make a test API call to check the connection
                # response = client.order.all()
                # print("Responsev:", response)
                client = razorpay.Client(auth=('rzp_test_I4CeG7pUY0K5BP', 'NoTvdgGVAfegBisCPePmru9t'))

                response_payment = client.order.create(dict(amount=amount, currency='INR'))

                order_id = response_payment['id']
                order_status = response_payment['status']

                if order_status == 'created':
                    response_payment['name'] = name
                    response_payment['email'] = email
                    response_payment['phone'] = phone
                    response_payment['batch_number'] = batch_number

                    return render(request, 'add_record_landingpage.html', {
                        'payment': response_payment, 'form': form,'payment': response_payment
                    })
                else:
                    messages.error(request, "Failed to create payment order. Please try again.")
                    return render(request, 'add_record_landingpage.html', {'form': form})

            except razorpay.errors.BadRequestError as e:
                print("BadRequestError apikey and security key is wrong regenerate the keys:", e)
                return render(request, 'payment_status.html', {
                'status': 'Razorpay BadRequestError'
            })
            except razorpay.errors.ServerError as e:
                print("ServerError:", e)
                return render(request, 'payment_status.html', {
                'status': 'Razorpay BadRequestError'
            })
            except razorpay.errors.NetworkError as e:
                print("NetworkError:", e)
                return render(request, 'payment_status.html', {
                'status': 'Razorpay BadRequestError'
            })
            except Exception as e:
                print("An error occurred:", e)
                return render(request, 'payment_status.html', {
                'status': 'Razorpay BadRequestError'
            })



    else:
        form = AddRecordLandingpageForm()

    return render(request, 'add_record_landingpage.html', {'form': form})


def download_invoice_view(request):
    session_email = request.session.get('session_email')
    session_paid_amount = request.session.get('session_paid_amount')
    record=Record_Landingpage.objects.get(email=session_email)
    mydict={
        'orderDate':record.created_at,
        'customerName':record.name,
        'customerEmail':record.email,
        'customerMobile':record.phone,
        'paidAmount' :session_paid_amount,
        'totalAmountPaid':record.amount,
        'balanceAmount' :record.balance_amount,
        'totalAmount' :record.total_amount,
    }

    html = render_to_string('download_invoice.html', mydict)

    # Create a HttpResponse object with content_type as pdf
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="invoice.pdf"'

    # Create PDF
    pisa_status = pisa.CreatePDF(
        html, dest=response
    )

    # Return response
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    return response

@csrf_exempt
def SignupPage(request):
    if request.method == 'POST':
        uname = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password1')
        pass2 = request.POST.get('password2')

        # Validate password match
        if pass1 != pass2:
            return render(request, 'signup.html', {'error_message': "Your password and confirm password are not the same!"})

        if User.objects.filter(email=email).exists():
            return render(request, 'signup.html', {'error_message': "Email already exists. Please use a different email address."})
 # Check if the email is in the Record_Landingpage model
        if not Record_Landingpage.objects.filter(email=email).exists():
            return redirect('payment_form')
        # Validate unique username
        try:
            user = User.objects.create_user(username=uname, email=email, password=pass1)
            user.save()
            UserProfile.objects.create(user=user, flag=0)  # Adjust this according to your UserProfile model
            return redirect('login')  # Replace 'login' with the name of your login URL pattern
        except IntegrityError as e:
            if 'UNIQUE constraint failed: auth_user.username' in str(e):
                return render(request, 'signup.html', {'error_message': "Username already exists. Please choose a different username."})
            else:
                return render(request, 'signup.html', {'error_message': "An error occurred. Please try again."})

        except Exception as e:
            return render(request, 'signup.html', {'error_message': "An unexpected error occurred. Please try again."})

    return render(request, 'signup.html')

@login_required(login_url='login')
def HomePage(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    # course_links = CourseLinks.objects.filter(flag=user_profile.flag).first()  # Fetch the course link based on the flag
    course_links = CourseLinks.objects.filter(batch_number=user_profile.batch_number).first()  # Fetch the course link based on the batch number

    context = {
        'user_profile': user_profile,
        'flag': user_profile.flag,
        'Course_Links': course_links,
        'batch_number': user_profile.batch_number  # Pass batch_number to the context
    }
    return render(request, 'home2.html', context)

@login_required(login_url='login')
def req_view(request):
    return render(request, 'req.html')
def LoginPage(request):
    if request.method == 'POST':
        form = EmailLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                try:
                    user_profile = UserProfile.objects.get(user=user)
                    if user_profile.flag == 0:
                        return redirect('req')
                    else:
                        return redirect('home2')
                except UserProfile.DoesNotExist:
                    return render(request, 'login.html', {'form': form, 'error': 'User profile not found.'})
            else:
                return render(request, 'login.html', {'form': form, 'error': 'Invalid email or password.'})
    else:
        form = EmailLoginForm()

    return render(request, 'login.html', {'form': form})



def LogoutPage(request):
    logout(request)
    return redirect('login')


from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse,reverse_lazy
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from django.views.generic.edit import FormView

class CustomPasswordResetView(FormView):
    template_name = 'password_reset_form.html'
    success_url = reverse_lazy('password_reset_done')  # Use named URL here
    form_class = PasswordResetForm

    def form_valid(self, form):
        email = form.cleaned_data['email']
        users = User.objects.filter(email=email)
        if users.exists():
            for user in users:
                current_site = get_current_site(self.request)
                subject = 'Password Reset Requested'
                message = render_to_string('password_reset_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                    'protocol': 'https' if self.request.is_secure() else 'http',
                })
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
        return super().form_valid(form)



# from django.shortcuts import render, HttpResponse, redirect
# from django.contrib.auth.decorators import login_required
# from django.utils import timezone
# from .models import JoinDetails

# @login_required(login_url='login')
# def join_course(request):
#     if request.method == 'POST':
#         email = request.user.email
#         JoinDetails.objects.create(email=email, join_date=timezone.now())
#         course_link = request.POST.get('course_link')
#         if course_link:
#             return redirect(course_link)
#     return HttpResponse("Invalid request", status=400)

from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import JoinDetails, CourseLinks

@login_required(login_url='login')
def join_course(request):
    if request.method == 'POST':
        email = request.user.email
        course_link = request.POST.get('course_link')

        if course_link:
            course = CourseLinks.objects.filter(link=course_link).first()

            if course:
                current_date = timezone.now().date()
                record = Record_Landingpage.objects.filter(email=email).first()

                if record:
                    half_total_amount = record.total_amount / 2
                    quarter_total_amount = record.total_amount / 4

                    if record.amount <= quarter_total_amount:
                        due_date = course.start_date + timezone.timedelta(days=10)
                    elif record.amount <= half_total_amount:
                        due_date = course.start_date + timezone.timedelta(days=15)
                    elif record.amount < record.total_amount:
                        due_date = course.start_date + timezone.timedelta(days=20)
                    elif record.amount == record.total_amount:
                        due_date = course.start_date + timezone.timedelta(days=32)
                    else:
                        print("pls contact admin team")

                    if current_date > due_date:
                        messages.error(request, "You are unable to join this meeting. Please pay your balance course fees now.")
                        return redirect('add_record_landingpage')

                    # If within due date, record the join details and redirect to the course link
                    JoinDetails.objects.create(email=email, join_date=timezone.now())
                    return redirect(course_link)

    return HttpResponse("Invalid request", status=400)





from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .forms import *
from .models import *
from django.views.decorators.csrf import csrf_protect
@csrf_protect
def home(request):
	records = Record.objects.all()

	# Check to see if logging in
	if request.method == 'POST':
		username = request.POST['username']
		password = request.POST['password']
		# Authenticate
		user = authenticate(request, username=username, password=password)
		if user is not None and user.is_superuser:
			login(request, user)
			messages.success(request, "You Have Been Logged In!")
			return redirect('home')
		else:
			messages.success(request, "There Was An Error Logging In, Please Try Again...")
			return redirect('home')
	else:
		return render(request, 'home.html', {'records':records})







def register_user(request): #users register for admin
	if request.method == 'POST':
		form = SignUpForm(request.POST)
		if form.is_valid():
			form.save()
			# Authenticate and login
			username = form.cleaned_data['username']
			password = form.cleaned_data['password1']
			user = authenticate(username=username, password=password)
			login(request, user)
			messages.success(request, "You Have Successfully Registered! Welcome!")
			return redirect('home')
	else:
		form = SignUpForm()
		return render(request, 'register.html', {'form':form})

	return render(request, 'register.html', {'form':form})



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from decimal import Decimal, InvalidOperation

from django.shortcuts import render
from django.http import JsonResponse
from .models import Contact

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

@csrf_exempt
def generate_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email)
        if email:
            try:
                # Fetch the last sent OTP ID from session or initialize it
                last_sent_otp_id = request.session.get('last_sent_otp_id', 0)

                # Fetch the next OTP in the cycle
                otp_instance = Python_otp.objects.filter(id__gt=last_sent_otp_id).first()
                if not otp_instance:
                    # If no OTP found, start from the beginning
                    otp_instance = Python_otp.objects.first()

                # Update the last sent OTP ID in session
                request.session['last_sent_otp_id'] = otp_instance.id
                request.session['last_sent_otp_code'] = otp_instance.otp
                # Email sending logic
                sender_email = settings.EMAIL_HOST_USER
                sender_password = settings.EMAIL_HOST_PASSWORD

                msg = MIMEMultipart()
                msg['From'] = sender_email
                msg['To'] = email
                msg['Subject'] = 'Your OTP Code'

                body = f'Your OTP code is {otp_instance.otp}'
                msg.attach(MIMEText(body, 'plain'))

                server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                server.starttls()
                server.login(sender_email, sender_password)
                text = msg.as_string()
                server.sendmail(sender_email, email, text)
                server.quit()
                print("OTP Email sent successfully!")
                return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully'})
            except Exception as e:
                print(f"Error sending OTP Email: {e}")
                return JsonResponse('')
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})



def verify_otp(request):
    if request.method == 'POST':
        verification_code = request.POST.get('verification_code')
        # Retrieve the last sent OTP code from session
        last_sent_otp_code = request.session.get('last_sent_otp_code')
        if last_sent_otp_code and verification_code == last_sent_otp_code:
            return JsonResponse({'message': 'OTP verified', 'status': 'success'})
        else:
            return JsonResponse({'message': 'Invalid OTP', 'status': 'error'})
    return JsonResponse({'message': 'Method Not Allowed', 'status': 'error'}, status=405)



def logout_user(request):
	logout(request)
	messages.success(request, "You Have Been Logged Out...")
	return redirect('home')

def customer_record(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record.objects.get(id=pk)
		return render(request, 'record.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')

def delete_record(request, pk):
	if request.user.is_authenticated:
		delete_it = Record.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')


def add_record(request):
    form = AddRecordForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            # Save the form data without committing to the database yet
            add_record = form.save(commit=False)
            # Fetch all WhatsApp links from the database
            whatsapp_links = WhatsAppLink_python.objects.all()
            if whatsapp_links.exists():
                # Choose a random link from the queryset
                random_link_instance = random.choice(whatsapp_links)
                random_link = random_link_instance.link
                # Save the selected link to the record
                add_record.whatsapp_link = random_link
                add_record.save()
                messages.success(request, "Python Record Added ")
                # Redirect to the randomly chosen link
                return redirect(random_link)

    return render(request, 'add_record_python.html', {'form': form})

def update_record(request, pk):
	if request.user.is_authenticated:
		current_record = Record.objects.get(id=pk)
		form = AddRecordForm(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')



def python(request):
    records = Record.objects.all()
    return render(request, 'python.html', {'records':records})


# !------------Java  records functions------------!

def customer_record_java(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_java.objects.get(id=pk)
		return render(request, 'record_java.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')



def delete_record_java(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_java.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')




def add_record_java(request):
    form = AddRecordForm_java(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            # Save the form data without committing to the database yet
            add_record_java = form.save(commit=False)
            # Fetch all WhatsApp links from the database
            whatsapp_links = WhatsAppLink_java.objects.all()
            if whatsapp_links.exists():
                # Choose a random link from the queryset
                random_link_instance = random.choice(whatsapp_links)
                random_link = random_link_instance.link
                # Save the selected link to the record
                add_record_java.whatsapp_link = random_link
                add_record_java.save()
                messages.success(request, "Java Record Added ")
                # Redirect to the randomly chosen link
                return redirect(random_link)
            # else:
            #     messages.error(request, "No WhatsApp links available.")
    return render(request, 'add_record_java.html', {'form': form})



def update_record_java(request, pk):
	if request.user.is_authenticated:
		current_record = Record_java.objects.get(id=pk)
		form = AddRecordForm_java(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_java.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')



def java(request):
    records = Record_java.objects.all()
    return render(request, 'java.html', {'records':records})




#!--------community--------!
# from django.contrib.auth.decorators import login_required

# @login_required

def customer_record_community(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_community.objects.get(id=pk)
		return render(request, 'record_community.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')



def delete_record_community(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_community.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')




def add_record_community(request):
    form = AddRecordForm_community(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            # Save the form data without committing to the database yet
            add_record_community = form.save(commit=False)
            # Fetch all WhatsApp links from the database
            whatsapp_links = WhatsAppLink_community.objects.all()
            if whatsapp_links.exists():
                # Choose a random link from the queryset
                random_link_instance = random.choice(whatsapp_links)
                random_link = random_link_instance.link
                # Save the selected link to the record
                add_record_community.whatsapp_link = random_link
                add_record_community.save()
                messages.success(request, "community Record Added ")
                # Redirect to the randomly chosen link
                return redirect(random_link)
            # else:
            #     messages.error(request, "No WhatsApp links available.")
    return render(request, 'add_record_community.html', {'form': form})

def update_record_community(request, pk):
	if request.user.is_authenticated:
		current_record = Record_community.objects.get(id=pk)
		form = AddRecordForm_community(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_community.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')



def community(request):
    records = Record_community.objects.all()
    return render(request, 'community.html', {'records':records})




# Helper function to generate a random OTP
def generate_random_otp_1():
    return random.randint(100000, 999999)

def delete_expired_otps():
    expired_threshold = timezone.now() - timedelta(minutes=5)
    expired_otps = random_otp.objects.filter(created_at__lt=expired_threshold)
    expired_otps.delete()


# View to generate and send OTP
@csrf_exempt
def generate_otp_community(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email,"reg")
        if email:
            try:
                if random_otp.objects.filter(email=email).exists():
                    return JsonResponse({'status': 'error', 'message': 'OTP already sent to your email, please check it valid for 5 minutes'})
                otp = generate_random_otp_1()
                random_otp.objects.create(email=email, otp=otp)
                delete_expired_otps()
                sender_email = settings.EMAIL_HOST_USER
                sender_password = settings.EMAIL_HOST_PASSWORD
                msg = MIMEMultipart()
                msg['From'] = sender_email
                msg['To'] = email
                msg['Subject'] = 'Your OTP Code'
                body = f'Your OTP code is {otp}'
                msg.attach(MIMEText(body, 'plain'))
                server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                server.starttls()
                server.login(sender_email, sender_password)
                text = msg.as_string()
                server.sendmail(sender_email, email, text)
                server.quit()
                print("OTP Email sent successfully!")
                return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
            except Exception as e:
                print(f"Error sending OTP Email: {e}")
                return JsonResponse({'status': 'error', 'message': 'Failed to send OTP'})
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

# View to verify the OTP
@csrf_exempt
def verify_otp_community(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        verification_code = request.POST.get('verification_code')


        try:
            otp_instance = random_otp.objects.filter(email=email).latest('created_at')
            if otp_instance.otp == verification_code:
                otp_instance.delete()  # Delete the OTP entry from the database
                return JsonResponse({'message': 'OTP verified succesfully', 'status': 'success'})
            else:
                return JsonResponse({'message': 'OTP Entered is incorrect', 'status': 'error'})
        except random_otp.DoesNotExist:
            return JsonResponse({'message': 'Invalid OTP', 'status': 'error'})
    return JsonResponse({'message': 'Method Not Allowed', 'status': 'error'}, status=405)


#!---------basic_python_certificate------------!
def customer_record_basic_python_certificates(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_basic_python_certificates.objects.get(id=pk)
		return render(request, 'record_basic_python_certificates.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')


def delete_record_basic_python_certificates(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_basic_python_certificates.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')




def update_record_basic_python_certificates(request, pk):
	if request.user.is_authenticated:
		current_record = Record_basic_python_certificates.objects.get(id=pk)
		form = AddRecordForm_basic_python_certificates(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_basic_python_certificates.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')

def basic_python_certificates(request):
    records = Record_basic_python_certificates.objects.all()
    return render(request, 'basic_python_certificates.html', {'records':records})

def add_record_basic_python_certificates(request):
    form = AddRecordForm_basic_python_certificates(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            add_record_community = form.save()
            messages.success(request, "Basic python CERTIFICATE Record Added...")
            name = form.cleaned_data['name']

            # Generate certificate ID
            current_year = datetime.now().year
            latest_certificate = Certificate.objects.aggregate(Max('certificate_id'))
            latest_certificate_id = latest_certificate['certificate_id__max']
            if latest_certificate_id:
                latest_certificate_id_number = int(latest_certificate_id.split('/')[1])
            else:
                latest_certificate_id_number = 100000
            next_certificate_id_number = latest_certificate_id_number + 1
            certificate_id = f"{current_year}/{next_certificate_id_number:06d}"

            # Save certificate ID to the database
            Certificate.objects.create(name=name, certificate_id=certificate_id)

            pdf_file = generate_certificate_basic_python(name, certificate_id)

            # Serve the PDF for download
            response = HttpResponse(pdf_file, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="certificate_{name}.pdf"'
            return response

    return render(request, 'add_record_basic_python_certificates.html', {'form': form})

@csrf_exempt
def generate_otp_basic_python_certificates(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email,"basic python certificate")
        if email:
            try:
                # Check if the email exists in the Record table and cert value is 1
                if Record.objects.filter(email=email, cert=1).exists():
                    # Check if the email has already been issued a certificate
                    if Record_basic_python_certificates.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'Certificate already issued for this email'})
                    if random_otp.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'OTP already sent to your email, please check it valid for 5 minutes'})
                    # Generate a random OTP
                    otp = generate_random_otp_1()

                    # Save the email and OTP to the database
                    random_otp.objects.create(email=email, otp=otp)
                    # Call the function to delete expired OTPs
                    delete_expired_otps()

                    # # Email sending logic
                    sender_email = settings.EMAIL_HOST_USER
                    sender_password = settings.EMAIL_HOST_PASSWORD
                    # sender_emails = ['gurutech688@gmail.com', 'gurutech09876@gmail.com','gurutech2620@gmail.com','gurutech2026@gmail.com','gurutech897@gmail.com']
                    # sender_passwords = ['caczvezxbefewtav', 'vstxtkjlvacrwatj','bjhghplymboipyyz','ktjlqjdajbfbndaq','ovlxqsflkwzioeqm']



                    # selected_index = random.randint(0, 4)
                    # sender_email = sender_emails[selected_index]
                    # sender_password = sender_passwords[selected_index]

                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = email
                    msg['Subject'] = 'Your OTP Code'

                    body = f'Your OTP code is {otp}'
                    msg.attach(MIMEText(body, 'plain'))

                    server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                    server.starttls()
                    server.login(sender_email, sender_password)
                    text = msg.as_string()
                    server.sendmail(sender_email, email, text)
                    server.quit()
                    print("OTP Email sent successfully!")
                    return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
                elif Record.objects.filter(email=email, cert=0).exists():
                    # Update the cert value to 2
                    Record.objects.filter(email=email, cert=0).update(cert=2)
                    return JsonResponse({'status': 'error', 'message': 'contact admin for basic python certificates '})
                elif Record.objects.filter(email=email, cert=2).exists():

                    return JsonResponse({'status': 'error', 'message': 'You can\'t further get certificates for basic python.you are blocked '})
                else:
                    return JsonResponse({'status': 'error', 'message': 'Email is not registered for this course'})
            except Exception as e:
                print(f"Error sending OTP Email: {e}")
                return JsonResponse({'status': 'error', 'message': 'Failed to send OTP'})
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})



def generate_certificate_basic_python(name, certificate_id):
    buffer = BytesIO()
    document_title = "CERTIFICATE"
    title_2="OF INTERN COMPLETION"
    course_name = "Full Stack Python Developer"
    description = "For Successfully Completing Of The Full Stack Intern Python Developer"
    offered_by = "Offered By The Training Division Of Guru Tech"
    signature = "Selva Kumar\nHead of Proprietor"
    date = "Date: 2024-06-18"  # Example, can be dynamically generated
    LEDGER = (11*inch, 8.5*inch)
    c = canvas.Canvas(buffer, pagesize=LEDGER)
    width, height = LEDGER

    # Default image
    logo_path =finders.find('images/basic_python_cer.png')
    logo_width = width
    logo_height = height
    c.drawImage(logo_path, 0, 0, width=logo_width, height=logo_height)

    c.setFont("Helvetica-Bold", 18)
    text_width = c.stringWidth(name, "Helvetica-Bold", 18)
    text_x = (width - text_width) / 2.0
    text_y = height - 3.5 * inch
    c.drawString(text_x, text_y, name)

    # c.setFont("Helvetica", 12)
    # certificate_id_text = f"/{certificate_id}"
    # text_width = c.stringWidth(certificate_id_text, "Helvetica", 12)
    # text_x = (width - text_width) / 2.0
    # text_y -= 0.5 * inch
    # c.drawString(text_x, text_y, certificate_id_text)
    c.setFont("Helvetica", 16)
    certificate_id_text = f"/{certificate_id}"
    text_width = c.stringWidth(certificate_id_text, "Helvetica", 12.5)
    # text_x = (width - text_width) / 2.0
    # text_y -= 0.5 * inch
    offset = 40
    text_x = (width - text_width) / 2.0+ offset
    text_y = 0.5 * inch  # Position it 0.5 inch from the bottom of the page
    c.drawString(text_x, text_y, certificate_id_text)

    c.showPage()
    c.save()

    buffer.seek(0)
    return buffer


#!---------basic_java_certificate------------!
def customer_record_basic_java_certificates(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_basic_java_certificates.objects.get(id=pk)
		return render(request, 'record_basic_java_certificates.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')


def delete_record_basic_java_certificates(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_basic_java_certificates.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')





def update_record_basic_java_certificates(request, pk):
	if request.user.is_authenticated:
		current_record = Record_basic_java_certificates.objects.get(id=pk)
		form = AddRecordForm_basic_java_certificates(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_basic_java_certificates.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')

def basic_java_certificates(request):
    records = Record_basic_java_certificates.objects.all()
    return render(request, 'basic_java_certificates.html', {'records':records})

def add_record_basic_java_certificates(request):
    form = AddRecordForm_basic_java_certificates(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            add_record_community = form.save()
            messages.success(request, "Basic java CERTIFICATE Record Added...")
            name = form.cleaned_data['name']

            # Generate certificate ID
            current_year = datetime.now().year
            latest_certificate = Certificate.objects.aggregate(Max('certificate_id'))
            latest_certificate_id = latest_certificate['certificate_id__max']
            if latest_certificate_id:
                latest_certificate_id_number = int(latest_certificate_id.split('/')[1])
            else:
                latest_certificate_id_number = 100000
            next_certificate_id_number = latest_certificate_id_number + 1
            certificate_id = f"{current_year}/{next_certificate_id_number:06d}"

            # Save certificate ID to the database
            Certificate.objects.create(name=name, certificate_id=certificate_id)

            pdf_file = generate_certificate_basic_java(name, certificate_id)

            # Serve the PDF for download
            response = HttpResponse(pdf_file, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="certificate_{name}.pdf"'
            return response

    return render(request, 'add_record_basic_java_certificates.html', {'form': form})
# @csrf_exempt
# def generate_otp_basic_java_certificates(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         print(email)
#         if email:
#             try:
#                 # Check if the email exists in the Record table and cert value is 1
#                 if Record_java.objects.filter(email=email, cert=1).exists():
#                     # Check if the email has already been issued a certificate
#                     if Record_basic_java_certificates.objects.filter(email=email).exists():
#                             return JsonResponse({'status': 'error', 'message': 'Certificate already issued for this email'})
#                     # Generate a random OTP
#                     otp = generate_random_otp_1()

#                     # Save the email and OTP to the database
#                     random_otp.objects.create(email=email, otp=otp)
#                     # Call the function to delete expired OTPs
#                     delete_expired_otps()

#                     # Email sending logic
#                     sender_email = settings.EMAIL_HOST_USER
#                     sender_password = settings.EMAIL_HOST_PASSWORD
#                     # sender_emails = ['gurutech688@gmail.com', 'gurutech09876@gmail.com','gurutech2620@gmail.com','gurutech2026@gmail.com','gurutech897@gmail.com']
#                     # sender_passwords = ['caczvezxbefewtav', 'vstxtkjlvacrwatj','bjhghplymboipyyz','ktjlqjdajbfbndaq','ovlxqsflkwzioeqm']



#                     # selected_index = random.randint(0, 4)
#                     # sender_email = sender_emails[selected_index]
#                     # sender_password = sender_passwords[selected_index]


#                     msg = MIMEMultipart()
#                     msg['From'] = sender_email
#                     msg['To'] = email
#                     msg['Subject'] = 'Your OTP Code'

#                     body = f'Your OTP code is {otp}'
#                     msg.attach(MIMEText(body, 'plain'))

#                     server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
#                     server.starttls()
#                     server.login(sender_email, sender_password)
#                     text = msg.as_string()
#                     server.sendmail(sender_email, email, text)
#                     server.quit()
#                     print("OTP Email sent successfully!")
#                     return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
#                 elif Record_java.objects.filter(email=email, cert=0).exists():
#                     # Update the cert value to 2
#                     Record_java.objects.filter(email=email, cert=0).update(cert=2)
#                     return JsonResponse({'status': 'error', 'message': 'contact admin for basic java certificates '})
#                 elif Record_java.objects.filter(email=email, cert=2).exists():

#                     return JsonResponse({'status': 'error', 'message': 'You can\'t further get certificates for basic java.you are blocked '})
#                 else:
#                     return JsonResponse({'status': 'error', 'message': 'Email is not registered for the course'})
#             except Exception as e:
#                 print(f"Error sending OTP Email: {e}")
#                 return JsonResponse({'status': 'error', 'message': 'Failed to send OTP'})
#         return JsonResponse({'status': 'error', 'message': 'Email is required'})
#     return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
@csrf_exempt
def generate_otp_basic_java_certificates(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email,"basic java certificate")
        if email:
            try:
                # Check if the email exists in the Record table and cert value is 1
                # if Record_java.objects.filter(email=email, cert=1).exists():
                if Record_java.objects.filter(email=email, cert=1,attempt=4).latest('created_at'):
                    # Check if the email has already been issued a certificate
                    if Record_basic_java_certificates.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'Certificate already issued for this email'})
                    if random_otp.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'OTP already sent to your email, please check it valid for 5 minutes'})
                    # Generate a random OTP
                    otp = generate_random_otp_1()

                    # Save the email and OTP to the database
                    random_otp.objects.create(email=email, otp=otp)
                    # Call the function to delete expired OTPs
                    delete_expired_otps()

                    # Email sending logic
                    sender_email = settings.EMAIL_HOST_USER
                    sender_password = settings.EMAIL_HOST_PASSWORD

                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = email
                    msg['Subject'] = 'Your OTP Code'

                    body = f'Your OTP code is {otp}'
                    msg.attach(MIMEText(body, 'plain'))

                    server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                    server.starttls()
                    server.login(sender_email, sender_password)
                    text = msg.as_string()
                    server.sendmail(sender_email, email, text)
                    server.quit()
                    print("OTP Email sent successfully!")
                    return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
                elif Record_java.objects.filter(email=email, cert=0).exists():
                    # Update the cert value to 2
                    Record_java.objects.filter(email=email, cert=0).update(cert=2)
                    return JsonResponse({'status': 'error', 'message': 'contact admin for basic java certificates '})
                elif Record_java.objects.filter(email=email, cert=2).exists():

                    return JsonResponse({'status': 'error', 'message': 'You can\'t further get certificates for basic java.you are blocked '})
                else:
                    return JsonResponse({'status': 'error', 'message': 'Email is not registered for the course'})
            except Exception as e:
                print(f"Error sending OTP Email: {e}")
                return JsonResponse({'status': 'error', 'message': 'write  test first for certificate'})
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})



def generate_certificate_basic_java(name, certificate_id):
    buffer = BytesIO()
    document_title = "CERTIFICATE"
    title_2="OF INTERN COMPLETION"
    course_name = "Full Stack Python Developer"
    description = "For Successfully Completing Of The Full Stack Intern Python Developer"
    offered_by = "Offered By The Training Division Of Guru Tech"
    signature = "Selva Kumar\nHead of Proprietor"
    date = "Date: 2024-06-18"  # Example, can be dynamically generated
    LEDGER = (11*inch, 8.5*inch)
    c = canvas.Canvas(buffer, pagesize=LEDGER)
    width, height = LEDGER

    # Default image
    logo_path =finders.find('images/basic_java_cer.png')
    logo_width = width
    logo_height = height
    c.drawImage(logo_path, 0, 0, width=logo_width, height=logo_height)

    c.setFont("Helvetica-Bold", 18)
    text_width = c.stringWidth(name, "Helvetica-Bold", 18)
    text_x = (width - text_width) / 2.0
    text_y = height - 3.5 * inch
    c.drawString(text_x, text_y, name)

    # c.setFont("Helvetica", 12)
    # certificate_id_text = f"/{certificate_id}"
    # text_width = c.stringWidth(certificate_id_text, "Helvetica", 12)
    # text_x = (width - text_width) / 2.0
    # text_y -= 0.5 * inch
    # c.drawString(text_x, text_y, certificate_id_text)
    c.setFont("Helvetica", 16)
    certificate_id_text = f"/{certificate_id}"
    text_width = c.stringWidth(certificate_id_text, "Helvetica", 14)
    # text_x = (width - text_width) / 2.0
    # text_y -= 0.5 * inch
    offset = 40
    text_x = (width - text_width) / 2.0+ offset
    text_y = 0.5 * inch  # Position it 0.5 inch from the bottom of the page
    c.drawString(text_x, text_y, certificate_id_text)

    c.showPage()
    c.save()

    buffer.seek(0)
    return buffer



def generate_certificate(name):
    buffer = BytesIO()
    document_title = "CERTIFICATE"
    title_2="OF INTERN COMPLETION"
    course_name = "Full Stack Python Developer"
    description = "For Successfully Completing Of The Full Stack Intern Python Developer"
    offered_by = "Offered By The Training Division Of Guru Tech"
    signature = "Selva Kumar\nHead of Proprietor"
    certificate_id = "Certificate ID: 12345"  # Example, can be dynamically generated
    date = "Date: 2024-06-18"  # Example, can be dynamically generated
    LEDGER = (11*inch, 8.5*inch)
    c = canvas.Canvas(buffer, pagesize=LEDGER)
    width, height = LEDGER

    # Default image
    logo_path =finders.find('images/cer.jpeg')
    logo_width = width
    logo_height = height
    c.drawImage(logo_path, 0, 0, width=logo_width, height=logo_height)

    c.setFont("Helvetica-Bold", 18)
    text_width = c.stringWidth(name, "Helvetica-Bold", 18)
    text_x = (width - text_width) / 2.0
    text_y = height - 3.5 * inch
    c.drawString(text_x, text_y, name)

    c.showPage()
    c.save()

    buffer.seek(0)
    return buffer





def search_certificate(request):
    certificate_id = request.GET.get('certificate_id', None)
    certificate = None
    not_found = False
    if certificate_id:
        try:
            certificate = Certificate.objects.get(certificate_id=certificate_id)
        except Certificate.DoesNotExist:
            not_found = True
    return render(request, 'search_certificate.html', {'certificate': certificate, 'not_found': not_found})

#!---------_advance_python_reg------------!
def customer_record_advance_python_reg(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_advance_python_reg.objects.get(id=pk)
		return render(request, 'record_advance_python_reg.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')

def delete_record_advance_python_reg(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_advance_python_reg.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')
def add_record_advance_python_reg(request):
    form = AddRecordForm_advance_python_reg(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            # Save the form data without committing to the database yet
                form.save()
                messages.success(request, "Python Record Added ")
                # Redirect to the randomly chosen link
                return redirect('thank_you_for_reg')
            # else:
            #     messages.error(request, "No WhatsApp links available.")
    return render(request, 'add_record_advance_python_reg.html', {'form': form})

def update_record_advance_python_reg(request, pk):
	if request.user.is_authenticated:
		current_record = Record_advance_python_reg.objects.get(id=pk)
		form = AddRecordForm_advance_python_reg(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_advance_python_reg.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')
def advance_python_reg(request):
    records = Record_advance_python_reg.objects.all()
    return render(request, 'advance_python_reg.html', {'records':records})
def thank_you_for_reg(request):
    return render(request, 'thank_you_for_reg.html')

#!---------advance_python_certificate------------!
def customer_record_advance_python_certificates(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_advance_python_certificates.objects.get(id=pk)
		return render(request, 'record_advance_python_certificates.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')


def delete_record_advance_python_certificates(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_advance_python_certificates.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')


def update_record_advance_python_certificates(request, pk):
	if request.user.is_authenticated:
		current_record = Record_advance_python_certificates.objects.get(id=pk)
		form = AddRecordForm_advance_python_certificates(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_advance_python_certificates.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')

def advance_python_certificates(request):
    records = Record_advance_python_certificates.objects.all()
    return render(request, 'advance_python_certificates.html', {'records':records})

def add_record_advance_python_certificates(request):
    form = AddRecordForm_advance_python_certificates(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            add_record_community = form.save()
            messages.success(request, "Advance python CERTIFICATE Record Added...")
            name = form.cleaned_data['name']

            # Generate certificate ID
            current_year = datetime.now().year
            latest_certificate = Certificate.objects.aggregate(Max('certificate_id'))
            latest_certificate_id = latest_certificate['certificate_id__max']
            if latest_certificate_id:
                latest_certificate_id_number = int(latest_certificate_id.split('/')[1])
            else:
                latest_certificate_id_number = 100000
            next_certificate_id_number = latest_certificate_id_number + 1
            certificate_id = f"{current_year}/{next_certificate_id_number:06d}"

            # Save certificate ID to the database
            Certificate.objects.create(name=name, certificate_id=certificate_id)

            pdf_file = generate_certificate_advance_python(name, certificate_id)

            # Serve the PDF for download
            response = HttpResponse(pdf_file, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="certificate_{name}.pdf"'
            return response

    return render(request, 'add_record_advance_python_certificates.html', {'form': form})
@csrf_exempt
def generate_otp_advance_python_certificates(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email,"advance python certificate")
        if email:
            try:
                # Check if the email exists in the Record table and cert value is 1
                if Record_advance_python_reg.objects.filter(email=email, cert=1).exists():
                    # Check if the email has already been issued a certificate
                    if Record_advance_python_certificates.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'Certificate already issued for this email'})
                    if random_otp.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'OTP already sent to your email, please check it valid for 5 minutes'})
                    # Generate a random OTP
                    otp = generate_random_otp_1()

                    # Save the email and OTP to the database
                    random_otp.objects.create(email=email, otp=otp)
                    # Call the function to delete expired OTPs
                    delete_expired_otps()

                    # Email sending logic
                    sender_email = settings.EMAIL_HOST_USER
                    sender_password = settings.EMAIL_HOST_PASSWORD
                    # sender_emails = ['gurutech688@gmail.com', 'gurutech09876@gmail.com','gurutech2620@gmail.com','gurutech2026@gmail.com','gurutech897@gmail.com']
                    # sender_passwords = ['caczvezxbefewtav', 'vstxtkjlvacrwatj','bjhghplymboipyyz','ktjlqjdajbfbndaq','ovlxqsflkwzioeqm']



                    # selected_index = random.randint(0, 4)
                    # sender_email = sender_emails[selected_index]
                    # sender_password = sender_passwords[selected_index]

                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = email
                    msg['Subject'] = 'Your OTP Code'

                    body = f'Your OTP code is {otp}'
                    msg.attach(MIMEText(body, 'plain'))

                    server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                    server.starttls()
                    server.login(sender_email, sender_password)
                    text = msg.as_string()
                    server.sendmail(sender_email, email, text)
                    server.quit()
                    print("OTP Email sent successfully!")
                    return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
                elif Record_advance_python_reg.objects.filter(email=email, cert=0).exists():
                    # Update the cert value to 2
                    Record_advance_python_reg.objects.filter(email=email, cert=0).update(cert=2)
                    return JsonResponse({'status': 'error', 'message': 'contact admin for advance python certificates '})
                elif Record_advance_python_reg.objects.filter(email=email, cert=2).exists():

                    return JsonResponse({'status': 'error', 'message': 'You can\'t further get certificates for advance python.you are blocked '})
                else:
                    return JsonResponse({'status': 'error', 'message': 'Email is not registered for the course'})
            except Exception as e:
                print(f"Error sending OTP Email: {e}")
                return JsonResponse({'status': 'error', 'message': 'Failed to send OTP'})
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
def generate_certificate_advance_python(name, certificate_id):
    buffer = BytesIO()

    LEDGER = (11*inch, 8.5*inch)
    c = canvas.Canvas(buffer, pagesize=LEDGER)
    width, height = LEDGER

    # Default image
    logo_path =finders.find('images/advance_python_cer.png')
    logo_width = width
    logo_height = height
    c.drawImage(logo_path, 0, 0, width=logo_width, height=logo_height)

    c.setFont("Helvetica-Bold", 18)
    text_width = c.stringWidth(name, "Helvetica-Bold", 18)
    text_x = (width - text_width) / 2.0
    text_y = height - 3.5 * inch
    c.drawString(text_x, text_y, name)

    c.setFont("Helvetica", 16)
    certificate_id_text = f"/{certificate_id}"
    text_width = c.stringWidth(certificate_id_text, "Helvetica", 12.5)
    # text_x = (width - text_width) / 2.0
    # text_y -= 0.5 * inch
    offset = 40
    text_x = (width - text_width) / 2.0+ offset
    text_y = 0.5 * inch  # Position it 0.5 inch from the bottom of the page
    c.drawString(text_x, text_y, certificate_id_text)

    c.showPage()
    c.save()

    buffer.seek(0)
    return buffer


#!---------_advance_java_reg------------!
def customer_record_advance_java_reg(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_advance_java_reg.objects.get(id=pk)
		return render(request, 'record_advance_java_reg.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')

def delete_record_advance_java_reg(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_advance_java_reg.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')
def add_record_advance_java_reg(request):
    form = AddRecordForm_advance_java_reg(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            # Save the form data without committing to the database yet
                form.save()
                messages.success(request, "java Record Added ")
                # Redirect to the randomly chosen link
                return redirect('thank_you_for_reg')
            # else:
            #     messages.error(request, "No WhatsApp links available.")
    return render(request, 'add_record_advance_java_reg.html', {'form': form})

def update_record_advance_java_reg(request, pk):
	if request.user.is_authenticated:
		current_record = Record_advance_java_reg.objects.get(id=pk)
		form = AddRecordForm_advance_java_reg(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_advance_java_reg.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')
def advance_java_reg(request):
    records = Record_advance_java_reg.objects.all()
    return render(request, 'advance_java_reg.html', {'records':records})


#!----------advance_java_certificate------------!
def customer_record_advance_java_certificates(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_advance_java_certificates.objects.get(id=pk)
		return render(request, 'record_advance_java_certificates.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')


def delete_record_advance_java_certificates(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_advance_java_certificates.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')

def update_record_advance_java_certificates(request, pk):
	if request.user.is_authenticated:
		current_record = Record_advance_java_certificates.objects.get(id=pk)
		form = AddRecordForm_advance_java_certificates(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_advance_java_certificates.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')



def advance_java_certificates(request):
    records = Record_advance_java_certificates.objects.all()
    return render(request, 'advance_java_certificates.html', {'records':records})





def add_record_advance_java_certificates(request):
    form = AddRecordForm_advance_java_certificates(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            add_record_community = form.save()
            messages.success(request, "Advance java CERTIFICATE Record Added...")
            name = form.cleaned_data['name']

            # Generate certificate ID
            current_year = datetime.now().year
            latest_certificate = Certificate.objects.aggregate(Max('certificate_id'))
            latest_certificate_id = latest_certificate['certificate_id__max']
            if latest_certificate_id:
                latest_certificate_id_number = int(latest_certificate_id.split('/')[1])
            else:
                latest_certificate_id_number = 100000
            next_certificate_id_number = latest_certificate_id_number + 1
            certificate_id = f"{current_year}/{next_certificate_id_number:06d}"

            # Save certificate ID to the database
            Certificate.objects.create(name=name, certificate_id=certificate_id)

            pdf_file = generate_certificate_advance_java(name, certificate_id)

            # Serve the PDF for download
            response = HttpResponse(pdf_file, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="certificate_{name}.pdf"'
            return response

    return render(request, 'add_record_advance_java_certificates.html', {'form': form})


@csrf_exempt
def generate_otp_advance_java_certificates(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email,"advance java certificate")
        if email:
            try:
                # Check if the email exists in the Record table and cert value is 1
                if Record_advance_java_reg.objects.filter(email=email, cert=1).exists():
                    # Check if the email has already been issued a certificate
                    if Record_advance_java_certificates.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'Certificate already issued for this email'})
                    if random_otp.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'OTP already sent to your email, please check it valid for 5 minutes'})
                    # Generate a random OTP
                    otp = generate_random_otp_1()

                    # Save the email and OTP to the database
                    random_otp.objects.create(email=email, otp=otp)
                    # Call the function to delete expired OTPs
                    delete_expired_otps()

                    # Email sending logic
                    sender_email = settings.EMAIL_HOST_USER
                    sender_password = settings.EMAIL_HOST_PASSWORD
                    # sender_emails = ['gurutech688@gmail.com', 'gurutech09876@gmail.com','gurutech2620@gmail.com','gurutech2026@gmail.com','gurutech897@gmail.com']
                    # sender_passwords = ['caczvezxbefewtav', 'vstxtkjlvacrwatj','bjhghplymboipyyz','ktjlqjdajbfbndaq','ovlxqsflkwzioeqm']



                    # selected_index = random.randint(0, 4)
                    # sender_email = sender_emails[selected_index]
                    # sender_password = sender_passwords[selected_index]


                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = email
                    msg['Subject'] = 'Your OTP Code'

                    body = f'Your OTP code is {otp}'
                    msg.attach(MIMEText(body, 'plain'))

                    server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                    server.starttls()
                    server.login(sender_email, sender_password)
                    text = msg.as_string()
                    server.sendmail(sender_email, email, text)
                    server.quit()
                    print("OTP Email sent successfully!")
                    return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
                elif Record_advance_java_reg.objects.filter(email=email, cert=0).exists():
                    # Update the cert value to 2
                    Record_advance_java_reg.objects.filter(email=email, cert=0).update(cert=2)
                    return JsonResponse({'status': 'error', 'message': 'contact admin for advance java certificates '})
                elif Record_advance_java_reg.objects.filter(email=email, cert=2).exists():

                    return JsonResponse({'status': 'error', 'message': 'You can\'t further get certificates for advance java.you are blocked '})
                else:
                    return JsonResponse({'status': 'error', 'message': 'Email is not registered for the course'})
            except Exception as e:
                print(f"Error sending OTP Email: {e}")
                return JsonResponse({'status': 'error', 'message': 'Failed to send OTP'})
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

def generate_certificate_advance_java(name, certificate_id):
    buffer = BytesIO()

    LEDGER = (11*inch, 8.5*inch)
    c = canvas.Canvas(buffer, pagesize=LEDGER)
    width, height = LEDGER

    # Default image
    logo_path =finders.find('images/advance_java_cer.png')
    logo_width = width
    logo_height = height
    c.drawImage(logo_path, 0, 0, width=logo_width, height=logo_height)

    c.setFont("Helvetica-Bold", 18)
    text_width = c.stringWidth(name, "Helvetica-Bold", 18)
    text_x = (width - text_width) / 2.0
    text_y = height - 3.5 * inch
    c.drawString(text_x, text_y, name)

    c.setFont("Helvetica", 16)
    certificate_id_text = f"/{certificate_id}"
    text_width = c.stringWidth(certificate_id_text, "Helvetica", 14)
    # text_x = (width - text_width) / 2.0
    # text_y -= 0.5 * inch
    offset = 40
    text_x = (width - text_width) / 2.0+ offset
    text_y = 0.5 * inch  # Position it 0.5 inch from the bottom of the page
    c.drawString(text_x, text_y, certificate_id_text)

    c.showPage()
    c.save()

    buffer.seek(0)
    return buffer


#!---------intern_reg------------!
def customer_record_intern_reg(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_intern_reg.objects.get(id=pk)
		return render(request, 'record_intern_reg.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')

def delete_record_intern_reg(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_intern_reg.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')
def add_record_intern_reg(request):
    form = AddRecordForm_intern_reg(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            # Save the form data without committing to the database yet
                form.save()
                messages.success(request, "intern Record Added ")
                # Redirect to the randomly chosen link
                return redirect('thank_you_for_reg')
            # else:
            #     messages.error(request, "No WhatsApp links available.")
    return render(request, 'add_record_intern_reg.html', {'form': form})

def update_record_intern_reg(request, pk):
	if request.user.is_authenticated:
		current_record = Record_intern_reg.objects.get(id=pk)
		form = AddRecordForm_intern_reg(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_intern_reg.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')
def intern_reg(request):
    records = Record_intern_reg.objects.all()
    return render(request, 'intern_reg.html', {'records':records})

#!----------intern_certificate------------!
def customer_record_intern_certificates(request, pk):
	if request.user.is_authenticated:
		# Look Up Records
		customer_record = Record_intern_certificates.objects.get(id=pk)
		return render(request, 'record_intern_certificates.html', {'customer_record':customer_record})
	else:
		messages.success(request, "You Must Be Logged In To View That Page...")
		return redirect('home')


def delete_record_intern_certificates(request, pk):
	if request.user.is_authenticated:
		delete_it = Record_intern_certificates.objects.get(id=pk)
		delete_it.delete()
		messages.success(request, "Record Deleted Successfully...")
		return redirect('home')
	else:
		messages.success(request, "You Must Be Logged In To Do That...")
		return redirect('home')

def update_record_intern_certificates(request, pk):
	if request.user.is_authenticated:
		current_record = Record_intern_certificates.objects.get(id=pk)
		form = AddRecordForm_intern_certificates(request.POST or None, instance=current_record)
		if form.is_valid():
			form.save()
			messages.success(request, "Record Has Been Updated!")
			return redirect('home')
		return render(request, 'update_record_intern_certificates.html', {'form':form})
	else:
		messages.success(request, "You Must Be Logged In...")
		return redirect('home')



def intern_certificates(request):
    records = Record_intern_certificates.objects.all()
    return render(request, 'intern_certificates.html', {'records':records})





def add_record_intern_certificates(request):
    form = AddRecordForm_intern_certificates(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            add_record_community = form.save()
            messages.success(request, "Advance java CERTIFICATE Record Added...")
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            # Check if the email exists in Record_intern_reg
            existing_record = Record_intern_reg.objects.filter(email=email).first()
            if existing_record:
                start_date = existing_record.start_date
                end_date = existing_record.end_date
            else:
                start_date = None
                end_date = None

            # Generate certificate ID
            current_year = datetime.now().year
            latest_certificate = Certificate.objects.aggregate(Max('certificate_id'))
            latest_certificate_id = latest_certificate['certificate_id__max']
            if latest_certificate_id:
                latest_certificate_id_number = int(latest_certificate_id.split('/')[1])
            else:
                latest_certificate_id_number = 100000
            next_certificate_id_number = latest_certificate_id_number + 1
            certificate_id = f"{current_year}/{next_certificate_id_number:06d}"

            # Save certificate ID to the database
            Certificate.objects.create(name=name, certificate_id=certificate_id)

            #pdf_file = generate_certificate_intern(name, certificate_id)
            pdf_file = generate_certificate_intern(name, certificate_id, start_date, end_date)

            # Serve the PDF for download
            response = HttpResponse(pdf_file, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="certificate_{name}.pdf"'
            return response

    return render(request, 'add_record_intern_certificates.html', {'form': form})


@csrf_exempt
def generate_otp_intern_certificates(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        print(email,"intern certificate")
        if email:
            try:
                # Check if the email exists in the Record table and cert value is 1
                if Record_intern_reg.objects.filter(email=email, cert=1).exists():
                    # Check if the email has already been issued a certificate
                    if Record_intern_certificates.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'Certificate already issued for this email'})
                    if random_otp.objects.filter(email=email).exists():
                            return JsonResponse({'status': 'error', 'message': 'OTP already sent to your email, please check it valid for 5 minutes'})
                    # Generate a random OTP
                    otp = generate_random_otp_1()

                    # Save the email and OTP to the database
                    random_otp.objects.create(email=email, otp=otp)
                    # Call the function to delete expired OTPs
                    delete_expired_otps()

                    # Email sending logic
                    sender_email = settings.EMAIL_HOST_USER
                    sender_password = settings.EMAIL_HOST_PASSWORD
                    # sender_emails = ['gurutech688@gmail.com', 'gurutech09876@gmail.com','gurutech2620@gmail.com','gurutech2026@gmail.com','gurutech897@gmail.com']
                    # sender_passwords = ['caczvezxbefewtav', 'vstxtkjlvacrwatj','bjhghplymboipyyz','ktjlqjdajbfbndaq','ovlxqsflkwzioeqm']



                    # selected_index = random.randint(0, 4)
                    # sender_email = sender_emails[selected_index]
                    # sender_password = sender_passwords[selected_index]


                    msg = MIMEMultipart()
                    msg['From'] = sender_email
                    msg['To'] = email
                    msg['Subject'] = 'Your OTP Code'

                    body = f'Your OTP code is {otp}'
                    msg.attach(MIMEText(body, 'plain'))

                    server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                    server.starttls()
                    server.login(sender_email, sender_password)
                    text = msg.as_string()
                    server.sendmail(sender_email, email, text)
                    server.quit()
                    print("OTP Email sent successfully!")
                    return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
                elif Record_intern_reg.objects.filter(email=email, cert=0).exists():
                    # Update the cert value to 2
                    Record_intern_reg.objects.filter(email=email, cert=0).update(cert=2)
                    return JsonResponse({'status': 'error', 'message': 'contact admin for advance java certificates '})
                elif Record_intern_reg.objects.filter(email=email, cert=2).exists():

                    return JsonResponse({'status': 'error', 'message': 'You can\'t further get certificates for advance java.you are blocked '})
                else:
                    return JsonResponse({'status': 'error', 'message': 'Email is not registered for the course'})
            except Exception as e:
                print(f"Error sending OTP Email: {e}")
                return JsonResponse({'status': 'error', 'message': 'Failed to send OTP'})
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def generate_certificate_intern(name, certificate_id, start_date=None, end_date=None):
    buffer = BytesIO()

    LEDGER = (11*inch, 17*inch)
    c = canvas.Canvas(buffer, pagesize=LEDGER)
    width, height = LEDGER

    # Convert the name to title case
    name = name.title()


    # Page 1: current date, name, certificate ID
    logo_path = finders.find('images/1.png')
    c.drawImage(logo_path, 0, 0, width=width, height=height)

    current_date = datetime.now().strftime('%Y-%m-%d')
    c.setFont("Helvetica-Bold", 18)
    offset = 270  # Adjust this value as needed for the left side offset
    current_date_text = f"{current_date}"
    current_date_text_width = c.stringWidth(current_date_text, "Helvetica-Bold", 18)
    current_date_text_x = (width-current_date_text_width) /2.0 - offset
    current_date_text_y = height - 4 * inch
    c.drawString(current_date_text_x, current_date_text_y, current_date_text)

    c.setFont("Helvetica-Bold", 18)
    offset2 = 220
    name_text_width = c.stringWidth(name, "Helvetica-Bold", 18)
    # name_text_x = (width - name_text_width) / 2.0 - offset2
    # name_text_y = height - 4.3* inch
    name_text_x = 1.1 * inch
    name_text_y = 12.7 * inch
    c.drawString(name_text_x, name_text_y, name)

    c.setFont("Helvetica", 17)
    offset7 = 210
    name2 = f"Dear {name},"
    name_text_width = c.stringWidth(name2, "Helvetica", 17)
    name_text_x = 1.1 * inch
    name_text_y = height - 6.3 * inch
    c.drawString(name_text_x, name_text_y, name2)

    c.setFont("Helvetica", 15)
    certificate_id_text = f"/{certificate_id}"
    text_width = c.stringWidth(certificate_id_text, "Helvetica", 15)
    offset3=133
    text_x = (width - text_width) / 2.0 - offset3
    text_y = 1.02 * inch
    c.drawString(text_x, text_y, certificate_id_text)



    c.showPage()

    # Page 2: start date, end date, certificate ID
    logo_path2 = finders.find('images/2.png')
    c.drawImage(logo_path2, 0, 0, width=width, height=height)

    if start_date:
        formatted_start_date = start_date.strftime('%d-%m-%Y')
        c.setFont("Helvetica-Bold", 14)
        start_date_text = f"Start Date: {formatted_start_date}"
        start_date_text_width = c.stringWidth(start_date_text, "Helvetica-Bold", 14)
        offset5=241
        start_date_text_x = (width - start_date_text_width) / 2.0 - offset5
        start_date_text_y = height - 4.8 * inch
        c.drawString(start_date_text_x, start_date_text_y, start_date_text)

    if end_date:
        formatted_end_date = end_date.strftime('%d-%m-%Y')
        c.setFont("Helvetica-Bold", 14)
        end_date_text = f"End Date: {formatted_end_date}"
        end_date_text_width = c.stringWidth(end_date_text, "Helvetica-Bold", 14)
        offset6=242
        end_date_text_x = (width - end_date_text_width) / 2.0 - offset6
        end_date_text_y = start_date_text_y - 0.3 * inch
        c.drawString(end_date_text_x, end_date_text_y, end_date_text)

    # c.setFont("Helvetica", 12)
    # c.drawString(text_x, text_y, certificate_id_text)

    # validation_text_y = text_y + 0.25 * inch
    # c.drawString(validation_text_x, validation_text_y, validation_text)
    c.setFont("Helvetica", 15)
    certificate_id_text = f"/{certificate_id}"
    text_width = c.stringWidth(certificate_id_text, "Helvetica", 15)
    offset3=133
    text_x = (width - text_width) / 2.0 - offset3
    text_y = 1.02 * inch
    c.drawString(text_x, text_y, certificate_id_text)





    c.showPage()

    # Page 3: name, certificate ID
    logo_path3 = finders.find('images/3.png')
    c.drawImage(logo_path3, 0, 0, width=width, height=height)

    # c.setFont("Helvetica-Bold", 18)
    # c.drawString(name_text_x, name_text_y, name)
    c.setFont("Helvetica-Bold", 17)
    offset2 = 205
    name1 = f"{name},"
    name_text_width = c.stringWidth(name1, "Helvetica-Bold", 17)
    name_text_x = 1.3 * inch
    name_text_y = height - 5 * inch
    c.drawString(name_text_x, name_text_y, name1)

    # c.setFont("Helvetica", 12)
    # c.drawString(text_x, text_y, certificate_id_text)

    # c.drawString(validation_text_x, validation_text_y, validation_text)
    c.setFont("Helvetica", 15)
    certificate_id_text = f"/{certificate_id}"
    text_width = c.stringWidth(certificate_id_text, "Helvetica", 15)
    offset3=133
    text_x = (width - text_width) / 2.0 - offset3
    text_y = 1.02 * inch
    c.drawString(text_x, text_y, certificate_id_text)



    c.showPage()

    c.save()

    buffer.seek(0)
    return buffer

from django.shortcuts import render, get_object_or_404
from django.shortcuts import get_object_or_404
from django.shortcuts import render, get_object_or_404

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def verify_otp_community_landingpage(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        verification_code = request.POST.get('verification_code')

        try:
            otp_instance = random_otp.objects.filter(email=email).latest('created_at')
            if otp_instance.otp == verification_code:
                otp_instance.delete()  # Delete the OTP entry from the database

                try:
                    record = Record_Landingpage.objects.get(email=email)
                    data = {
                        'message': 'OTP verified successfully',
                        'status': 'success',
                        'amount': record.amount,
                        'balance_amount': record.balance_amount,
                        'total_amount': record.total_amount
                    }
                except Record_Landingpage.DoesNotExist:
                    data = {
                        'message': 'OTP verified successfully',
                        'status': 'success'
                    }

                return JsonResponse(data)
            else:
                return JsonResponse({'message': 'OTP Entered is incorrect', 'status': 'error'})
        except random_otp.DoesNotExist:
            return JsonResponse({'message': 'Invalid OTP', 'status': 'error'})
    return JsonResponse({'message': 'Method Not Allowed', 'status': 'error'}, status=405)

#!---------basic_python_certificate------------!



# def add_record_landingpage(request):
#     if request.method == "POST":
#         form = AddRecordLandingpageForm(request.POST)
#         if form.is_valid():
#             name = form.cleaned_data['name']
#             email = form.cleaned_data['email']
#             phone = form.cleaned_data['phone']
#             batch_number = form.cleaned_data['batch_number']
#             try:
#                 amount = int(form.cleaned_data['amount']) * 100
#                 #amount = int(request.POST.get('amount')) * 100
#                 print(amount, type(amount))
#             except InvalidOperation:
#                 messages.error(request, "Invalid amount. Please enter a valid number.")
#                 return render(request, 'add_record_landingpage.html', {'form': form})


#             try:
#                 # client = razorpay.Client(auth=('rzp_test_I4CeG7pUY0K5BP', 'NoTvdgGVAfegBisCPePmru9t'))
#                 # # Make a test API call to check the connection
#                 # response = client.order.all()
#                 # print("Responsev:", response)
#                 client = razorpay.Client(auth=('rzp_live_mE6RBTFnjDkz48', 'M0oDyJt9wZdlrWzCnbWGjYUe'))

#                 response_payment = client.order.create(dict(amount=amount, currency='INR'))

#                 order_id = response_payment['id']
#                 order_status = response_payment['status']

#                 if order_status == 'created':
#                     response_payment['name'] = name
#                     response_payment['email'] = email
#                     response_payment['phone'] = phone
#                     response_payment['batch_number'] = batch_number

#                     return render(request, 'thankyou_landingpage.html', {
#                         'payment': response_payment,
#                     })
#                 else:
#                     messages.error(request, "Failed to create payment order. Please try again.")
#                     return render(request, 'add_record_landingpage.html', {'form': form})

#             except razorpay.errors.BadRequestError as e:
#                 print("BadRequestError apikey and security key is wrong regenerate the keys:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })
#             except razorpay.errors.ServerError as e:
#                 print("ServerError:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })
#             except razorpay.errors.NetworkError as e:
#                 print("NetworkError:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })
#             except Exception as e:
#                 print("An error occurred:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })



#     else:
#         form = AddRecordLandingpageForm()

#     return render(request, 'add_record_landingpage.html', {'form': form})


# def add_record_landingpage(request):
#     if request.method == "POST":
#         form = AddRecordLandingpageForm(request.POST)
#         if form.is_valid():
#             name = form.cleaned_data['name']
#             email = form.cleaned_data['email']
#             phone = form.cleaned_data['phone']
#             # try:
#             #     amount = int(form.cleaned_data['amount']) * 100
#             #     #amount = int(request.POST.get('amount')) * 100
#             #     print(amount, type(amount))
#             # except InvalidOperation:
#             #     messages.error(request, "Invalid amount. Please enter a valid number.")
#             #     return render(request, 'add_record_landingpage.html', {'form': form})


#             try:
#                 # client = razorpay.Client(auth=('rzp_test_I4CeG7pUY0K5BP', 'NoTvdgGVAfegBisCPePmru9t'))
#                 # # Make a test API call to check the connection
#                 # response = client.order.all()
#                 # print("Responsev:", response)
#                 #client = razorpay.Client(auth=('rzp_test_I4CeG7pUY0K5BP', 'NoTvdgGVAfegBisCPePmru9t'))
#                 client = razorpay.Client(auth=('rzp_live_mE6RBTFnjDkz48', 'M0oDyJt9wZdlrWzCnbWGjYUe'))

#                 response_payment = client.order.create(dict(amount=19900, currency='INR'))

#                 order_id = response_payment['id']
#                 order_status = response_payment['status']

#                 if order_status == 'created':
#                     response_payment['name'] = name
#                     response_payment['email'] = email
#                     response_payment['phone'] = phone

#                     return render(request, 'thankyou_landingpage.html', {
#                         'payment': response_payment,
#                     })
#                 else:
#                     messages.error(request, "Failed to create payment order. Please try again.")
#                     return render(request, 'add_record_landingpage.html', {'form': form})

#             except razorpay.errors.BadRequestError as e:
#                 print("BadRequestError apikey and security key is wrong regenerate the keys:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })
#             except razorpay.errors.ServerError as e:
#                 print("ServerError:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })
#             except razorpay.errors.NetworkError as e:
#                 print("NetworkError:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })
#             except Exception as e:
#                 print("An error occurred:", e)
#                 return render(request, 'payment_status.html', {
#                 'status': 'Razorpay BadRequestError'
#             })



#     else:
#         form = AddRecordLandingpageForm()

#     return render(request, 'add_record_landingpage.html', {'form': form})


# @csrf_exempt
# def payment_status(request):
#     if request.method == "POST":
#         response = request.POST
#         params_dict = {
#             'razorpay_order_id': response.get('razorpay_order_id'),
#             'razorpay_payment_id': response.get('razorpay_payment_id'),
#             'razorpay_signature': response.get('razorpay_signature')
#         }

#         client = razorpay.Client(auth=('rzp_live_mE6RBTFnjDkz48', 'M0oDyJt9wZdlrWzCnbWGjYUe'))

#         try:
#             status = client.utility.verify_payment_signature(params_dict)
#             if status:
#                 name = request.POST.get('name')
#                 email = request.POST.get('email')
#                 phone = request.POST.get('phone')
#                 amount = Decimal(request.POST.get('amount')) / 100  # Convert back to main currency
#                 batch_number = request.POST.get('batch_number')
#                 razorpay_payment_id = response.get('razorpay_payment_id')  # Get the Razorpay payment ID

#                 batch = get_object_or_404(Batch, batch_number=batch_number)
#                 fees_amount = batch.fees_amount

#                 total_amount = Decimal(fees_amount)
#                 balance_amount = total_amount - amount

#                 existing_record = Record_Landingpage.objects.filter(email=email).first()
#                 razorpay_payment_check = Record_Landingpage.objects.filter(razorpay_payment_id=razorpay_payment_id).first()

#                 if existing_record and not razorpay_payment_check:
#                     existing_record.amount += amount
#                     existing_record.balance_amount -= amount
#                     existing_record.razorpay_payment_id = razorpay_payment_id  # Update the Razorpay payment ID
#                     existing_record.save()
#                     record = existing_record
#                 elif razorpay_payment_check:
#                     return render(request, 'payment_status.html', {
#                         'status': 'payment_id',
#                         'amount': str(razorpay_payment_check.amount),
#                         'balance_amount': str(razorpay_payment_check.balance_amount),
#                         'total_amount': str(razorpay_payment_check.total_amount),
#                     })
#                 else:
#                     new_record = Record_Landingpage(
#                         name=name,
#                         email=email,
#                         phone=phone,
#                         amount=amount,
#                         total_amount=total_amount,
#                         balance_amount=balance_amount,
#                         student_batch=batch_number,
#                         razorpay_payment_id=razorpay_payment_id  # Save the Razorpay payment ID
#                     )
#                     new_record.save()
#                     record = new_record

#                 return render(request, 'payment_status.html', {
#                     'amount': str(record.amount),
#                     'balance_amount': str(record.balance_amount),
#                     'total_amount': str(record.total_amount),
#                     'status': 'success'
#                 })
#             else:
#                 print("Payment verification failed")
#                 return render(request, 'payment_status.html', {
#                     'status': 'Payment verification failed'
#                 })
#         except razorpay.errors.SignatureVerificationError:
#             print("Razorpay signature verification failed")
#             return render(request, 'payment_status.html', {
#                 'status': 'Razorpay signature verification failed'
#             })
#         except Exception as e:
#             print(f"An error occurred: {e}")
#             return render(request, 'payment_status.html', {'status': False})

#     return render(request, 'payment_status.html', {
#         'status': 'Invalid request method'
#     })


# @csrf_exempt
# def payment_status(request):
#     if request.method == "POST":
#         response = request.POST
#         params_dict = {
#             'razorpay_order_id': response.get('razorpay_order_id'),
#             'razorpay_payment_id': response.get('razorpay_payment_id'),
#             'razorpay_signature': response.get('razorpay_signature')
#         }

#         #client = razorpay.Client(auth=('rzp_test_I4CeG7pUY0K5BP', 'NoTvdgGVAfegBisCPePmru9t'))
#         client = razorpay.Client(auth=('rzp_live_mE6RBTFnjDkz48', 'M0oDyJt9wZdlrWzCnbWGjYUe'))

#         try:
#             status = client.utility.verify_payment_signature(params_dict)
#             if status:
#                 name = request.POST.get('name')
#                 email = request.POST.get('email')
#                 phone = request.POST.get('phone')
#                 amount = Decimal(request.POST.get('amount')) / 100  # Convert back to main currency
#                 razorpay_payment_id = response.get('razorpay_payment_id')  # Get the Razorpay payment ID



#                 existing_record = Record_Landingpage.objects.filter(email=email).first()
#                 razorpay_payment_check = Record_Landingpage.objects.filter(razorpay_payment_id=razorpay_payment_id).first()

#                 if existing_record and not razorpay_payment_check:
#                     existing_record.amount += amount

#                     existing_record.razorpay_payment_id = razorpay_payment_id  # Update the Razorpay payment ID
#                     existing_record.save()
#                     record = existing_record
#                 elif razorpay_payment_check:
#                     return render(request, 'payment_status.html', {
#                         'status': 'payment_id',
#                         'amount': str(razorpay_payment_check.amount),

#                     })
#                 else:
#                     new_record = Record_Landingpage(
#                         name=name,
#                         email=email,
#                         phone=phone,
#                         amount=amount,
#                         razorpay_payment_id=razorpay_payment_id  # Save the Razorpay payment ID
#                     )
#                     new_record.save()
#                     record = new_record

#                 return render(request, 'payment_status.html', {
#                     'amount': str(record.amount),

#                     'status': 'success'
#                 })
#             else:
#                 print("Payment verification failed")
#                 return render(request, 'payment_status.html', {
#                     'status': 'Payment verification failed'
#                 })
#         except razorpay.errors.SignatureVerificationError:
#             print("Razorpay signature verification failed")
#             return render(request, 'payment_status.html', {
#                 'status': 'Razorpay signature verification failed'
#             })
#         except Exception as e:
#             print(f"An error occurred: {e}")
#             return render(request, 'payment_status.html', {'status': False})

#     return render(request, 'payment_status.html', {
#         'status': 'Invalid request method'
#     })

def advance_python_account_list(request):
    records = Record_Landingpage.objects.all()
    return render(request, 'advance_python_account_list.html', {'records': records})

# def landingpage(request):
# 	return render(request, 'landingpage.html')
# def terms(request):
#     return render(request,'terms.html')

# def contactus(request):
#     if request.method == 'POST':
#         name = request.POST.get('fname')
#         phone = request.POST.get('phone')
#         email = request.POST.get('email')
#         message = request.POST.get('msg')

#         # Server-side validation
#         errors = {}
#         if not name:
#             errors['fname'] = 'Name is required.'
#         phone_pattern = re.compile(r'^(\+?\d{1,4}[-\s]?)?\d{10}$')
#         if not phone or not phone_pattern.match(phone):
#             errors['phone'] = 'Enter a valid phone number (10 digits or with country code).'

#         if not email:
#             errors['email'] = 'Email is required.'
#         if not message:
#             errors['msg'] = 'Message is required.'

#         if errors:
#             return JsonResponse({'success': False, 'errors': errors})

#         # Save data to the database
#         Contact.objects.create(name=name, phone=phone, email=email, message=message)
#         from_email=settings.EMAIL_HOST_USER
#         email_message = f"Name: {name}\nPhone: {phone}\nEmail: {email}\nMessage:\n{message}"
#         send_mail(
#             f'Message from Guru Tech website users doubts {email}',
#             email_message,
#             from_email,
#             ['haritamilhp@gmail.com'],  # Replace with the website owner's email address
#         )

#         return JsonResponse({'success': True, 'message': 'Thank you for your message!'})

#     return render(request, 'Contact us.html')

from django.shortcuts import render
from .models import Basic_JavaQuestion,Record_java
import random

def quiz(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        print(email)
        # Handle form submission
        selected_answers = request.POST.dict()
        score = 0
        total_questions = 30

        for key, value in selected_answers.items():
            if key.startswith('question_'):
                question_id = int(key.split('_')[1])
                question = Basic_JavaQuestion.objects.get(pk=question_id)
                if question.correct_option == value:
                    score += 1
        percentage_score = (score / total_questions) * 100

        try:
            # Get the latest Record_java entry for the given email
            latest_record = Record_java.objects.filter(email=email).latest('created_at')
            # Update the cert and attempt based on percentage_score
            if percentage_score >= 80:
                latest_record.cert = 1
                latest_record.attempt = 4
            else:
                if latest_record.attempt == 1:
                    latest_record.attempt = 2
                else:
                    latest_record.attempt = 1
            latest_record.save()
        except Record_java.DoesNotExist:
            pass  # Handle the case where no record is found

        return render(request, 'results.html', {'score': score, 'total': total_questions,'percentage': percentage_score})

    else:
        questions = list(Basic_JavaQuestion.objects.all())
        if len(questions) < 30:
            return HttpResponse("Not enough questions in the database. Please add more questions.")

        selected_questions = random.sample(questions, 30)
        # Prepare questions with index for template rendering
        questions_with_index = [(index, question) for index, question in enumerate(selected_questions)]
        return render(request, 'quiz.html', {'questions': questions_with_index})
#random_otp.objects.filter(email=email).latest('created_at')
from django.shortcuts import get_object_or_404
from django.http import JsonResponse

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
import json

@csrf_exempt
def generate_otp_basic_java_questions(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        print(email,"basic java test")
        if email:
            try:
                user_record = Record_java.objects.filter(email=email).latest('created_at')
                if user_record:
                    if user_record.attempt == 4:
                        return JsonResponse({'status': 'error', 'message': 'Test already passed'})
                    elif user_record.attempt == 2:
                        return JsonResponse({'status': 'error', 'message': 'Attempt for test finished'})
                    elif user_record.attempt in [0, 1]:
                        try:
                            if random_otp.objects.filter(email=email).exists():
                                     return JsonResponse({'status': 'error', 'message': 'OTP already sent to your email, please check it valid for 5 minutes'})
                            otp = generate_random_otp_1()
                            random_otp.objects.create(email=email, otp=otp)

                            sender_email = settings.EMAIL_HOST_USER
                            sender_password = settings.EMAIL_HOST_PASSWORD

                            msg = MIMEMultipart()
                            msg['From'] = sender_email
                            msg['To'] = email
                            msg['Subject'] = 'Your OTP Code'

                            body = f'Your OTP code is {otp}'
                            msg.attach(MIMEText(body, 'plain'))

                            server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
                            server.starttls()
                            server.login(sender_email, sender_password)
                            text = msg.as_string()
                            server.sendmail(sender_email, email, text)
                            server.quit()
                            print("OTP Email sent successfully!")
                            return JsonResponse({'status': 'success', 'message': 'OTP generated and sent successfully to your email'})
                        except Exception as e:
                            print(f"Error sending OTP Email: {e}")
                            return JsonResponse({'status': 'error', 'message': 'Failed to send OTP'})
                else:
                    return JsonResponse({'status': 'error', 'message': 'Email is not registered'})
            except Record_java.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Email is not registered'})
        return JsonResponse({'status': 'error', 'message': 'Email is required'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})
@csrf_exempt
def verify_otp_new(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        verification_code = data.get('verification_code')

        try:
            otp_instance = random_otp.objects.filter(email=email).latest('created_at')
            if otp_instance.otp == verification_code:
                otp_instance.delete()  # Delete the OTP entry from the database after verification
                return JsonResponse({'message': 'OTP verified successfully', 'status': 'success'})
            else:
                return JsonResponse({'message': 'Incorrect OTP entered', 'status': 'error'})
        except random_otp.DoesNotExist:
            return JsonResponse({'message': 'Invalid OTP or OTP expired', 'status': 'error'})


