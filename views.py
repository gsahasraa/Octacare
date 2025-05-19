from datetime import timezone
from email.message import EmailMessage
from multiprocessing.connection import Client
from click import FileError
from django.conf import settings
from django.shortcuts import render,redirect
from django.urls import reverse

from .utils.ai_verification import verify_document

# from code.otcproject.otcapp import models # type: ignore


account_sid = 'AC87c2a7f0187439b6c1e08ee06c74025f'       # Replace with your Account SID
auth_token = 'a771922a4ceff468d85871853f052242'         # Replace with your Auth Token
twilio_phone_number = '+13218004216'
        
# Function to send SMS using Twilio
def send_sms(receiver_phone_number,message):
    try:
        # Retrieve Twilio credentials from settings
        # account_sid = settings.TWILIO_ACCOUNT_SID  # Set this in your settings.py
        # auth_token = settings.TWILIO_AUTH_TOKEN  # Set this in your settings.py
        # twilio_phone_number = settings.TWILIO_PHONE_NUMBER  # Set this in your settings.py
        #     # Twilio credentials
        
        # Ensure the receiver's phone number is in the correct format
        receiver_phone_number = f'+91{receiver_phone_number}'
        
        # Initialize Twilio Client
        client = Client(account_sid, auth_token)
        message_body = message
        # message_body = "Emergency alert: Your friend needs your help."
        message = client.messages.create(
            body=message_body,
            from_=twilio_phone_number,
            to=receiver_phone_number
        )
        print(f"Message sent with SID: {message.sid}")
    except Exception as e:
        print(f"Error sending SMS: {e}")
# Create your views here.

from django.conf import settings

# def send_sms():
#    client = Client(account_sid, auth_token)
# #    print(f"SMS sent to {receiver_phone}")
  
  
def openingpage(request):
    return render(request, 'opening_page.html')

def index(request):
    return render(request, "index.html")

def about(request):
    return render(request, "about.html")


def overviewpage(request):
    return render(request, 'overviewpage.html')

def selectuser(request):
    return render(request, 'select_user.html')

def user_patient(request):
    return render(request, 'user_patient.html')



# from django.shortcuts import render
# from django.http import JsonResponse

# def show_ip_page(request):
#     return render(request, 'ip_address.html')

# def get_ip_address(request):
#     ip_address = request.META.get('REMOTE_ADDR')
    
#     if ip_address == '127.0.0.1':
#         ip_address = '8.8.8.8'  # Example IP for testing

#     return JsonResponse({'ip_address': ip_address})
# ipapp/views.py
# import geocoder
# from django.http import JsonResponse
# from django.shortcuts import render

# def get_ip_location(request):
#     # Get the geographical information of the current IP address
#     # g = geocoder.ip('me')

#     # Accessing the latitude and longitude
#     g=True
#     if g:  # Check if the geocoding was successful
#         lat, lng =18.530300, 79.627288 # Retrieve the latitude and longitude
#         maps_link = f"https://www.google.com/maps?q={lat},{lng}"  # Google Maps link
#         return JsonResponse({
#             'latitude': lat,
#             'longitude': lng,
#             'maps_link': maps_link
#         })
#     else:
#         return JsonResponse({'error': 'Unable to retrieve location data.'})

# def home(request):
#     return render(request, 'ip_address.html')


def patient_homepage(request):
    return render(request,"user_homepage.html")

def user_signup(request):
    return render(request, "user_signuppage.html")





def password_options(request):
    return render(request, 'password_resetoption.html')



def forgotpass(request):
    return render(request, 'forgotoss.html')



def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = mainuser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, mainuser.DoesNotExist):
        user = None
    
    if user is not None:
        signer = TimestampSigner()
        try:
            # Check if token is valid and not expired (2-minute limit)
            original_token = signer.unsign(token, max_age=300)  # 120 seconds = 2 minutes
            if account_activation_token.check_token(user, original_token):
                if request.method == "POST":
                    new_password = request.POST.get("new_password")
                    user.user_password = new_password  # Hash the password before saving
                    user.save()
                    return redirect('password_reset_complete')
                return render(request, 'password_reset_confirm.html', {'uidb64': uidb64, 'token': token})
        except (SignatureExpired, BadSignature):
            return redirect('password_reset_invalid')
    return redirect('password_reset_invalid')


def password_reset_complete(request):
    return render(request, "password_reset_complete.html")


from django.shortcuts import render, redirect
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.urls import reverse
from django.conf import settings
from .models import mainuser
from .tokens import account_activation_token
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature

def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = mainuser.objects.get(email=email)
            signer = TimestampSigner()
            token = signer.sign(account_activation_token.make_token(user))
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token}))
            mail_subject = 'Reset your password'
            message = f"""\
            <html>
            <body>
            <p>Hi { user.full_name }</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="{reset_link }">{ reset_link }</a></p>
            </body>
            </html>
            """
            emailm = EmailMessage(
                mail_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email]
            )
            emailm.content_subtype = 'html'
            emailm.send(fail_silently=False)
            return redirect('password_reset_done')
        except mainuser.DoesNotExist:
            return render(request, "password_reset_form.html", {'error': 'Email does not exist'})
    return render(request, "password_reset_form.html")



def password_reset_done(request):
    return render(request, "password_reset_done.html")


from django.core.mail import EmailMessage
from django.conf import settings
from django.shortcuts import render
from .models import mainuser

def fgpm(request):
    error_message = None
    if request.method == 'POST':
        entered_email = request.POST['forgotemail']
    
        # Check if the email exists in the mainuser model
        try:
            user = mainuser.objects.get(email=entered_email)
            # Decode the password (assuming decode_password is a function you've defined)
            fp = decode_password(user.password)
            
            # HTML message with the password
            message = f"""\
            <html>
            <body>
                <p>Your password:</p>
                <hr>
                <h1>{fp}</h1>
            </body>
            </html>
            """
            
            # Create and send the email
            email = EmailMessage(
                'SmartMart',
                message,
                settings.EMAIL_HOST_USER,
                [entered_email]
            )
            email.content_subtype = 'html'  # Set the content to HTML
            email.send(fail_silently=False)
            
            # Redirect to a success page after sending the email
            return render(request, 'forgotpasssucces.html')
        except mainuser.DoesNotExist:
            # If the email doesn't exist, display an error message
            error_message = 'This email is not registered.'
    
    # Render the form again with an error message if there's an error or for GET request
    return render(request, 'forgotoss.html', {'error_message': error_message})






import base64

def encode_password(password):
    encoded_password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
    return encoded_password




def decode_password(encoded_password):
    try:
        decoded_password = base64.b64decode(encoded_password).decode('utf-8')
    except UnicodeDecodeError:
        # Handle the case where decoding fails due to invalid characters
        decoded_password = "Unable to decode password"
    return decoded_password


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import mainuser, Donor
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponse
from django.contrib.auth.models import User
from .models import mainuser

def register_user(request):
    if request.method == "POST":
        print("1111111111")
        full_name = request.POST.get("full_name")
        email = request.POST.get("email")
        password = request.POST.get("password")
        cpassword =request.POST.get("confirm_password")
        phone_number = request.POST.get("phone")
        address = request.POST.get("address")
        user_type = request.POST.get("user_type")

        # Check if email or phone number already exists
        if mainuser.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            print("Email is already registered.")
            msg="enter otp is 111001"
            # send_sms(phone_number,msg)
            print("\n", msg)
            return redirect("register_user")
        print("222222222")
        
        
        if mainuser.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number is already registered.")
            print("Phone number is already registered.")
            return redirect("register_user")
        
        if password != cpassword:
            messages.error(request,"password is not matched..")
            print("password not mtched..")
            return redirect("register_user")
        print("3333333333")
        # Create User
        hashed_password = encode_password(password) #make_password(password)  # Hash password
           # Create a new User instance
        user = User.objects.create_user(username=full_name, email=email, password=password)
        user.first_name = full_name
        # user.last_name = full_name
        user.is_active = False  # User is inactive until email confirmation
        user.save()
      
        print("444444444444")
        user_u = mainuser.objects.create(
            full_name=full_name,
            email=email,
            password=hashed_password,
            phone_number=phone_number,
            address=address,
            user_type=user_type
        )

        # If user is a donor, create donor record
        if user_type in ["donor", "both"]:
            dob = request.POST.get("dob")
            gender = request.POST.get("gender")
            blood_group = request.POST.get("blood_group")
            country = request.POST.get("country")
            state = request.POST.get("state")
            district = request.POST.get("district")
            mandal = request.POST.get("mandal")
            village = request.POST.get("village")
            house_number = request.POST.get("house_number")
            donation_type = request.POST.get("donation_type")
            
            Donor.objects.create(
                user=user_u,
                dob=dob,
                gender=gender,
                blood_group=blood_group,
                country=country,
                state=state,
                district=district,
                mandal=mandal,
                village=village,
                house_number=house_number,
                donation_type=donation_type,
            )
         # Send confirmation email
        current_site = get_current_site(request)
        mail_subject = 'Activate your account.'
        message = render_to_string('acc_active_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': default_token_generator.make_token(user),
        })
        # send_mail(mail_subject, message, 'settings.EMAIL_HOST_USER', [user_mail])
        email_from = settings.EMAIL_HOST_USER
            # subject = 'Feedback from User'
        html_message = f"""
            {message}
            """
        sendemail = EmailMessage(mail_subject, html_message, email_from, [email])
        sendemail.content_subtype = 'html'  # Set the content type to HTML
        sendemail.send()
        
        messages.success(request, "Registration successful! Please log in.")
        return render(request,'requestdone.html',{'user':user_u})
        print("registration success..!")
        # return redirect("user_login")
    print("errorrr..")
    return render(request, "user_signuppage.html")





def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        print("111111111111111111111111111111111")

    if user is not None and default_token_generator.check_token(user, token):
        print("user=",user)
        user.is_active = True
        user.save()
        user2= mainuser.objects.get(full_name=user)
        if user2:
            user2.is_active=True
            user2.save()
            print("saved.....!!")
        print("debngdfddddddddddddddd")
        return render(request, 'gotologin.html')
        # return HttpResponse('Thank you for your email confirmation. Your account is now active. You can log in.')
    else:
        return HttpResponse('Activation link is invalid!')



def user_login(request):
    return render(request, "user_loginpage.html")



from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from .models import mainuser

# def user_login_operation(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         # print(email)
#         password = request.POST.get('password')
#         # print(password)
#         hash_pass=encode_password(password)
#         # print(hash_pass)

#         try:
#             user = mainuser.objects.get(email=email)
#             # print("try....")
#             if not user:
#                 return render(request, 'user_loginpage.html', {'error': 'Invalid email or password'})
            
#             # print("email..matched...")

#             # Compare passwords (assuming passwords are stored as plaintext)
#             if user.password == hash_pass:  # Use hashed password in production
#                 # print("pass matched..")
#                 request.session['user_id'] = user.user_id 
#                 request.session['user_type']=user.user_type# Store session
#                 return redirect('user_dashboard')  # Redirect to dashboard or home
#             else:
#                 # print(user.password)
#                 # print("pass not matched..")
#                 return render(request, 'user_loginpage.html', {'error': 'Invalid email or password'})

#         except mainuser.DoesNotExist:
#             # print("exception got")
#             return render(request, 'user_loginpage.html', {'error': 'User does not exist'})

#     return render(request, 'user_loginpage.html')



from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from .models import mainuser, CareCoin, ScratchCard
import random

# def user_login_operation(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')
#         hash_pass=encode_password(password)

#         try:
#             user = mainuser.objects.get(email=email)
            
#             # Verify hashed password
#             if user.password == hash_pass: # Assumes password is hashed
#                 # Set session variables
#                 request.session['user_id'] = user.user_id
#                 request.session['user_type'] = user.user_type
#                 request.session['selected_type'] = user.user_type if user.user_type != 'both' else 'donor'
                

#                 # Check for first login and award scratch card for donor/both
#                 if hasattr(user, 'first_login') and user.first_login and user.user_type in ['donor', 'both']:
#                     # Generate scratch card
#                     scratch_card = ScratchCard.objects.create(user=user)
#                     bonus_coins = scratch_card.bonus_coins  # Random 100-200 from model

#                     # Award Care-Coins
#                     CareCoin.objects.create(
#                         donor=user,
#                         transaction_type='earned',
#                         coins=bonus_coins,
#                         donation_type='bonus',
#                         description=f"First login bonus from scratch card (ID: {scratch_card.id})"
#                     )

#                     # Mark first login as complete
#                     user.first_login = False
#                     user.save()

#                     # Set session flags for scratch card display
#                     request.session['show_scratch_card'] = True
#                     request.session['bonus_coins'] = bonus_coins

#                 return redirect('user_dashboard')
#             else:
#                 return render(request, 'user_loginpage.html', {'error': 'Invalid email or password'})

#         except mainuser.DoesNotExist:
#             return render(request, 'user_loginpage.html', {'error': 'User does not exist'})

#     return render(request, 'user_loginpage.html')



from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from .models import mainuser, Donor, CareCoin, ScratchCard
import random

def user_login_operation(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        hash_pass=encode_password(password)

        try:
            user = mainuser.objects.get(email=email)
            # Check if account is active
            if not user.is_active:
                return render(request, 'user_loginpage.html', {'error': 'Account not activated. Please check your email.'})

            # Verify hashed password
            if user.password == hash_pass: # Assumes password is hashed
                # Set session variables
                request.session['user_id'] = user.user_id
                request.session['user_type'] = user.user_type
                request.session['selected_type'] = user.user_type if user.user_type != 'both' else 'donor'

                # Update last_login
                # user.last_login = timezone.now()
                
                # Check for first login and award scratch card for donor/both
                if user.first_login and user.user_type in ['donor', 'both']:
                    # Generate scratch card
                    scratch_card, created = ScratchCard.objects.get_or_create(user=user)
                    if created:  # Only set bonus_coins if newly created
                        scratch_card.bonus_coins = random.randint(100, 200)
                        scratch_card.save()

                    bonus_coins = scratch_card.bonus_coins

                    # Award Care-Coins
                    CareCoin.objects.create(
                        donor=user,
                        transaction_type='earned',
                        coins=bonus_coins,
                        donation_type='bonus',
                        description=f"First login bonus from scratch card (ID: )"
                    )

                    # Mark first login as complete
                    user.first_login = False
                    user.save()

                    # Set session flags for scratch card display
                    request.session['show_scratch_card'] = True
                    request.session['bonus_coins'] = bonus_coins

                user.save()  # Save last_login and first_login updates
                return redirect('user_dashboard')
            else:
                return render(request, 'user_loginpage.html', {'error': 'Invalid email or password'})

        except mainuser.DoesNotExist:
            return render(request, 'user_loginpage.html', {'error': 'User does not exist'})

    return render(request, 'user_loginpage.html')


# # def dashboard(request):
#     if 'user_id' not in request.session:
#         return redirect('user_login')

#     user = mainuser.objects.get(user_id=request.session['user_id'])
#     return render(request, 'user_dashboard.html', {'user': user})


from django.shortcuts import render

# def dashboard(request):
#      if 'user_id' not in request.session:
#          return redirect('user_login')
     
#      user = mainuser.objects.get(user_id=request.session['user_id'])

#     # Fetch user type from the logged-in user
#     # user = request.user  # Assuming the user is authenticated
#      user_type = user.user_type  # Assuming `user_type` is stored in the profile model

#     # Default selection if user type is 'both'
#      selected_type = "Donor" if user_type == "both" else user_type

#     # Store selected type in session to persist selection
#      if request.method == "POST":
#         selected_type = request.POST.get("selected_type", selected_type)
#         request.session["selected_type"] = selected_type
#         return render(request, "user_dashboard.html", {"user_type": user_type, "selected_type": selected_type})



def user_logout(request):
    request.session.flush()
    return redirect('user_login')


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
# from .models import User  # Import the User model

# # @login_required
# def dashboard(request):
#     # Fetch user_id from session
#     user_id = request.session.get("user_id")

#     # Get the user object
#     user = mainuser.objects.get(user_id=user_id) if user_id else None

#     if not user:
#         return redirect("user_login")  # Redirect to login if user not found

#     user_type = user.user_type  # Get user type

#     # Default type selection for "both" users
#     selected_type = request.session.get("selected_type", "Donor" if user_type == "both" else user_type)

#     # Handle switching user type for "both"
#     if request.method == "POST":
#         selected_type = request.POST.get("selected_type", selected_type)
#         request.session["selected_type"] = selected_type  # Store in session

#     context = {
#         "user_id": user_id,
#         "user_type": user_type,
#         "selected_type": selected_type,
#     }
#     return render(request, "user_dashboard.html", context)

from django.shortcuts import render
from .models import Hospital

# def patient_registration(request):
#     hospitals = Hospital.objects.values_list('name', flat=True)  # Fetch hospital names
#     return render(request, 'patient_registration.html', {'hospitals': hospitals})


def patient_request_for_slot(request):
    hospitals = Hospital.objects.values_list('hospital_name', flat=True)  # Fetch hospital names
    return render(request, "patient_registration.html", {'hospitals': hospitals})







from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Patient, Hospital

# def patient_registration(request):
#     if request.method == "POST":
#         print("dnjvlcjbkljblbnkjnd...........")
#         patient_name = request.POST.get("name")
#         patient_age = request.POST.get("age")
#         patient_gender = request.POST.get("gender")
#         patient_address = request.POST.get("address")
#         patient_dob=request.POST.get("date")
#         patient_phone=request.POST.get("phone")
#         patient_alt=request.POST.get("alt_phone")
#         patient_email=request.POST.get("mail")
#         patient_aadhar=request.POST.get("aadhar")
#         patient_aadhar_file=request.POST.get("aadhar_file")
        
        
        
        
#         h_name = request.POST.get("h_name")
#         h_loc = request.POST.get("h_loc")
#         d_name = request.POST.get("d_name")
#         d_con = request.POST.get("d_con")
#         pid = request.POST.get("p_id_in_h")
#         problem = request.POST.get("problem")
#         desc = request.POST.get("Description")
#         Prescription = request.POST.get("Prescription")
#         time = request.POST.get("time")
        
        
        
#         report_name = request.POST.get("report_name")
#         report_file = request.POST.get("report_file")
        
        
        
#         ass_type = request.POST.get("AssistanceTye")
        
#         amt = request.POST.get("amt")
#         bank_name = request.POST.get("bank_name")
#         acc_no = request.POST.get("acc_no")
#         ifsc = request.POST.get("ifsc")
#         accfile = request.POST.get("acc_file")
#         qr = request.POST.get("qr_file")
#         upis = request.POST.get("upis")
        
#         blood_group = request.POST.get("blood_group")
#         qnt = request.POST.get("qnt")
#         b_loc = request.POST.get("location")
        
#         donation_other=request.POST.get("desc")
        
#         isp = request.POST.get("isp")
#         isnotp = request.POST.get("isnotp")
#         isnotp_file=request.POST.get("isnot_file")
        
        

from django.shortcuts import render, redirect
# from .models import Patient, MedicalDetails, MedicalReport, AssistanceRequired, FinancialAid, BloodDonation, OtherResources, Verification

# def patient_registration(request):
#     if request.method == "POST":
#         # Patient information
#         patient_name = request.POST.get("name")
#         patient_age = request.POST.get("age")
#         patient_gender = request.POST.get("gender")
#         patient_address = request.POST.get("address")
#         patient_dob = request.POST.get("date")
#         patient_phone = request.POST.get("phone")
#         patient_alt = request.POST.get("alt_phone")
#         patient_email = request.POST.get("mail")
#         patient_aadhar = request.POST.get("aadhar")
#         patient_aadhar_file = request.FILES.get("aadhar_file")
        
#         patient = Patient.objects.create(
#             user_id=1,
#             hospital_id=1,
#             full_name=patient_name,
#             age=patient_age,
#             gender=patient_gender,
#             address=patient_address,
#             dob=patient_dob,
#             contact_number=patient_phone,
#             alternate_number=patient_alt,
#             email=patient_email,
#             aadhaar_id=patient_aadhar,
#             aadhaar_card=patient_aadhar_file
#         )
        
#         # MedicalDetails information
#         h_name = "bjvkjd"
#         h_loc = request.POST.get("h_loc")
#         d_name = request.POST.get("d_name")
#         d_con = request.POST.get("d_con")
#         pid = request.POST.get("p_id_in_h")
#         problem = request.POST.get("problem")
#         desc = request.POST.get("Description")
#         Prescription = request.FILES.get("Prescription")
#         time = request.POST.get("time")
        
#         medical_details = MedicalDetails.objects.create(
#             patient=patient,
#             hospital_name=h_name,
#             hospital_location=h_loc,
#             doctor_name=d_name,
#             doctor_contact=d_con,
#             patient_id_in_hospital=pid,
#             problem=problem,
#             description=desc,
#             prescription=Prescription,
#             expected_recovery_time=time
#         )
        
#         # MedicalReport information
#         report_name = request.POST.get("report_name")
#         report_file = request.FILES.get("report_file")
        
#         MedicalReport.objects.create(
#             medical_details=medical_details,
#             report_name=report_name,
#             report_file=report_file
#         )
        
#         # AssistanceRequired information
#         ass_type = request.POST.get("AssistanceTye")
        
#         assistance = AssistanceRequired.objects.create(
#             patient=patient,
#             assistance_type=ass_type
#         )
        
#         # FinancialAid information
#         if ass_type == 'Financial Aid':
#             amt = request.POST.get("amt")
#             bank_name = request.POST.get("bank_name")
#             acc_no = request.POST.get("acc_no")
#             ifsc = request.POST.get("ifsc")
#             accfile = request.FILES.get("acc_file")
#             qr = request.FILES.get("qr_file")
#             upis = request.POST.getlist("upis")
            
#             financial_aid = FinancialAid.objects.create(
#                 assistance=assistance,
#                 expected_fund_required=amt,
#                 banck_account_name=bank_name,
#                 bank_account_number=acc_no,
#                 ifsc_code=ifsc,
#                 bank_passbook_image=accfile,
#                 qr_code_image=qr,
#                 upi_ids=upis
#             )
        
#         # BloodDonation information
#         elif ass_type == 'Blood Donation':
#             blood_group = request.POST.get("blood_group")
#             qnt = request.POST.get("qnt")
#             b_loc = request.POST.get("location")
            
#             BloodDonation.objects.create(
#                 assistance=assistance,
#                 required_blood_group=blood_group,
#                 blood_quantity=qnt,
#                 blood_donation_location=b_loc
#             )
        
#         # OtherResources information
#         elif ass_type == 'Other Resources':
#             donation_other = request.POST.get("desc")
            
#             OtherResources.objects.create(
#                 assistance=assistance,
#                 resources_name=donation_other
#             )
        
#         # Verification information
#         isp = request.POST.get("isp")
#         isnotp = request.POST.get("isnotp")
#         isnotp_file = request.FILES.get("isnot_file")
        
#         Verification.objects.create(
#             patient=patient,
#             registered_by_patient=bool(isp),
#             registered_by_other=bool(isnotp),
#             relative_or_other_id=isnotp_file
#         )
        
#         return redirect('dashboard')  # Redirect to a success page after registration
    
#     return render(request, 'patient_registration.html')  # Render the registration form template

#         # Create and save patient
     
        
         
#         # print(patient_aadhar,patient_age,patient_alt,patient_gender)
#         # return render(request, "user_loginpage.html")
#         # hospital_name = request.POST.get("hospital")
#         # other_hospital_name = request.POST.get("other_hospital")
#         # medical_records = request.FILES.get("medical_records")
        
#         # Check if the user selected "Other" and provided a hospital name
#         # if hospital_id == "other" and other_hospital_name:
#         #     hospital = Hospital.objects.create(name=other_hospital_name)
#         # else:
#         #     hospital = Hospital.objects.get(id=hospital_id)
        
#         # Create and save patient
#         # patient = Patient.objects.create(
#         #     name=patient_name,
#         #     age=patient_age,
#         #     gender=patient_gender,
#         #     address=patient_address,
#         #     hospital=hospital,
#         #     medical_records=medical_records
#         # )
        
#     #     return JsonResponse({"message": "Patient registered successfully!"})
    
#     # hospitals = Hospital.objects.all()
#     # return render(request, "patient_registration.html", {"hospitals": hospitals})

# from django.shortcuts import render, redirect
# from django.core.exceptions import ValidationError
# from django.db import transaction
# from .models import Patient, MedicalReport, AssistanceRequired, FinancialAid, BloodDonation, OtherResources, Verification

# def patient_registration(request):
#     if request.method == 'POST':
#         try:
#                 # Section 1: Patient Details
#                 patient = Patient.objects.create(
#                     full_name=request.POST.get('full_name'),
#                     age=request.POST.get('age'),
#                     dob=request.POST.get('dob'),
#                     gender=request.POST.get('gender'),
#                     contact_number=request.POST.get('contact_number'),
#                     alternate_number=request.POST.get('alternate_number'),
#                     email=request.POST.get('email'),
#                     address=request.POST.get('address'),
#                     aadhaar_id=request.POST.get('aadhaar_id'),
#                     aadhaar_card=request.FILES.get('aadhaar_card')
#                 )
#                 # patient.full_clean()  # Validate model fields
#                 # patient.save()

#                 # Section 2: Medical Details
#                 hospital_name = request.POST.get('hospital_name')
#                 if hospital_name == 'Other':
#                     hospital_name = request.POST.get('other_hospital')

#                 medical_details = MedicalDetails(
#                     patient=patient,
#                     hospital_name=hospital_name,
#                     hospital_location=request.POST.get('hospital_location'),
#                     doctor_name=request.POST.get('doctor_name'),
#                     doctor_contact=request.POST.get('doctor_contact'),
#                     patient_id_in_hospital=request.POST.get('patient_id_in_hospital'),
#                     problem=request.POST.get('problem'),
#                     description=request.POST.get('description'),
#                     prescription=request.FILES.get('prescription'),
#                     expected_recovery_time=request.POST.get('expected_recovery_time')
#                 )
#                 # medical_details.full_clean()
#                 medical_details.save()

#                 # Section 3: Medical Reports
#                 for report_name, report_file in zip(
#                     request.POST.getlist('report_name[]'),
#                     request.FILES.getlist('report_file[]')
#                 ):
#                     medical_report = MedicalReport(
#                         medical_details=medical_details,
#                         report_name=report_name,
#                         report_file=report_file
#                     )
#                     medical_report.full_clean()
#                     medical_report.save()

#                 # Section 4: Assistance Required
#                 assistance = AssistanceRequired(
#                     patient=patient,
#                     assistance_type=request.POST.get('assistance_type')
#                 )
#                 # assistance.full_clean()
#                 assistance.save()

#                 # Handle specific assistance types
#                 if assistance.assistance_type == 'Financial Aid':
#                     financial_aid = FinancialAid(
#                         assistance=assistance,
#                         expected_fund_required=request.POST.get('amt'),
#                         banck_account_name=request.POST.get('bank_name'),
#                         bank_account_holder_name=request.POST.get('account_name'),
#                         bank_account_number=request.POST.get('account_no'),
#                         ifsc_code=request.POST.get('ifsc'),
#                         bank_passbook_image=request.FILES.get('acc_file'),
#                         qr_code_image=request.FILES.get('qr_file'),
#                         upi_ids=request.POST.getlist('upis[]')
#                     )
#                     # financial_aid.full_clean()
#                     financial_aid.save()

#                 elif assistance.assistance_type == 'Blood Donation':
#                     blood_donation = BloodDonation(
#                         assistance=assistance,
#                         required_blood_group=request.POST.get('blood_group'),
#                         blood_quantity=request.POST.get('qnt'),
#                         blood_donation_location=request.POST.get('location')
#                     )
#                     # blood_donation.full_clean()
#                     blood_donation.save()

#                 elif assistance.assistance_type == 'Other Resources':
#                     other_resources = OtherResources(
#                         assistance=assistance,
#                         resources_name=request.POST.get('desc')
#                     )
#                     # other_resources.full_clean()
#                     other_resources.save()

#                 # Section 5: Verification
#                 verification = Verification(
#                     patient=patient,
#                     registered_by_patient=request.POST.get('registered_by_patient') == 'on',
#                     phone_number=request.POST.get('verifier_phone'),
#                     aadhar_card=request.FILES.get('verifier_aadhaar')
#                 )
#                 # verification.full_clean()
#                 verification.save()

#                 return redirect('success_page')

#         except ValidationError as e:
#             # Handle validation errors
#             return render(request, 'registration.html', {'error': e.message_dict})
#         except Exception as e:
#             # Handle other exceptions
#             return render(request, 'registration.html', {'error': str(e)})

#     return render(request, 'patient_registration.html')











# from django.shortcuts import render
# from django.contrib.auth.decorators import login_required
# from django.core.exceptions import ValidationError
# from django.utils import timezone
# from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus
# import json

# @login_required
# def patient_registration(request):
#     if request.method == 'POST':
#         user_id = request.session.get("user_id")

#         try:
#             # Personal Details
#             full_name = request.POST.get('full_name')
#             age = request.POST.get('age')
#             dob = request.POST.get('dob')
#             gender = request.POST.get('gender')
#             contact_number = request.POST.get('contact_number')
#             alternate_number = request.POST.get('alternate_number', '')
#             email = request.POST.get('email', '')
#             address = request.POST.get('address')
#             aadhaar_id = request.POST.get('aadhaar_id')
#             aadhaar_card = request.FILES.get('aadhaar_card')

#             # Hospital & Doctor Details
#             hospital_name = request.POST.get('hospital_name')
#             other_hospital = request.POST.get('other_hospital', '') if hospital_name == 'Other' else ''
#             hospital_location = request.POST.get('hospital_location')
#             doctor_name = request.POST.get('doctor_name')
#             doctor_contact = request.POST.get('doctor_contact')
#             patient_id_in_hospital = request.POST.get('patient_id_in_hospital', '')
#             problem = request.POST.get('problem')
#             description = request.POST.get('description')
#             prescription = request.FILES.get('prescription')
#             expected_recovery_time = request.POST.get('expected_recovery_time')

#             # Medical Reports
#             report_names = request.POST.getlist('report_name[]')
#             report_files = request.FILES.getlist('report_file[]')

#             # Assistance Required
#             assistance_type = request.POST.get('assistance_type')
#             assistance_data = {}
#             if assistance_type == 'Financial Aid':
#                 assistance_data = {
#                     'amount_required': request.POST.get('amt'),
#                     'bank_name': request.POST.get('bank_name'),
#                     'account_holder_name': request.POST.get('account_name'),
#                     'account_number': request.POST.get('account_no'),
#                     'ifsc_code': request.POST.get('ifsc'),
#                     'bank_details_file': request.FILES.get('acc_file'),
#                     'qr_code_file': request.FILES.get('qr_file'),
#                     'upi_ids': request.POST.get('upis')
#                 }
#             elif assistance_type == 'Blood Donation':
#                 assistance_data = {
#                     'blood_type': request.POST.get('blood_group'),
#                     'quantity': request.POST.get('qnt'),
#                     'location_to_reach': request.POST.get('location')
#                 }
#             elif assistance_type == 'Other Resources':
#                 assistance_data = {'description': request.POST.get('desc')}

#             # Verification
#             registered_by_patient = 'registered_by_patient' in request.POST
#             verifier_phone = request.POST.get('verifier_phone') if not registered_by_patient else None
#             verifier_aadhaar = request.FILES.get('verifier_aadhaar') if not registered_by_patient else None
#             verifier_email = request.POST.get('verifier_email') if not registered_by_patient else None

#             # Validate required fields
#             required_fields = [
#                 full_name, age, dob, gender, contact_number, address, aadhaar_id, aadhaar_card,
#                 hospital_name, hospital_location, doctor_name, doctor_contact, problem, description, 
#                 prescription, expected_recovery_time, report_names, report_files, assistance_type
#             ]
#             if not all(required_fields) or len(report_names) != len(report_files):
#                 return JsonResponse({'error': 'All required fields must be filled.'}, status=400)

#             # Check unique fields
#             if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
#                 return JsonResponse({'error': 'Aadhaar ID already exists.'}, status=400)
#             if email and Patient.objects.filter(email=email).exists():
#                 return JsonResponse({'error': 'Email already exists.'}, status=400)
#             if patient_id_in_hospital and HospitalDetails.objects.filter(patient_id_in_hospital=patient_id_in_hospital).exists():
#                 return JsonResponse({'error': 'Patient ID in hospital already exists.'}, status=400)

#             # Save Patient
#             patient = Patient(
#                 user=user_id,
#                 full_name=full_name,
#                 age=age,
#                 dob=dob,
#                 gender=gender,
#                 contact_number=contact_number,
#                 alternate_number=alternate_number,
#                 email=email,
#                 address=address,
#                 aadhaar_id=aadhaar_id
#             )
#             if aadhaar_card:
#                 patient.aadhaar_card.save(aadhaar_card.name, aadhaar_card)
#             patient.save()

#             # Save HospitalDetails
#             hospital_details = HospitalDetails(
#                 patient=patient,
#                 hospital_name=other_hospital if hospital_name == 'Other' else hospital_name,
#                 hospital_location=hospital_location,
#                 doctor_name=doctor_name,
#                 doctor_contact=doctor_contact,
#                 patient_id_in_hospital=patient_id_in_hospital,
#                 medical_problem=problem,
#                 problem_description=description,
#                 expected_recovery_time=expected_recovery_time
#             )
#             if prescription:
#                 hospital_details.prescription.save(prescription.name, prescription)
#             hospital_details.save()

#             # Save MedicalReports
#             for name, file in zip(report_names, report_files):
#                 medical_report = MedicalReport(
#                     hospital_details=hospital_details,
#                     report_name=name
#                 )
#                 medical_report.report_file.save(file.name, file)
#                 medical_report.save()

#             # Save AssistanceRequired
#             assistance_required = AssistanceRequired(
#                 hospital_details=hospital_details,
#                 assistance_type=assistance_type,
#                 **{k: v for k, v in assistance_data.items() if v is not None and v != ''}
#             )
#             if 'bank_details_file' in assistance_data and assistance_data['bank_details_file']:
#                 assistance_required.bank_details_file.save(assistance_data['bank_details_file'].name, assistance_data['bank_details_file'])
#             if 'qr_code_file' in assistance_data and assistance_data['qr_code_file']:
#                 assistance_required.qr_code_file.save(assistance_data['qr_code_file'].name, assistance_data['qr_code_file'])
#             assistance_required.save()

#             # Save Verification
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient,
#                 verifier_phone=verifier_phone,
#                 verifier_email=verifier_email
#             )
#             if verifier_aadhaar:
#                 verification.verifier_aadhaar.save(verifier_aadhaar.name, verifier_aadhaar)
#             verification.save()

#             # Save Donation Status
#             donation_status, created = PatientDonationStatus.objects.get_or_create(patient=patient)
#             donation_status.is_active = True
#             donation_status.start_time = timezone.now()
#             donation_status.set_end_time(expected_recovery_time)
#             donation_status.save()

#             return JsonResponse({
#                 'success': True,
#                 'message': 'Patient registered successfully.',
#                 'redirect': '/patient-success/'
#             })

#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=400)

#     else:  # GET request for initial load
#         return render(request, 'patient_registration.html')


from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus
import os

# # @csrf_exempt
# def patient_registration(request):
#     print("fsdg")
#     if request.method == 'POST':
#         try:
#             user_id = request.session.get("user_id")

#             # Check for unique email
#             email = request.POST.get('email', '').strip()
#             if email and Patient.objects.filter(email=email).exists():
#                 return JsonResponse({'success': False, 'error': 'This email is already registered'})

#             # Check for unique Aadhaar ID
#             aadhaar_id = request.POST.get('aadhaar_id')
#             if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
#                 return JsonResponse({'success': False, 'error': 'This Aadhaar ID is already registered'})

#             # Patient Details
#             patient = Patient(
#                 user_id=user_id,  # Assuming user is authenticated
#                 full_name=request.POST['full_name'],
#                 age=request.POST['age'],
#                 dob=request.POST['dob'],
#                 gender=request.POST['gender'],
#                 contact_number=request.POST['contact_number'],
#                 alternate_number=request.POST.get('alternate_number', ''),
#                 email=email,
#                 address=request.POST['address'],
#                 aadhaar_id=aadhaar_id,
#                 aadhaar_card=request.FILES['aadhaar_card']
#             )
#             patient.save()

#             # Hospital Details
#             hospital_name = request.POST['hospital_name']
#             if hospital_name == 'Other':
#                 hospital_name = request.POST.get('other_hospital', '')

#             hospital = HospitalDetails(
#                 patient=patient,
#                 hospital_name=hospital_name,
#                 hospital_location=request.POST['hospital_location'],
#                 doctor_name=request.POST['doctor_name'],
#                 doctor_contact=request.POST['doctor_contact'],
#                 patient_id_in_hospital=request.POST.get('patient_id_in_hospital', ''),
#                 medical_problem=request.POST['problem'],
#                 problem_description=request.POST['description'],
#                 prescription=request.FILES['prescription'],
#                 expected_recovery_time=request.POST['expected_recovery_time']
#             )
#             hospital.save()

#             # Medical Reports
#             report_names = request.POST.getlist('report_name[]')
#             report_files = request.FILES.getlist('report_file[]')
#             for name, file in zip(report_names, report_files):
#                 MedicalReport.objects.create(
#                     hospital_details=hospital,
#                     report_name=name,
#                     report_file=file
#                 )

#             # Assistance Required
#             assistance_type = request.POST['assistance_type']
#             assistance = AssistanceRequired(
#                 hospital_details=hospital,
#                 assistance_type=assistance_type
#             )

#             if assistance_type == 'Financial Aid':
#                 assistance.amount_required = request.POST['amt']
#                 assistance.bank_name = request.POST['bank_name']
#                 assistance.account_holder_name = request.POST['account_name']
#                 assistance.account_number = request.POST['account_no']
#                 assistance.ifsc_code = request.POST['ifsc']
#                 assistance.bank_details_file = request.FILES.get('acc_file')
#                 assistance.qr_code_file = request.FILES.get('qr_file')
#                 assistance.upi_ids = request.POST['upis']
#             elif assistance_type == 'Blood Donation':
#                 assistance.blood_type = request.POST['blood_group']
#                 assistance.quantity = request.POST['qnt']
#                 assistance.location_to_reach = request.POST['location']
#             elif assistance_type == 'Other Resources':
#                 assistance.description = request.POST['desc']
#             assistance.save()

#             # Verification
#             registered_by_patient = request.POST.get('registered_by_patient') == 'on'
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient
#             )
#             if not registered_by_patient:
#                 verification.verifier_phone = request.POST['verifier_phone']
#                 verification.verifier_aadhaar = request.FILES['verifier_aadhaar']
#                 verification.verifier_email = request.POST['verifier_email']
#             verification.save()

#             # Patient Donation Status
#             donation_status = PatientDonationStatus(
#                 patient=patient,
#                 is_active=True
#             )
#             donation_status.save()
#             donation_status.set_end_time(int(request.POST['expected_recovery_time']))

#             return JsonResponse({
#                 'success': True,
#                 'message': 'Patient registered successfully',
#                 'redirect': '/success_page/'  # Adjust this URL
#             })

#         except ValidationError as e:
#             return JsonResponse({'success': False, 'error': str(e)})
#         except Exception as e:
#             return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})

#     return render(request, 'patient_registration.html')
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus
import os

# # @csrf_exempt
# def patient_registration(request):
#     print("gvjlhsfkvdbjcjsm")
#     if request.method == 'POST':
#         try:
#             # Check for unique email
#             email = request.POST.get('email', '').strip()
#             if email and Patient.objects.filter(email=email).exists():
#                 return JsonResponse({'success': False, 'error': 'This email is already registered'})

#             # Check for unique Aadhaar ID
#             aadhaar_id = request.POST.get('aadhaar_id')
#             if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
#                 return JsonResponse({'success': False, 'error': 'This Aadhaar ID is already registered'})

#             # Check for unique patient_id_in_hospital if provided
#             patient_id_in_hospital = request.POST.get('patient_id_in_hospital', '').strip()
#             if patient_id_in_hospital and HospitalDetails.objects.filter(patient_id_in_hospital=patient_id_in_hospital).exists():
#                 return JsonResponse({'success': False, 'error': 'This patient ID in hospital is already registered'})

#             # Patient Details
#             patient = Patient(
#                 user=request.user,  # Assuming user is authenticated
#                 full_name=request.POST['full_name'],
#                 age=request.POST['age'],
#                 dob=request.POST['dob'],
#                 gender=request.POST['gender'],
#                 contact_number=request.POST['contact_number'],
#                 alternate_number=request.POST.get('alternate_number', ''),
#                 email=email,
#                 address=request.POST['address'],
#                 aadhaar_id=aadhaar_id,
#                 aadhaar_card=request.FILES['aadhaar_card']
#             )
#             patient.save()

#             # Hospital Details
#             hospital_name = request.POST['hospital_name']
#             if hospital_name == 'Other':
#                 hospital_name = request.POST.get('other_hospital', '')

#             hospital = HospitalDetails(
#                 patient=patient,
#                 hospital_name=hospital_name,
#                 hospital_location=request.POST['hospital_location'],
#                 doctor_name=request.POST['doctor_name'],
#                 doctor_contact=request.POST['doctor_contact'],
#                 patient_id_in_hospital=patient_id_in_hospital,
#                 medical_problem=request.POST['problem'],
#                 problem_description=request.POST['description'],
#                 prescription=request.FILES['prescription'],
#                 expected_recovery_time=request.POST['expected_recovery_time']
#             )
#             hospital.save()

#             # Medical Reports (Multiple)
#             report_names = request.POST.getlist('report_name[]')
#             report_files = request.FILES.getlist('report_file[]')
#             if len(report_names) != len(report_files):
#                 return JsonResponse({'success': False, 'error': 'Number of report names and files must match'})
#             for name, file in zip(report_names, report_files):
#                 MedicalReport.objects.create(
#                     hospital_details=hospital,
#                     report_name=name,
#                     report_file=file
#                 )

#             # Assistance Required
#             assistance_type = request.POST['assistance_type']
#             assistance = AssistanceRequired(
#                 hospital_details=hospital,
#                 assistance_type=assistance_type
#             )

#             if assistance_type == 'Financial Aid':
#                 assistance.amount_required = request.POST['amt']
#                 assistance.bank_name = request.POST['bank_name']
#                 assistance.account_holder_name = request.POST['account_name']
#                 assistance.account_number = request.POST['account_no']
#                 assistance.ifsc_code = request.POST['ifsc']
#                 assistance.phone_number = request.POST['phone_number']  # New field
#                 assistance.bank_details_file = request.FILES.get('acc_file')
#                 assistance.qr_code_file = request.FILES.get('qr_file')
#                 # Handle multiple UPI IDs
#                 upi_ids = request.POST.getlist('upis[]')
#                 if not upi_ids:
#                     return JsonResponse({'success': False, 'error': 'At least one UPI ID is required for Financial Aid'})
#                 assistance.upi_ids = ','.join(upi_ids)  # Store as comma-separated string
#             elif assistance_type == 'Blood Donation':
#                 assistance.blood_type = request.POST['blood_group']
#                 assistance.quantity = request.POST['qnt']
#                 assistance.location_to_reach = request.POST['location']
#             elif assistance_type == 'Other Resources':
#                 assistance.description = request.POST['desc']
#             assistance.save()

#             # Verification
#             registered_by_patient = request.POST.get('registered_by_patient') == 'on'
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient
#             )
#             if not registered_by_patient:
#                 verification.verifier_phone = request.POST['verifier_phone']
#                 verification.verifier_aadhaar = request.FILES['verifier_aadhaar']
#                 verification.verifier_email = request.POST['verifier_email']
#             verification.save()

#             # Patient Donation Status
#             donation_status = PatientDonationStatus(
#                 patient=patient,
#                 is_active=True
#             )
#             donation_status.save()
#             donation_status.set_end_time(int(request.POST['expected_recovery_time']))

#             return JsonResponse({
#                 'success': True,
#                 'message': 'Patient registered successfully',
#                 'redirect': '/success_page/'  # Adjust this URL
#             })

#         except ValidationError as e:
#             return JsonResponse({'success': False, 'error': str(e)})
#         except KeyError as e:
#             return JsonResponse({'success': False, 'error': f'Missing required field: {str(e)}'})
#         except Exception as e:
#             return JsonResponse({'success': False, 'error': f'An error occurred: {str(e)}'})

#     return render(request, 'patient_registration.html')



from django.shortcuts import render
from django.core.exceptions import ValidationError
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus

# def patient_registration(request):
#     user_id = request.session.get("user_id")
#     print("gvjlhsfkvdbjcjsm===", user_id)
#     if request.method == 'POST':
#         try:
#             # Check for unique email
#             email = request.POST.get('email', '').strip()
#             if email and Patient.objects.filter(email=email).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This email is already registered'})
#             print("222222222")
#             # Check for unique Aadhaar ID
#             aadhaar_id = request.POST.get('aadhaar_id')
#             if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This Aadhaar ID is already registered'})
#             print("33333")
#             # Check for unique patient_id_in_hospital if provided
#             patient_id_in_hospital = request.POST.get('patient_id_in_hospital', '').strip()
#             if patient_id_in_hospital and HospitalDetails.objects.filter(patient_id_in_hospital=patient_id_in_hospital).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This patient ID in hospital is already registered'})
#             print("444444")
#             # Patient Details
#             patient = Patient(
#                 user_id=user_id,  # Assuming user is authenticated
#                 full_name=request.POST['full_name'],
#                 age=request.POST['age'],
#                 dob=request.POST['dob'],
#                 gender=request.POST['gender'],
#                 contact_number=request.POST['contact_number'],
#                 alternate_number=request.POST.get('alternate_number', ''),
#                 email=email,
#                 address=request.POST['address'],
#                 aadhaar_id=aadhaar_id,
#                 aadhaar_card=request.FILES['aadhaar_card']
#             )
#             patient.save()
#             print("5555555")
#             # Hospital Details
#             hospital_name = request.POST['hospital_name']
#             if hospital_name == 'Other':
#                 hospital_name = request.POST.get('other_hospital', '')

#             hospital = HospitalDetails(
#                 patient=patient,
#                 hospital_name=hospital_name,
#                 hospital_location=request.POST['hospital_location'],
#                 doctor_name=request.POST['doctor_name'],
#                 doctor_contact=request.POST['doctor_contact'],
#                 patient_id_in_hospital=patient_id_in_hospital,
#                 medical_problem=request.POST['problem'],
#                 problem_description=request.POST['description'],
#                 prescription=request.FILES['prescription'],
#                 expected_recovery_time=request.POST['expected_recovery_time']
#             )
#             hospital.save()

#             # Medical Reports (Multiple)
#             report_names = request.POST.getlist('report_name[]')
#             report_files = request.FILES.getlist('report_file[]')
#             if len(report_names) != len(report_files):
#                 return render(request, 'patient_registration.html', {'error': 'Number of report names and files must match'})
#             for name, file in zip(report_names, report_files):
#                 MedicalReport.objects.create(
#                     hospital_details=hospital,
#                     report_name=name,
#                     report_file=file
#                 )

#             # Assistance Required
#             assistance_type = request.POST['assistance_type']
#             assistance = AssistanceRequired(
#                 hospital_details=hospital,
#                 assistance_type=assistance_type
#             )

#             if assistance_type == 'Financial Aid':
#                 assistance.amount_required = request.POST['amt']
#                 assistance.bank_name = request.POST['bank_name']
#                 assistance.account_holder_name = request.POST['account_name']
#                 assistance.account_number = request.POST['account_no']
#                 assistance.ifsc_code = request.POST['ifsc']
#                 assistance.phone_number = request.POST['phone_number']  # New field
#                 assistance.bank_details_file = request.FILES.get('acc_file')
#                 assistance.qr_code_file = request.FILES.get('qr_file')
#                 # Handle multiple UPI IDs
#                 upi_ids = request.POST.getlist('upis[]')
#                 if not upi_ids:
#                     return render(request, 'patient_registration.html', {'error': 'At least one UPI ID is required for Financial Aid'})
#                 assistance.upi_ids = ','.join(upi_ids)  # Store as comma-separated string
#             elif assistance_type == 'Blood Donation':
#                 assistance.blood_type = request.POST['blood_group']
#                 assistance.quantity = request.POST['qnt']
#                 assistance.location_to_reach = request.POST['location']
#             elif assistance_type == 'Other Resources':
#                 assistance.description = request.POST['desc']
#             assistance.save()

#             # Verification
#             registered_by_patient = request.POST.get('registered_by_patient') == 'on'
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient
#             )
#             if not registered_by_patient:
#                 verification.verifier_phone = request.POST['verifier_phone']
#                 verification.verifier_aadhaar = request.FILES['verifier_aadhaar']
#                 verification.verifier_email = request.POST['verifier_email']
#             verification.save()

#             # Patient Donation Status
#             donation_status = PatientDonationStatus(
#                 patient=patient,
#                 is_active=True
#             )
#             donation_status.save()
#             donation_status.set_end_time(int(request.POST['expected_recovery_time']))
            
            
#             context = {
#                 'message': 'Patient registered successfully',
#                 'patient': patient,
#                 'hospital': hospital,
#                 'medical_reports': medical_reports,
#                 'assistance': assistance,
#                 'verification': verification,
#                 'donation_status': donation_status,
#             }

#             return render(request, 'success_page.html', context)

#             # On success, render a success page
#             # return render(request, 'success_page.html', {'message': 'Patient registered successfully'})

#         except ValidationError as e:
#             return render(request, 'patient_registration.html', {'error': str(e)})
#         except KeyError as e:
#             return render(request, 'patient_registration.html', {'error': f'Missing required field: {str(e)}'})
#         except Exception as e:
#             return render(request, 'patient_registration.html', {'error': f'An error occurred: {str(e)}'})

#     return render(request, 'patient_registration.html')
# utils/ai_verification.py


from django.shortcuts import render
from django.core.exceptions import ValidationError
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus

# def patient_registration(request):
#     user_id = request.session.get("user_id")
#     print("gvjlhsfkvdbjcjsm")
#     if request.method == 'POST':
#         try:
#             # Check for unique email
#             email = request.POST.get('email', '').strip()
#             if email and Patient.objects.filter(email=email).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This email is already registered'})

#             # Check for unique Aadhaar ID
#             aadhaar_id = request.POST.get('aadhaar_id')
#             if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This Aadhaar ID is already registered'})

#             # Check for unique patient_id_in_hospital if provided
#             patient_id_in_hospital = request.POST.get('patient_id_in_hospital', '').strip()
#             if patient_id_in_hospital and HospitalDetails.objects.filter(patient_id_in_hospital=patient_id_in_hospital).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This patient ID in hospital is already registered'})

#             # Patient Details
#             patient = Patient(
#                 user_id=user_id, # Assuming user is authenticated
#                 full_name=request.POST['full_name'],
#                 age=request.POST['age'],
#                 dob=request.POST['dob'],
#                 gender=request.POST['gender'],
#                 contact_number=request.POST['contact_number'],
#                 alternate_number=request.POST.get('alternate_number', ''),
#                 email=email,
#                 address=request.POST['address'],
#                 aadhaar_id=aadhaar_id,
#                 aadhaar_card=request.FILES['aadhaar_card']
#             )
#             patient.save()

#             # Hospital Details
#             hospital_name = request.POST['hospital_name']
#             if hospital_name == 'Other':
#                 hospital_name = request.POST.get('other_hospital', '')

#             hospital = HospitalDetails(
#                 patient=patient,
#                 hospital_name=hospital_name,
#                 hospital_location=request.POST['hospital_location'],
#                 doctor_name=request.POST['doctor_name'],
#                 doctor_contact=request.POST['doctor_contact'],
#                 patient_id_in_hospital=patient_id_in_hospital,
#                 medical_problem=request.POST['problem'],
#                 problem_description=request.POST['description'],
#                 prescription=request.FILES['prescription'],
#                 expected_recovery_time=request.POST['expected_recovery_time']
#             )
#             hospital.save()

#             # Medical Reports (Multiple)
#             report_names = request.POST.getlist('report_name[]')
#             report_files = request.FILES.getlist('report_file[]')
#             if len(report_names) != len(report_files):
#                 return render(request, 'patient_registration.html', {'error': 'Number of report names and files must match'})
#             medical_reports = []
#             for name, file in zip(report_names, report_files):
#                 report = MedicalReport(
#                     hospital_details=hospital,
#                     report_name=name,
#                     report_file=file
#                 )
#                 report.save()
#                 medical_reports.append(report)

#             # Assistance Required
#             assistance_type = request.POST['assistance_type']
#             assistance = AssistanceRequired(
#                 hospital_details=hospital,
#                 assistance_type=assistance_type
#             )

#             if assistance_type == 'Financial Aid':
#                 assistance.amount_required = request.POST['amt']
#                 assistance.bank_name = request.POST['bank_name']
#                 assistance.account_holder_name = request.POST['account_name']
#                 assistance.account_number = request.POST['account_no']
#                 assistance.ifsc_code = request.POST['ifsc']
#                 assistance.phone_number = request.POST['phone_number']  # New field
#                 assistance.bank_details_file = request.FILES.get('acc_file')
#                 assistance.qr_code_file = request.FILES.get('qr_file')
#                 upi_ids = request.POST.getlist('upis[]')
#                 if not upi_ids:
#                     return render(request, 'patient_registration.html', {'error': 'At least one UPI ID is required for Financial Aid'})
#                 assistance.upi_ids = ','.join(upi_ids)
#             elif assistance_type == 'Blood Donation':
#                 assistance.blood_type = request.POST['blood_group']
#                 assistance.quantity = request.POST['qnt']
#                 assistance.location_to_reach = request.POST['location']
#             elif assistance_type == 'Other Resources':
#                 assistance.description = request.POST['desc']
#             assistance.save()

#             # Verification
#             registered_by_patient = request.POST.get('registered_by_patient') == 'on'
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient
#             )
#             if not registered_by_patient:
#                 verification.verifier_phone = request.POST['verifier_phone']
#                 verification.verifier_aadhaar = request.FILES['verifier_aadhaar']
#                 verification.verifier_email = request.POST['verifier_email']
#             verification.save()

#             # Patient Donation Status
#             donation_status = PatientDonationStatus(
#                 patient=patient,
#                 is_active=True
#             )
#             donation_status.save()
#             donation_status.set_end_time(int(request.POST['expected_recovery_time']))

#             # Prepare context for success page
#             context = {
#                 'message': 'Patient registered successfully',
#                 'patient': patient,
#                 'hospital': hospital,
#                 'medical_reports': medical_reports,
#                 'assistance': assistance,
#                 'verification': verification,
#                 'donation_status': donation_status,
#             }

#             return render(request, 'success_page.html', context)

#         except ValidationError as e:
#             return render(request, 'patient_registration.html', {'error': str(e)})
#         except KeyError as e:
#             return render(request, 'patient_registration.html', {'error': f'Missing required field: {str(e)}'})
#         except Exception as e:
#             return render(request, 'patient_registration.html', {'error': f'An error occurred: {str(e)}'})

#     return render(request, 'patient_registration.html')


from django.shortcuts import render
from django.core.exceptions import ValidationError
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus
# from .utils.ai_verification import verify_document, verify_patient_data  
import os

# def patient_registration(request):
#     if request.method == 'POST':
#         try:
#             # Check for unique email
#             email = request.POST.get('email', '').strip()
#             if email and Patient.objects.filter(email=email).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This email is already registered'})

#             # Check for unique Aadhaar ID
#             aadhaar_id = request.POST.get('aadhaar_id')
#             if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This Aadhaar ID is already registered'})

#             # Check for unique patient_id_in_hospital if provided
#             patient_id_in_hospital = request.POST.get('patient_id_in_hospital', '').strip()
#             if patient_id_in_hospital and HospitalDetails.objects.filter(patient_id_in_hospital=patient_id_in_hospital).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This patient ID in hospital is already registered'})

#             # Patient Details
#             patient = Patient(
#                 user=request.user,
#                 full_name=request.POST['full_name'],
#                 age=request.POST['age'],
#                 dob=request.POST['dob'],
#                 gender=request.POST['gender'],
#                 contact_number=request.POST['contact_number'],
#                 alternate_number=request.POST.get('alternate_number', ''),
#                 email=email,
#                 address=request.POST['address'],
#                 aadhaar_id=aadhaar_id,
#                 aadhaar_card=request.FILES['aadhaar_card']
#             )
#             patient.save()

#             # Hospital Details
#             hospital_name = request.POST['hospital_name']
#             if hospital_name == 'Other':
#                 hospital_name = request.POST.get('other_hospital', '')

#             hospital = HospitalDetails(
#                 patient=patient,
#                 hospital_name=hospital_name,
#                 hospital_location=request.POST['hospital_location'],
#                 doctor_name=request.POST['doctor_name'],
#                 doctor_contact=request.POST['doctor_contact'],
#                 patient_id_in_hospital=patient_id_in_hospital,
#                 medical_problem=request.POST['problem'],
#                 problem_description=request.POST['description'],
#                 prescription=request.FILES['prescription'],
#                 expected_recovery_time=request.POST['expected_recovery_time']
#             )
#             hospital.save()

#             # Medical Reports (Multiple)
#             report_names = request.POST.getlist('report_name[]')
#             report_files = request.FILES.getlist('report_file[]')
#             if len(report_names) != len(report_files):
#                 return render(request, 'patient_registration.html', {'error': 'Number of report names and files must match'})
#             medical_reports = []
#             for name, file in zip(report_names, report_files):
#                 report = MedicalReport(
#                     hospital_details=hospital,
#                     report_name=name,
#                     report_file=file
#                 )
#                 report.save()
#                 medical_reports.append(report)

#             # Assistance Required
#             assistance_type = request.POST['assistance_type']
#             assistance = AssistanceRequired(
#                 hospital_details=hospital,
#                 assistance_type=assistance_type
#             )

#             if assistance_type == 'Financial Aid':
#                 assistance.amount_required = request.POST['amt']
#                 assistance.bank_name = request.POST['bank_name']
#                 assistance.account_holder_name = request.POST['account_name']
#                 assistance.account_number = request.POST['account_no']
#                 assistance.ifsc_code = request.POST['ifsc']
#                 assistance.phone_number = request.POST['phone_number']
#                 assistance.bank_details_file = request.FILES.get('acc_file')
#                 assistance.qr_code_file = request.FILES.get('qr_file')
#                 upi_ids = request.POST.getlist('upis[]')
#                 if not upi_ids:
#                     return render(request, 'patient_registration.html', {'error': 'At least one UPI ID is required for Financial Aid'})
#                 assistance.upi_ids = ','.join(upi_ids)
#             elif assistance_type == 'Blood Donation':
#                 assistance.blood_type = request.POST['blood_group']
#                 assistance.quantity = request.POST['qnt']
#                 assistance.location_to_reach = request.POST['location']
#             elif assistance_type == 'Other Resources':
#                 assistance.description = request.POST['desc']
#             assistance.save()

#             # Verification with AI
#             registered_by_patient = request.POST.get('registered_by_patient') == 'on'
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient
#             )

#             # AI Verification
#             patient_data = {
#                 'aadhaar_id': aadhaar_id,
#                 'age': patient.age,
#                 'dob': patient.dob,
#             }
#             aadhaar_path = default_storage.path(patient.aadhaar_card.name)
#             doc_genuine, doc_confidence, doc_notes = verify_document(aadhaar_path, patient_data)
#             data_genuine, data_confidence, data_notes = verify_patient_data(patient_data)

#             # Combine results (simple rule: both must be genuine)
#             is_genuine = doc_genuine and data_genuine
#             confidence_score = (doc_confidence + data_confidence) / 2  # Average confidence
#             analysis_notes = f"Document: {doc_notes}; Data: {data_notes}"

#             verification.status = 'Verified' if is_genuine else 'Fake'
#             verification.ai_confidence_score = confidence_score
#             verification.ai_analysis_notes = analysis_notes

#             if not registered_by_patient:
#                 verification.verifier_phone = request.POST['verifier_phone']
#                 verification.verifier_aadhaar = request.FILES.get('verifier_aadhaar')
#                 verification.verifier_email = request.POST['verifier_email']
#                 if verification.verifier_aadhaar:
#                     verifier_aadhaar_path = default_storage.path(verification.verifier_aadhaar.name)
#                     verifier_genuine, verifier_confidence, verifier_notes = verify_document(verifier_aadhaar_path, {})
#                     verification.ai_confidence_score = (confidence_score + verifier_confidence) / 2
#                     verification.ai_analysis_notes += f"; Verifier Document: {verifier_notes}"
#                     verification.status = 'Verified' if is_genuine and verifier_genuine else 'Fake'

#             verification.save()

#             # Patient Donation Status
#             donation_status = PatientDonationStatus(
#                 patient=patient,
#                 is_active=True
#             )
#             donation_status.save()
#             donation_status.set_end_time(int(request.POST['expected_recovery_time']))

#             # Context for success page
#             context = {
#                 'message': 'Patient registered successfully',
#                 'patient': patient,
#                 'hospital': hospital,
#                 'medical_reports': medical_reports,
#                 'assistance': assistance,
#                 'verification': verification,
#                 'donation_status': donation_status,
#             }

#             return render(request, 'success_page.html', context)

#         except ValidationError as e:
#             return render(request, 'patient_registration.html', {'error': str(e)})
#         except KeyError as e:
#             return render(request, 'patient_registration.html', {'error': f'Missing required field: {str(e)}'})
#         except Exception as e:
#             return render(request, 'patient_registration.html', {'error': f'An error occurred: {str(e)}'})

#     return render(request, 'patient_registration.html')


from django.shortcuts import render
from django.core.exceptions import ValidationError
from django.core.files.storage import default_storage  # Add this import
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus
# from .utils.ai_verification import verify_document, verify_patient_data # type: ignore
import os
import cv2  # type: ignore # Assuming opencv-python is now installed
from django.shortcuts import render, redirect
from django.core.files.storage import default_storage
from django.urls import reverse
from django.core.exceptions import ValidationError
from .models import mainuser, Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientStatus

def patient_registration(request):
    user_id = request.session.get("user_id")
    if not user_id:
        return redirect('user_loginpage')

    if request.method == 'POST':
        try:
            # email = request.POST.get('email')
            # patient_with_status = Patient.objects.filter(email=email).first()  # Check existing patient
            # print("patient_with_status", patient_with_status)
            # if patient_with_status:
            #     patient_status = PatientDonationStatus.objects.filter(patient_id=patient_with_status.patient_id).first()
            #     print("patient_status====", patient_status)
            #     if patient_status and patient_status.status != 'completed':
            #         return render(request, 'patient_registration.html', {
            #         'error': 'This patient has an active or deactive status and cannot re-register.'
            #     })
            # Check for unique email
            email = request.POST.get('email', '').strip()
            if email and Patient.objects.filter(email=email).exists():
                return render(request, 'patient_registration.html', {'error': 'This email is already registered'})
            # patient_with_status = Patient.objects.filter(email=email).first()  # Check existing patient
            # print("patient_with_status",patient_with_status)
            # if patient_with_status:
            #     patient_status = PatientDonationStatus.objects.filter(patient=patient_with_status).first()
            #     print("patient_status====",patient_status)
            #     if not patient_status and patient_status.status != 'completed':
            #         return render(request, 'patient_registration.html', {
            #         'error': 'This patient has a completed status and cannot re-register.'
            #     })
            

            # Check for unique Aadhaar ID
            aadhaar_id = request.POST.get('aadhaar_id')
            if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
                return render(request, 'patient_registration.html', {'error': 'This Aadhaar ID is already registered'})

            # Check for unique patient_id_in_hospital if provided
            patient_id_in_hospital = request.POST.get('patient_id_in_hospital', '').strip()
            if patient_id_in_hospital and HospitalDetails.objects.filter(patient_id_in_hospital=patient_id_in_hospital).exists():
                return render(request, 'patient_registration.html', {'error': 'This patient ID in hospital is already registered'})

            # Patient Details
            patient = Patient(
                user_id=user_id,
                full_name=request.POST['full_name'],
                age=request.POST['age'],
                dob=request.POST['dob'],
                gender=request.POST['gender'],
                contact_number=request.POST['contact_number'],
                alternate_number=request.POST.get('alternate_number', ''),
                email=email,
                address=request.POST['address'],
                aadhaar_id=aadhaar_id,
                aadhaar_card=request.FILES['aadhaar_card'],
                patient_photo=request.FILES['patient_photo']
            )
            patient.save()

            # Hospital Details
            hospital_name = request.POST['hospital_name']
            if hospital_name == 'Other':
                hospital_name = request.POST.get('other_hospital', '')

            hospital = HospitalDetails(
                patient=patient,
                hospital_name=hospital_name,
                hospital_location=request.POST['hospital_location'],
                doctor_name=request.POST['doctor_name'],
                doctor_contact=request.POST['doctor_contact'],
                patient_id_in_hospital=patient_id_in_hospital,
                medical_problem=request.POST['problem'],
                problem_description=request.POST['description'],
                prescription=request.FILES['prescription'],
                expected_recovery_time=request.POST['expected_recovery_time']
            )
            hospital.save()

            # Medical Reports (Multiple)
            report_names = request.POST.getlist('report_name[]')
            report_files = request.FILES.getlist('report_file[]')
            if len(report_names) != len(report_files):
                return render(request, 'patient_registration.html', {'error': 'Number of report names and files must match'})
            medical_reports = []
            for name, file in zip(report_names, report_files):
                report = MedicalReport(
                    hospital_details=hospital,
                    report_name=name,
                    report_file=file
                )
                report.save()
                medical_reports.append(report)

            # Assistance Required
            assistance_type = request.POST['assistance_type']
            assistance = AssistanceRequired(
                hospital_details=hospital,
                assistance_type=assistance_type
            )

            if assistance_type == 'Financial Aid':
                assistance.amount_required = request.POST['amt']
                assistance.bank_name = request.POST['bank_name']
                assistance.account_holder_name = request.POST['account_name']
                assistance.account_number = request.POST['account_no']
                assistance.ifsc_code = request.POST['ifsc']
                assistance.phone_number = request.POST['phone_number']
                assistance.bank_details_file = request.FILES.get('acc_file')
                assistance.qr_code_file = request.FILES.get('qr_file')
                upi_ids = request.POST.getlist('upis[]')
                if not upi_ids:
                    return render(request, 'patient_registration.html', {'error': 'At least one UPI ID is required for Financial Aid'})
                assistance.upi_ids = ','.join(upi_ids)
            elif assistance_type == 'Blood Donation':
                assistance.blood_type = request.POST['blood_group']
                assistance.quantity = request.POST['qnt']
                assistance.location_to_reach = request.POST['location']
            elif assistance_type == 'Other Resources':
                assistance.description = request.POST['desc']
            assistance.save()

            # Verification with AI
            registered_by_patient = request.POST.get('registered_by_patient') == 'on'
            verification = Verification(
                patient=patient,
                registered_by_patient=registered_by_patient
            )

            # AI Verification for Aadhaar (assuming verify_document is defined elsewhere)
            patient_data = {
                'aadhaar_id': aadhaar_id,
            }
            aadhaar_path = default_storage.path(patient.aadhaar_card.name)
            doc_genuine, doc_confidence, doc_notes = verify_document(aadhaar_path, patient_data)

            # Set verification status based on document check
            verification.status = 'Verified'
            verification.ai_confidence_score = doc_confidence
            verification.ai_analysis_notes = doc_notes

            if not registered_by_patient:
                verification.verifier_phone = request.POST['verifier_phone']
                verification.verifier_aadhaar = request.FILES.get('verifier_aadhaar')
                verification.verifier_email = request.POST['verifier_email']
                if verification.verifier_aadhaar:
                    verifier_aadhaar_path = default_storage.path(verification.verifier_aadhaar.name)
                    verifier_genuine, verifier_confidence, verifier_notes = verify_document(verifier_aadhaar_path, {})
                    verification.ai_confidence_score = (doc_confidence + verifier_confidence) / 2
                    verification.ai_analysis_notes += f"; Verifier Document: {verifier_notes}"
                    verification.status = 'Verified'

            verification.save()

            # Patient Status (replacing PatientDonationStatus)
            patient_status = PatientStatus(
                patient=patient,
                is_active=True
            )
            patient_status.save()
            patient_status.set_end_time(int(request.POST['expected_recovery_time']))

            # Update initial status based on assistance
            patient_status.update_status()

            # Prepare JSON-serializable context for session
            context = {
                'message': 'Patient registered successfully',
                'patient_id': patient.patient_id,
                'patient_name': patient.full_name,
                'hospital_name': hospital.hospital_name,
                'hospital_location': hospital.hospital_location,
                'assistance_type': assistance.assistance_type,
                'verification_status': verification.status,
                'patient_status': patient_status.status,
            }

            # Store context in session as JSON-serializable data
            request.session['context'] = context
            return redirect('user_dashboard')

        except ValidationError as e:
            return render(request, 'patient_registration.html', {'error': str(e)})
        except KeyError as e:
            return render(request, 'patient_registration.html', {'error': f'Missing required field: {str(e)}'})
        except Exception as e:
            return render(request, 'patient_registration.html', {'error': f'An error occurred: {str(e)}'})

    return render(request, 'patient_registration.html')
# def patient_registration(request):
#     user_id = request.session.get("user_id")
#     if request.method == 'POST':
#         try:
#             # Check for unique email
#             email = request.POST.get('email', '').strip()
#             if email and Patient.objects.filter(email=email).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This email is already registered'})

#             # Check for unique Aadhaar ID
#             aadhaar_id = request.POST.get('aadhaar_id')
#             if Patient.objects.filter(aadhaar_id=aadhaar_id).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This Aadhaar ID is already registered'})

#             # Check for unique patient_id_in_hospital if provided
#             patient_id_in_hospital = request.POST.get('patient_id_in_hospital', '').strip()
#             if patient_id_in_hospital and HospitalDetails.objects.filter(patient_id_in_hospital=patient_id_in_hospital).exists():
#                 return render(request, 'patient_registration.html', {'error': 'This patient ID in hospital is already registered'})

#             # Patient Details
#             patient = Patient(
#                 user_id=user_id,
#                 full_name=request.POST['full_name'],
#                 age=request.POST['age'],
#                 dob=request.POST['dob'],
#                 gender=request.POST['gender'],
#                 contact_number=request.POST['contact_number'],
#                 alternate_number=request.POST.get('alternate_number', ''),
#                 email=email,
#                 address=request.POST['address'],
#                 aadhaar_id=aadhaar_id,
#                 aadhaar_card=request.FILES['aadhaar_card'],
#                 patient_photo=request.FILES['patient_photo']
#             )
#             patient.save()

#             # Hospital Details
#             hospital_name = request.POST['hospital_name']
#             if hospital_name == 'Other':
#                 hospital_name = request.POST.get('other_hospital', '')

#             hospital = HospitalDetails(
#                 patient=patient,
#                 hospital_name=hospital_name,
#                 hospital_location=request.POST['hospital_location'],
#                 doctor_name=request.POST['doctor_name'],
#                 doctor_contact=request.POST['doctor_contact'],
#                 patient_id_in_hospital=patient_id_in_hospital,
#                 medical_problem=request.POST['problem'],
#                 problem_description=request.POST['description'],
#                 prescription=request.FILES['prescription'],
#                 expected_recovery_time=request.POST['expected_recovery_time']
#             )
#             hospital.save()

#             # Medical Reports (Multiple)
#             report_names = request.POST.getlist('report_name[]')
#             report_files = request.FILES.getlist('report_file[]')
#             if len(report_names) != len(report_files):
#                 return render(request, 'patient_registration.html', {'error': 'Number of report names and files must match'})
#             medical_reports = []
#             for name, file in zip(report_names, report_files):
#                 report = MedicalReport(
#                     hospital_details=hospital,
#                     report_name=name,
#                     report_file=file
#                 )
#                 report.save()
#                 medical_reports.append(report)

#             # Assistance Required
#             assistance_type = request.POST['assistance_type']
#             assistance = AssistanceRequired(
#                 hospital_details=hospital,
#                 assistance_type=assistance_type
#             )

#             if assistance_type == 'Financial Aid':
#                 assistance.amount_required = request.POST['amt']
#                 assistance.bank_name = request.POST['bank_name']
#                 assistance.account_holder_name = request.POST['account_name']
#                 assistance.account_number = request.POST['account_no']
#                 assistance.ifsc_code = request.POST['ifsc']
#                 assistance.phone_number = request.POST['phone_number']
#                 assistance.bank_details_file = request.FILES.get('acc_file')
#                 assistance.qr_code_file = request.FILES.get('qr_file')
#                 upi_ids = request.POST.getlist('upis[]')
#                 if not upi_ids:
#                     return render(request, 'patient_registration.html', {'error': 'At least one UPI ID is required for Financial Aid'})
#                 assistance.upi_ids = ','.join(upi_ids)
#             elif assistance_type == 'Blood Donation':
#                 assistance.blood_type = request.POST['blood_group']
#                 assistance.quantity = request.POST['qnt']
#                 assistance.location_to_reach = request.POST['location']
#             elif assistance_type == 'Other Resources':
#                 assistance.description = request.POST['desc']
#             assistance.save()

#             # Verification with AI
#             registered_by_patient = request.POST.get('registered_by_patient') == 'on'
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient
#             )
# # views.py (relevant section only)
# # ... [previous imports and code remain unchanged] ...

#             # Verification with AI
#             registered_by_patient = request.POST.get('registered_by_patient') == 'on'
#             verification = Verification(
#                 patient=patient,
#                 registered_by_patient=registered_by_patient
#             )

#             # AI Verification for Aadhaar
#             patient_data = {
#                 'aadhaar_id': aadhaar_id,
#             }
#             aadhaar_path = default_storage.path(patient.aadhaar_card.name)
#             doc_genuine, doc_confidence, doc_notes = verify_document(aadhaar_path, patient_data)

#             # Set verification status based on document check
#             verification.status = 'Verified' if doc_genuine else 'Fake'
#             verification.ai_confidence_score = doc_confidence
#             verification.ai_analysis_notes = doc_notes

#             if not registered_by_patient:
#                 verification.verifier_phone = request.POST['verifier_phone']
#                 verification.verifier_aadhaar = request.FILES.get('verifier_aadhaar')
#                 verification.verifier_email = request.POST['verifier_email']
#                 if verification.verifier_aadhaar:
#                     verifier_aadhaar_path = default_storage.path(verification.verifier_aadhaar.name)
#                     verifier_genuine, verifier_confidence, verifier_notes = verify_document(verifier_aadhaar_path, {})
#                     verification.ai_confidence_score = (doc_confidence + verifier_confidence) / 2
#                     verification.ai_analysis_notes += f"; Verifier Document: {verifier_notes}"
#                     verification.status = 'Verified' if doc_genuine and verifier_genuine else 'Fake'

#             verification.save()

# # ... [rest of the view remains unchanged] ...

#             # Patient Donation Status
#             donation_status = PatientDonationStatus(
#                 patient=patient,
#                 is_active=True
#             )
#             donation_status.save()
#             donation_status.set_end_time(int(request.POST['expected_recovery_time']))

#             # Context for success page
#             context = {
#                 'message': 'Patient registered successfully',
#                 'patient': patient,
#                 'hospital': hospital,
#                 'medical_reports': medical_reports,
#                 'assistance': assistance,
#                 'verification': verification,
#                 'donation_status': donation_status,
#             }
#             request.session['context'] = context
#             # return render(request, 'success_page.html', context)
#             return redirect('user_dashboard')

#         except ValidationError as e:
#             return render(request, 'patient_registration.html', {'error': str(e)})
#         except KeyError as e:
#             return render(request, 'patient_registration.html', {'error': f'Missing required field: {str(e)}'})
#         except Exception as e:
#             return render(request, 'patient_registration.html', {'error': f'An error occurred: {str(e)}'})

#     return render(request, 'patient_registration.html')





# views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.core.files.storage import default_storage
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus
import os
import urllib.parse
# views.py (partial update)
# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'both')  # Default to 'both' for testing
#     selected_type = request.session.get('selected_type', 'Donor')  # Default to 'Donor'

#     if request.method == 'POST':
#         selected_type = request.POST.get('selected_type', selected_type)
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         print(f"Switched to {selected_type}")  # Debug log
#         return HttpResponseRedirect(request.path_info)

#     context = {
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if selected_type == 'Donor':
#         active_patients = Patient.objects.filter(
#             verification__status='Verified',
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients

#     print("Rendering dashboard with:", context)  # Debug log
#     return render(request, 'user_dashboard.html', context)

# def user_dashboard(request):
#     # Assuming user_type is set via authentication or session
#     user_type = request.session.get('user_type', 'both')  # Default to 'both' for testing
#     selected_type = request.session.get('selected_type', 'Donor')  # Default to 'Donor'

#     if request.method == 'POST':
#         selected_type = request.POST.get('selected_type', selected_type)
#         request.session['selected_type'] = selected_type
#         request.session.modified = True  # Ensure session saves
#         print(f"Switched to {selected_type}")  # Debug log
#         return HttpResponseRedirect(request.path_info)  # Redirect to same page

#     context = {
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if selected_type == 'Donor':
#         active_patients = Patient.objects.filter(
#             verification__status='Verified',
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients

#     return render(request, 'user_dashboard.html', context)

def patient_detail(request, patient_id):
    # Store patient_id in session
    request.session['selected_patient_id'] = patient_id
    request.session.modified = True  # Ensure session saves
    print(f"Stored patient_id in session: {patient_id}")  # Debug log

    patient = get_object_or_404(Patient, patient_id=patient_id, verification__status='Verified')
    context = {
        'patient': patient,
    }
    return render(request, 'patient_detail.html', context)

def donate(request, patient_id):
    if request.method == 'POST':
        patient = get_object_or_404(Patient, patient_id=patient_id, verification__status='Verified')
        # Placeholder donation logic
        context = {
            'patient': patient,
            'message': 'Donation processed (placeholder)',
        }
        return render(request, 'patient_detail.html', context)
    patient = get_object_or_404(Patient, patient_id=patient_id, verification__status='Verified')
    return render(request, 'patient_detail.html', {'patient': patient, 'error': 'Invalid request'})

def share_patient(request, patient_id, platform):
    patient = get_object_or_404(Patient, patient_id=patient_id, verification__status='Verified')
    base_url = request.build_absolute_uri('/')
    patient_url = f"{base_url}patient/{patient_id}/"
    message = f"Help {patient.full_name} with {patient.hospitaldetails_set.first().medical_problem}. Donate here: {patient_url}"

    if platform == 'whatsapp':
        encoded_message = urllib.parse.quote(message)
        share_url = f"https://wa.me/?text={encoded_message}"
    elif platform == 'twitter':
        encoded_message = urllib.parse.quote(message)
        share_url = f"https://twitter.com/intent/tweet?text={encoded_message}"
    elif platform == 'facebook':
        encoded_message = urllib.parse.quote(message)
        share_url = f"https://www.facebook.com/sharer/sharer.php?u={patient_url}&quote={encoded_message}"
    else:
        return redirect('patient_detail', patient_id=patient_id)

    return HttpResponseRedirect(share_url)



# views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.core.files.storage import default_storage
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
from .models import Patient, HospitalDetails, MedicalReport, AssistanceRequired, Verification, PatientDonationStatus
# from .utils.ai_verification import check_aadhaar_number
import os
# import urllib.parse

# def user_dashboard(request):
#     # Default to 'both' for testing; in production, set via auth
#     user_type = request.session.get('user_type', 'both')
#     selected_type = request.session.get('selected_type', 'donor')  # Default to 'donor'

#     if request.method == 'POST':
#         selected_type = request.POST.get('selected_type', selected_type).lower()  # Ensure lowercase
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         print(f"Switched to {selected_type}")  # Debug log
#         return HttpResponseRedirect(request.path_info)

#     context = {
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     print(f"Current user_type: {user_type}, selected_type: {selected_type}")  # Debug log

#     if selected_type == 'donor':
#         active_patients = Patient.objects.filter(
#             verification__status='Verified',
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
#         print(f"Active patients found: {active_patients.count()}")  # Debug log

#     return render(request, 'user_dashboard.html', context)



# # ... [rest of your views.py remains unchanged] ...

from django.shortcuts import render, HttpResponseRedirect
from .models import Patient  # Assuming Patient model exists

# def user_dashboard(request):
#     # Get user_type from session or authentication (default to 'donor' for testing)
#     user_type = request.session.get('user_type', 'donor')  # In production, tie this to auth
#     selected_type = request.session.get('selected_type', 'donor')  # Default to 'donor'

#     # Handle POST request for switching user type (only if user_type is 'both')
#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         print(f"Switched to {selected_type}")  # Debug log
#         return HttpResponseRedirect(request.path_info)

#     # If user_type is not 'both', enforce selected_type to match user_type
#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     print(f"Current user_type: {user_type}, selected_type: {selected_type}")  # Debug log

#     if selected_type == 'donor':
#         active_patients = Patient.objects.filter(
#             verification__status='Verified',
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
#         print(f"Active patients found: {active_patients.count()}")  # Debug log

#     return render(request, 'user_dashboard.html', context)


# from django.shortcuts import render, HttpResponseRedirect
# from django.utils import timezone
# from django.views.decorators.http import require_POST
# from .models import mainuser, Donor, CareCoin, ScratchCard, Patient
# import json

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     # Pass scratch card data from session
#     if 'show_scratch_card' in request.session and request.session['show_scratch_card']:
#         context['show_scratch_card'] = True
#         context['bonus_coins'] = request.session.get('bonus_coins', 0)
#         # Don’t clear session yet—it’ll be cleared AFTER the scratch card is revealed

#     if selected_type == 'donor':
#         active_patients = Patient.objects.filter(
#             verification__status='Verified',
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
#         donor_coins = CareCoin.objects.filter(donor=user)
#         context['coin_transactions'] = donor_coins
#         context['coin_balance'] = donor_coins[0].current_balance if donor_coins.exists() else 0

#     if selected_type == 'patient':
#         has_requested_aid = Patient.objects.filter(
#             user=user,
#             donation_status__is_active=True
#         ).exists()
#         context['has_requested_aid'] = has_requested_aid

#     return render(request, 'user_dashboard.html', context)

# @require_POST
# def reveal_scratch_card(request):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return JsonResponse({'error': 'User not authenticated'}, status=401)

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both'] or not request.session.get('show_scratch_card'):
#         return JsonResponse({'error': 'Invalid request'}, status=403)

#     # Create or get scratch card
#     scratch_card, created = ScratchCard.objects.get_or_create(user=user)
#     bonus_coins = scratch_card.bonus_coins

#     # Store coins in database
#     if created or not CareCoin.objects.filter(donor=user, donation_type='bonus').exists():
#         CareCoin.objects.create(
#             donor=user,
#             transaction_type='earned',
#             coins=bonus_coins,
#             donation_type='bonus',
#             description=f"First login bonus from scratch card (ID: {scratch_card.carecoin_id})"
#         )

#     # Clear session flags
#     del request.session['show_scratch_card']
#     del request.session['bonus_coins']
#     request.session.modified = True

#     return JsonResponse({'bonus_coins': bonus_coins})


# from django.shortcuts import render, HttpResponseRedirect
# from django.utils import timezone
# from django.views.decorators.http import require_POST
# from .models import mainuser, Donor, CareCoin, ScratchCard, Patient

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     # Only show scratch card on first login
#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True
#         # Don’t set bonus_coins here—it’ll be set on reveal

#     if selected_type == 'donor':
#         active_patients = Patient.objects.filter(
#             verification__status='Verified',
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
#         donor_coins = CareCoin.objects.filter(donor=user)
#         context['coin_transactions'] = donor_coins
#         context['coin_balance'] = donor_coins[0].current_balance if donor_coins.exists() else 0

#     if selected_type == 'patient':
#         has_requested_aid = Patient.objects.filter(
#             user=user,
#             donation_status__is_active=True
#         ).exists()
#         context['has_requested_aid'] = has_requested_aid

#     return render(request, 'user_dashboard.html', context)

# @require_POST
# def reveal_scratch_card(request):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return JsonResponse({'error': 'User not authenticated'}, status=401)

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both'] or not user.first_login:
#         return JsonResponse({'error': 'Invalid request'}, status=403)

#     # Create or get scratch card
#     scratch_card, created = ScratchCard.objects.get_or_create(user=user)
#     bonus_coins = scratch_card.bonus_coins

#     # Store coins in database only once
#     if created or not CareCoin.objects.filter(donor=user, donation_type='bonus').exists():
#         CareCoin.objects.create(
#             donor=user,
#             transaction_type='earned',
#             coins=bonus_coins,
#             donation_type='bonus',
#             description=f"First login bonus from scratch card (ID: {scratch_card.carecoin_id})"
#         )

#     # Mark first login as complete
#     user.first_login = False
#     user.save()

#     return JsonResponse({'bonus_coins': bonus_coins})

from django.shortcuts import render, HttpResponseRedirect
from django.utils import timezone
from django.views.decorators.http import require_POST
from .models import mainuser, Donor, CareCoin, ScratchCard, Patient
from django.urls import reverse

from django.shortcuts import render, redirect, HttpResponse
from django.utils import timezone
from django.urls import reverse
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin
from PIL import Image, ImageDraw, ImageFont
import io

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True

#     if selected_type == 'donor':
#         active_patients = Patient.objects.filter(
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
#         donor_coins = CareCoin.objects.filter(donor=user)
#         context['coin_transactions'] = donor_coins
#         context['coin_balance'] = donor_coins[0].current_balance if donor_coins.exists() else 0

#     if selected_type == 'patient':
#         active_patient = Patient.objects.filter(
#             user=user,
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()
#         context['active_patient'] = active_patient
#         context['has_requested_aid'] = bool(active_patient)

#     return render(request, 'user_dashboard.html', context)

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True

#     if selected_type == 'donor':
#         # Filter only active patients
#         active_patients = Patient.objects.filter(
#             donation_status__is_active=True,
#             donation_status__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
        
#         # Fetch donor's Care-Coin balance
#         coin_balance = CareCoin.objects.filter(donor=user).aggregate(total=models.Sum('coins'))['total'] or 0
#         context['coin_balance'] = coin_balance

#         # Fetch recent Care-Coin transactions for display
#         coin_transactions = CareCoin.objects.filter(donor=user).order_by('-created_at')[:5]  # Limit to 5 for brevity
#         context['coin_transactions'] = coin_transactions

#     if selected_type == 'patient':
#         active_patient = Patient.objects.filter(
#             user=user,
#             donation_status__is_active=True,
#             donation_status__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()
#         context['active_patient'] = active_patient
#         context['has_requested_aid'] = bool(active_patient)

#     return render(request, 'user_dashboard.html', context)



from django.shortcuts import render, redirect
from django.urls import reverse
from django.db.models import Sum
from .models import mainuser, Patient, CareCoin

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True

#     if selected_type == 'donor':
#         # Filter only active patients
#         active_patients = Patient.objects.filter(
#             donation_status__is_active=True,
#             donation_status__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
        
#         # Fetch donor's Care-Coin balance with error handling
#         coin_balance_query = CareCoin.objects.filter(donor=user).aggregate(total=Sum('coins'))
#         coin_balance = coin_balance_query['total'] if coin_balance_query['total'] is not None else 0
#         context['coin_balance'] = coin_balance

#         # Fetch recent Care-Coin transactions for display
#         coin_transactions = CareCoin.objects.filter(donor=user).order_by('-created_at')[:5]  # Limit to 5 for brevity
#         context['coin_transactions'] = coin_transactions

#     if selected_type == 'patient':
#         active_patient = Patient.objects.filter(
#             user=user,
#             donation_status__is_active=True,
#             donation_status__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()
#         context['active_patient'] = active_patient
#         context['has_requested_aid'] = bool(active_patient)

#     return render(request, 'user_dashboard.html', context)

from django.shortcuts import render, redirect
from django.urls import reverse
from django.db.models import Sum
from .models import mainuser, Patient, CareCoin

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True

#     if selected_type == 'donor':
#         # Filter only active patients with status 'active' using donation_status_id
#         active_patients = Patient.objects.filter(
#             donation_status__is_active=True,
#             donation_status_id__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
        
#         # Fetch donor's Care-Coin balance with error handling
#         coin_balance_query = CareCoin.objects.filter(donor=user).aggregate(total=Sum('coins'))
#         coin_balance = coin_balance_query['total'] if coin_balance_query['total'] is not None else 0
#         context['coin_balance'] = coin_balance

#         # Fetch recent Care-Coin transactions for display
#         coin_transactions = CareCoin.objects.filter(donor=user).order_by('-created_at')[:5]  # Limit to 5 for brevity
#         context['coin_transactions'] = coin_transactions

#     if selected_type == 'patient':
#         active_patient = Patient.objects.filter(
#             user=user,
#             donation_status_id__is_active=True,
#             donation_status_id__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()
#         context['active_patient'] = active_patient
#         context['has_requested_aid'] = bool(active_patient)

#     return render(request, 'user_dashboard.html', context)


from django.shortcuts import render, redirect
from django.urls import reverse
from django.db.models import Sum
from .models import mainuser, Patient, CareCoin


from django.shortcuts import render, redirect
from django.urls import reverse
from django.db.models import Sum
from .models import mainuser, Patient, CareCoin, Verification, PatientStatus

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True

#     if selected_type == 'donor':
#         # Filter only active and verified patients with status 'active' using PatientStatus
#         active_patients = Patient.objects.filter(
#             status__is_active=True,
#             status__status='active',
#             verification_set__status='Verified'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
        
#         # Fetch donor's Care-Coin balance with error handling
#         coin_balance_query = CareCoin.objects.filter(donor=user).aggregate(total=Sum('coins'))
#         coin_balance = coin_balance_query['total'] if coin_balance_query['total'] is not None else 0
#         context['coin_balance'] = coin_balance

#         # Fetch recent Care-Coin transactions for display
#         coin_transactions = CareCoin.objects.filter(donor=user).order_by('-created_at')[:5]  # Limit to 5 for brevity
#         context['coin_transactions'] = coin_transactions

#     if selected_type == 'patient':
#         # Filter for the patient's active donation status
#         active_patient = Patient.objects.filter(
#             user=user,
#             status__is_active=True,
#             status__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()
#         context['active_patient'] = active_patient
#         context['has_requested_aid'] = bool(active_patient)

#     return render(request, 'user_dashboard.html', context)

from django.shortcuts import render, redirect
from django.urls import reverse
from django.db.models import Sum
from .models import mainuser, Patient, CareCoin, Verification, PatientStatus, SaveTheSaviorRequest

# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     donor_id = None
#     try:
#         donor = Donor.objects.get(user_id=user_id)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         print("Donor profile not found for user_id:", user_id)
    
    
    
def user_dashboard(request):
    user_type = request.session.get('user_type', 'donor')
    selected_type = request.session.get('selected_type', 'donor')
    user_id = request.session.get('user_id')

    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)

    donor_id = None
    try:
        donor = Donor.objects.get(user_id=user_id)
        donor_id = donor.donor_id
    except Donor.DoesNotExist:
        print("Donor profile not found for user_id:", user_id)
    
    # patient1 = None
    # patient_id = None
    # request_count = 0
    # # patient_id= None
    # try:
    #     patient1=Patient.objects.get(user=user)
    #     print("p1====",patient1)
    #     patient_id=patient1.patient_id
    #     print("id===",patient_id)
    # except Patient.DoesNotExist:
    #     print("patient profile not found for user_id:", user_id)

    
    # patient = Patient.objects.filter(user=user).first()
    # if patient:
    #     patient_status = PatientDonationStatus.objects.filter(patient=patient, status='active').first()
    #     if patient_status and patient_status.is_active:
    #         request_count = SaveTheSaviorRequest.objects.filter(patient=patient, status='pending').count()
    # # patient_id= None
    # try:
    #     patient1=Patient.objects.get(user=user)
    #     print("p1====",patient1)
    #     patient_id=patient1.patient_id
    #     print("id===",patient_id)
    # except Patient.DoesNotExist:
    #     print("patient profile not found for user_id:", user_id)

    
    # patient = Patient.objects.filter(user=user).first()
    # if patient:
    #     patient_status = PatientDonationStatus.objects.filter(patient=patient, status='active').first()
    #     if patient_status and patient_status.is_active:
    #         request_count = SaveTheSaviorRequest.objects.filter(patient=patient, status='pending').count()
    # context = {
        
    # }
    # return render(request, 'user_dashboard.html', context)
    # Check if the user is a patient and count pending requests
    # patient = PatientDonationStatus.objects.filter(patient_id=user.user_id, status='active').first()  # Adjust based on your Patient model
    # print("patient====>", patient)
    # if patient:
        # Count pending SaveTheSaviorRequest records for this patient
        # patient_requests_count = SaveTheSaviorRequest.objects.filter(patient=patient, status='pending').count()
        # print("patient_requests_count====>", patient_requests_count)
    # patient = PatientDonationStatus.objects.filter(patient_id=user_id, status='active').first()
    # print("patient====",patient)
    # if patient:
    #     patient_requests_count = SaveTheSaviorRequest.objects.filter(patient=patient, status='pending').count()
    if request.method == 'POST' and user_type == 'both':
        selected_type = request.POST.get('selected_type', selected_type).lower()
        request.session['selected_type'] = selected_type
        request.session.modified = True
        return HttpResponseRedirect(request.path_info)

    if user_type != 'both':
        selected_type = user_type

    context = {
        'user': user,
        'user_type': user_type,
        'selected_type': selected_type,
        # 'user': user,
        'donor_id': donor_id # Pass donor_id to template
        # 'request_count': request_count,  
        # 'patient_id':patient_id,# Pass the count for the notification badge
        # 'patient_id': patient_id,
        # 'patient': patient1,
        # 'request_count': request_count
    }
        # Other context data as needed
    

    if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
        context['show_scratch_card'] = True

    if selected_type == 'donor':
        # Filter only active and verified patients with status 'active' using PatientStatus
        try:
            # Try using verification_set (default reverse name for ForeignKey)
            active_patients = Patient.objects.filter(
                status__is_active=True,
                status__status='active',
                verification__status='Verified'
            ).prefetch_related('hospitaldetails_set__assistancerequired_set')
        except FileError:
            # Fallback to verifications if verification_set is not recognized
            active_patients = Patient.objects.filter(
                status__is_active=True,
                status__status='active',
                verifications__status='Verified'
            ).prefetch_related('hospitaldetails_set__assistancerequired_set')

        context['patients'] = active_patients
        
        # Fetch donor's Care-Coin balance with error handling
        coin_balance_query = CareCoin.objects.filter(donor=user).aggregate(total=Sum('coins'))
        coin_balance = coin_balance_query['total'] if coin_balance_query['total'] is not None else 0
        context['coin_balance'] = coin_balance

        # Fetch recent Care-Coin transactions for display
        coin_transactions = CareCoin.objects.filter(donor=user).order_by('-created_at')[:5]  # Limit to 5 for brevity
        context['coin_transactions'] = coin_transactions

    if selected_type == 'patient':
        # Filter for the patient's active donation status
        active_patient = Patient.objects.filter(
            user=user,
            status__is_active=True,
            status__status='active'
        ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()
        context['active_patient'] = active_patient
        context['has_requested_aid'] = bool(active_patient)

    return render(request, 'user_dashboard.html', context)


# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import mainuser, Patient, SaveTheSaviorRequest

# def view_savior_requests(request, patient_id):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     patient = get_object_or_404(Patient, patient_id=patient_id, user=user, status='active')

#     if request.method == 'POST':
#         request_id = request.POST.get('request_id')
#         action = request.POST.get('action')  # e.g., 'accept' or 'reject'

#         try:
#             savior_request = SaveTheSaviorRequest.objects.get(request_id=request_id, patient=patient)
#             savior_request.status = 'accepted' if action == 'accept' else 'rejected'
#             savior_request.save()
#             messages.success(request, f"Request {action}ed successfully.")
#         except SaveTheSaviorRequest.DoesNotExist:
#             messages.error(request, "Request not found.")

#     savior_requests = SaveTheSaviorRequest.objects.filter(patient=patient, status='pending')
#     context = {
#         'user': user,
#         'patient': patient,
#         'savior_requests': savior_requests
#     }
#     return render(request, 'view_savior_requests.html', context)


# views.py
def view_savior_requests(request, patient_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    patient = get_object_or_404(Patient, patient_id=patient_id, user=user)
    patient_status = PatientDonationStatus.objects.get(patient=patient)

    savior_requests = SaveTheSaviorRequest.objects.filter(patient=patient, status='pending')
    return render(request, 'view_savior_requests.html', {
        'user': user,
        'patient': patient,
        'patient_status': patient_status,
        'savior_requests': savior_requests
    })
# views.py
# def view_savior_requests(request, patient_id):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     patient = get_object_or_404(Patient, patient_id=patient_id, user=user)
#     patient_status = PatientDonationStatus.objects.get(patient=patient)

#     if request.method == 'POST':
#         request_id = request.POST.get('request_id')
#         action = request.POST.get('action')  # e.g., 'accept' or 'reject'

#         try:
#             savior_request = SaveTheSaviorRequest.objects.get(request_id=request_id, patient=patient)
#             savior_request.status = 'accepted' if action == 'accept' else 'rejected'
#             savior_request.save()
#             messages.success(request, f"Request {action}ed successfully.")
#         except SaveTheSaviorRequest.DoesNotExist:
#             messages.error(request, "Request not found.")

#     savior_requests = SaveTheSaviorRequest.objects.filter(patient=patient, status='pending')
#     context = {
#         'user': user,
#         'patient': patient,
#         'patient_status': patient_status,
#         'savior_requests': savior_requests
#     }
#     return render(request, 'view_savior_requests.html', context)


# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, Donor, DonationTransaction, SaveTheSaviorRequest, PatientDonationStatus
from django.contrib import messages

# def register_as_both_sides(request, donor_id):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'register_as_both_sides.html', {'error': 'Only donors can register as patients'})

#     try:
#         donor = Donor.objects.get(donor_id=donor_id, user=user)
#     except Donor.DoesNotExist:
#         return render(request, 'register_as_both_sides.html', {
#             'error': 'Donor profile not found.',
#             'donor_id': donor_id
#         })

#     if request.method == 'POST':
#         # Check if the user’s email matches any patient email
#         donor_email = user.email
#         patient_status = PatientDonationStatus.objects.filter(patient__email=donor_email, status='active').first()
#         patient = patient_status.patient if patient_status else None

#         if patient:
#             # User is already a patient; ensure active status
#             patient_status.is_active = True
#             patient_status.status = 'active'
#             patient_status.save()
#         else:
#             # Create a new patient record and donation status for the donor
#             patient = Patient.objects.create(
#                 user=user,
#                 full_name=user.full_name,
#                 email=user.email,
#                 phone_number=user.phone_number,
#                 # Add other required fields based on your Patient model
#             )
#             PatientDonationStatus.objects.create(
#                 patient=patient,
#                 is_active=True,
#                 status='active'
#             )

#         # Find all donation transactions where this donor helped patients (excluding self if they’re a patient)
#         donations = DonationTransaction.objects.filter(donor=user)
#         notified_patients = set()

#         for donation in donations:
#             patient = donation.patient
#             patient_status = PatientDonationStatus.objects.filter(patient=patient, status='active').first()
#             if not patient_status:  # Skip if patient is not active
#                 continue
#             # Skip if the patient is the same as the current user (donor-turned-patient)
#             if patient.email == donor_email:
#                 continue
#             if patient not in notified_patients:
#                 # Create a Save-the-Savior request
#                 SaveTheSaviorRequest.objects.create(
#                     donor=donor,
#                     patient=patient,
#                     transaction=donation,
#                     message=f"Your previous savior, {donor.user.full_name}, is now in need of assistance. Please consider helping."
#                 )
#                 notified_patients.add(patient)
#                 messages.success(request, f"Notification sent to {patient.full_name} for assistance.")

#         # Redirect to a success page or patient dashboard
#         return redirect('patient_dashboard', patient_id=patient.patient_id)

#     context = {
#         'user': user,
#         'donor': donor,
#         'donor_id': donor_id
#     }
#     return render(request, 'register_as_both_sides.html', context)

# views.py
from django.shortcuts import render, redirect, get_object_or_404
from .models import mainuser, Patient, Donor, DonationTransaction, SaveTheSaviorRequest, PatientDonationStatus
from django.contrib import messages

def register_as_both_sides(request, donor_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    donor = get_object_or_404(Donor, donor_id=donor_id, user=user)

    if request.method == 'POST':
        # Check or create patient record
        donor_email = user.email
        patient_status = PatientDonationStatus.objects.filter(patient__email=donor_email, status='active').first()
        if patient_status:
            patient = patient_status.patient
        else:
            patient = Patient.objects.create(user=user, full_name=user.full_name, email=donor_email, phone_number=user.phone_number)
            PatientDonationStatus.objects.create(patient=patient, is_active=True, status='active')

        # Notify patients the donor previously helped (excluding self)
        donations = DonationTransaction.objects.filter(donor=user)
        for donation in donations:
            other_patient = donation.patient
            if other_patient.email != donor_email:  # Exclude self
                other_patient_status = PatientDonationStatus.objects.filter(patient=other_patient, status='active').first()
                if other_patient_status:
                    SaveTheSaviorRequest.objects.create(
                        donor=donor,
                        patient=other_patient,
                        transaction=donation
                    )
                    messages.success(request, f"Notification sent to {other_patient.full_name}")

        return redirect('user_dashboard')

    return render(request, 'register_as_both_sides.html', {'user': user, 'donor': donor})
# views.py
from django.shortcuts import render, get_object_or_404
from .models import mainuser, Donor, Patient

# def view_patient_details(request, donor_id):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     donor = get_object_or_404(Donor, donor_id=donor_id)
#     patient = Patient.objects.filter(user=donor.user, status='active').first()

#     if not patient:
#         return render(request, 'view_patient_details.html', {'error': 'Patient profile not found or inactive.'})

#     context = {
#         'user': user,
#         'donor': donor,
#         'patient': patient
#     }
#     return render(request, 'view_patient_details.html', context)

# views.py
from django.shortcuts import render, get_object_or_404
from .models import mainuser, Donor, Patient, PatientDonationStatus

def view_patient_details(request, donor_id):
    user_id = request.session.get('user_id')
    print("user_id==", user_id)
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    donor = get_object_or_404(Donor, donor_id=donor_id)
    patient = Patient.objects.filter(user=donor.user, status='active').first()
    patient_status = PatientDonationStatus.objects.filter(patient=patient, status='active').first()

    if not patient or not patient_status:
        return render(request, 'view_patient_details.html', {'error': 'Patient profile not found or inactive.'})

    context = {
        'user': user,
        'donor': donor,
        'patient': patient,
        'patient_status': patient_status
    }
    return render(request, 'view_patient_details.html', context)
# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True

#     if selected_type == 'donor':
#         # Filter only active patients with status 'active' using the donation_status relationship
#         active_patients = Patient.objects.filter(
#             donation_status__is_active=True,
#             donation_status__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
        
#         # Fetch donor's Care-Coin balance with error handling
#         coin_balance_query = CareCoin.objects.filter(donor=user).aggregate(total=Sum('coins'))
#         coin_balance = coin_balance_query['total'] if coin_balance_query['total'] is not None else 0
#         context['coin_balance'] = coin_balance

#         # Fetch recent Care-Coin transactions for display
#         coin_transactions = CareCoin.objects.filter(donor=user).order_by('-created_at')[:5]  # Limit to 5 for brevity
#         context['coin_transactions'] = coin_transactions

#     if selected_type == 'patient':
#         # Filter for the patient's active donation status
#         active_patient = Patient.objects.filter(
#             user=user,
#             donation_status__is_active=True,
#             donation_status__status='active'
#         ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()
#         context['active_patient'] = active_patient
#         context['has_requested_aid'] = bool(active_patient)

#     return render(request, 'user_dashboard.html', context)
# def donor_patient_detail(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donor_patient_detail.html', {'error': 'Only donors can view patient details'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set',
#         'hospitaldetails_set__medicalreport_set',
#         'verification_set',
#         'donation_status'
#     ).first()

#     if not patient:
#         return render(request, 'donor_patient_detail.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     medical_reports = hospital_details.medicalreport_set.all() if hospital_details else []
#     verification = patient.verification_set.first()
#     donation_status = patient.donation_status if hasattr(patient, 'donation_status') else None

#     # Calculate percentage and days left
#     total_needed = sum(a.amount_required or 0 for a in assistances if a.amount_required) or 1
#     total_received = sum(a.amount_received or 0 for a in assistances if a.amount_received) or 0
#     percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0
#     days_left = None
#     if donation_status and donation_status.end_time:
#         days_left = max(0, (donation_status.end_time - timezone.now()).days)

#     # Fetch earlier donations (assuming CareCoin tracks donations)
#     earlier_donations = CareCoin.objects.filter(
#         donor=user,
#         description__contains=f"Donation to Patient ID: {patient_id}"
#     ).order_by('-created_at')

#     # Generate shareable link
#     share_link = request.build_absolute_uri(reverse('donor_patient_detail', args=[patient_id]))

#     context = {
#         'user': user,
#         'patient': patient,
#         'hospital_details': hospital_details,
#         'assistances': assistances,
#         'medical_reports': medical_reports,
#         'verification': verification,
#         'donation_status': donation_status,
#         'percentage': percentage,
#         'total_received': total_received,
#         'total_needed': total_needed,
#         'share_link': share_link,
#         'days_left': days_left,
#         'earlier_donations': earlier_donations,
#     }

#     if 'download' in request.GET:
#         img = Image.new('RGB', (800, 800), color='white')
#         draw = ImageDraw.Draw(img)
#         try:
#             font = ImageFont.truetype("arial.ttf", 20)
#             large_font = ImageFont.truetype("arial.ttf", 30)
#         except:
#             font = ImageFont.load_default()
#             large_font = ImageFont.load_default()

#         y = 20
#         draw.text((20, y), f"{patient.full_name}", font=large_font, fill='black')
#         y += 50

#         try:
#             photo_path = patient.patient_photo   # Adjust if photo field exists
#             photo = Image.open(photo_path).resize((200, 200), Image.LANCZOS)
#             img.paste(photo, (20, y))
#             y += 220
#         except (AttributeError, FileNotFoundError):
#             draw.text((20, y), "No photo available", font=font, fill='gray')
#             y += 40

#         draw.text((20, y), f"Issue: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         days_text = f"{days_left} days" if days_left is not None else "Not set"
#         draw.text((20, y), f"Days Left: {days_text}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Patient ID: {patient.patient_id}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Location: {hospital_details.hospital_location if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         if assistances:
#             draw.text((20, y), f"Assistance Needed: {assistances[0].assistance_type}", font=font, fill='black')
#             y += 40
#             if assistances[0].assistance_type == "Financial Aid":
#                 draw.text((20, y), f"Amount: {assistances[0].amount_required}", font=font, fill='black')
#                 y += 40
#         draw.text((20, y), "Donate at:", font=font, fill='black')
#         y += 40
#         draw.text((20, y), share_link, font=font, fill='black')

#         buffer = io.BytesIO()
#         img.save(buffer, format="PNG")
#         buffer.seek(0)
#         response = HttpResponse(buffer, content_type='image/png')
#         response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
#         return response

#     return render(request, 'donor_patient_detail.html', context)


# def donor_patient_detail(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donor_patient_detail.html', {'error': 'Only donors can view patient details'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True, donation_status__status='active').prefetch_related(
#         'hospitaldetails_set__assistancerequired_set',
#         'hospitaldetails_set__medicalreport_set',
#         'verification_set',
#         'donation_status'
#     ).first()

#     if not patient:
#         return render(request, 'donor_patient_detail.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     medical_reports = hospital_details.medicalreport_set.all() if hospital_details else []
#     verification = patient.verification_set.first()
#     donation_status = patient.donation_status if hasattr(patient, 'donation_status') else None

#     # Calculate percentage and days left
#     total_needed = sum(a.amount_required or 0 for a in assistances if a.amount_required) or 1
#     total_received = sum(a.amount_received or 0 for a in assistances if a.amount_received) or 0
#     percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0
#     days_left = None
#     if donation_status and donation_status.end_time:
#         days_left = max(0, (donation_status.end_time - timezone.now()).days)

#     # Fetch earlier donations by this donor for this patient
#     earlier_donations = DonationTransaction.objects.filter(
#         donor=user,
#         patient__patient_id=patient_id
#     ).order_by('-transaction_date')

#     # Generate shareable link
#     share_link = request.build_absolute_uri(reverse('donor_patient_detail', args=[patient_id]))

#     context = {
#         'user': user,
#         'patient': patient,
#         'hospital_details': hospital_details,
#         'assistances': assistances,
#         'medical_reports': medical_reports,
#         'verification': verification,
#         'donation_status': donation_status,
#         'percentage': percentage,
#         'total_received': total_received,
#         'total_needed': total_needed,
#         'share_link': share_link,
#         'days_left': days_left,
#         'earlier_donations': earlier_donations,
#     }

#     if 'download' in request.GET:
#         img = Image.new('RGB', (800, 800), color='white')
#         draw = ImageDraw.Draw(img)
#         try:
#             font = ImageFont.truetype("arial.ttf", 20)
#             large_font = ImageFont.truetype("arial.ttf", 30)
#         except:
#             font = ImageFont.load_default()
#             large_font = ImageFont.load_default()

#         y = 20
#         draw.text((20, y), f"{patient.full_name}", font=large_font, fill='black')
#         y += 50

#         try:
#             photo_path = patient.photo.path  # Adjust if photo field exists
#             photo = Image.open(photo_path).resize((200, 200), Image.LANCZOS)
#             img.paste(photo, (20, y))
#             y += 220
#         except (AttributeError, FileNotFoundError):
#             draw.text((20, y), "No photo available", font=font, fill='gray')
#             y += 40

#         draw.text((20, y), f"Issue: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         days_text = f"{days_left} days" if days_left is not None else "Not set"
#         draw.text((20, y), f"Days Left: {days_text}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Patient ID: {patient.patient_id}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Location: {hospital_details.hospital_location if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         if assistances:
#             draw.text((20, y), f"Assistance Needed: {assistances[0].assistance_type}", font=font, fill='black')
#             y += 40
#             if assistances[0].assistance_type == "Financial Aid":
#                 draw.text((20, y), f"Amount: {assistances[0].amount_required}", font=font, fill='black')
#                 y += 40
#         draw.text((20, y), "Donate at:", font=font, fill='black')
#         y += 40
#         draw.text((20, y), share_link, font=font, fill='black')

#         buffer = io.BytesIO()
#         img.save(buffer, format="PNG")
#         buffer.seek(0)
#         response = HttpResponse(buffer, content_type='image/png')
#         response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
#         return response

#     return render(request, 'donor_patient_detail.html', context)


from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse
from django.utils import timezone
from PIL import Image, ImageDraw, ImageFont
import io
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, DonationTransaction, PatientDonationStatus

# def donor_patient_detail(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donor_patient_detail.html', {'error': 'Only donors can view patient details'})

#     # Filter patient using the donation_status relationship from PatientDonationStatus
#     patient = Patient.objects.filter(
#         patient_id=patient_id,
#         donation_status__is_active=True,
#         donation_status__status='active'
#     ).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set',
#         'hospitaldetails_set__medicalreport_set',
#         'verification_set'
#     ).first()

#     if not patient:
#         return render(request, 'donor_patient_detail.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     medical_reports = hospital_details.medicalreport_set.all() if hospital_details else []
#     verification = patient.verification_set.first()
#     # Get PatientDonationStatus via the relationship
#     donation_status = patient.donation_status if hasattr(patient, 'donation_status') else None

#     # Calculate percentage and days left
#     total_needed = sum(a.amount_required or 0 for a in assistances if a.amount_required) or 1
#     total_received = sum(a.amount_received or 0 for a in assistances if a.amount_received) or 0
#     percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0
#     days_left = None
#     if donation_status and donation_status.end_time:
#         days_left = max(0, (donation_status.end_time - timezone.now()).days)

#     # Fetch earlier donations by this donor for this patient
#     earlier_donations = DonationTransaction.objects.filter(
#         donor=user,
#         patient__patient_id=patient_id
#     ).order_by('-transaction_date')

#     # Generate shareable link
#     share_link = request.build_absolute_uri(reverse('donor_patient_detail', args=[patient_id]))

#     context = {
#         'user': user,
#         'patient': patient,
#         'hospital_details': hospital_details,
#         'assistances': assistances,
#         'medical_reports': medical_reports,
#         'verification': verification,
#         'donation_status': donation_status,
#         'percentage': percentage,
#         'total_received': total_received,
#         'total_needed': total_needed,
#         'share_link': share_link,
#         'days_left': days_left,
#         'earlier_donations': earlier_donations,
#     }

#     if 'download' in request.GET:
#         img = Image.new('RGB', (800, 800), color='white')
#         draw = ImageDraw.Draw(img)
#         try:
#             font = ImageFont.truetype("arial.ttf", 20)
#             large_font = ImageFont.truetype("arial.ttf", 30)
#         except:
#             font = ImageFont.load_default()
#             large_font = ImageFont.load_default()

#         y = 20
#         draw.text((20, y), f"{patient.full_name}", font=large_font, fill='black')
#         y += 50

#         try:
#             photo_path = patient.patient_photo.path  # Use patient_photo as per your model
#             photo = Image.open(photo_path).resize((200, 200), Image.LANCZOS)
#             img.paste(photo, (20, y))
#             y += 220
#         except (AttributeError, FileNotFoundError):
#             draw.text((20, y), "No photo available", font=font, fill='gray')
#             y += 40

#         draw.text((20, y), f"Issue: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         days_text = f"{days_left} days" if days_left is not None else "Not set"
#         draw.text((20, y), f"Days Left: {days_text}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Patient ID: {patient.patient_id}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Location: {hospital_details.hospital_location if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         if assistances:
#             draw.text((20, y), f"Assistance Needed: {assistances[0].assistance_type}", font=font, fill='black')
#             y += 40
#             if assistances[0].assistance_type == "Financial Aid":
#                 draw.text((20, y), f"Amount: {assistances[0].amount_required}", font=font, fill='black')
#                 y += 40
#         draw.text((20, y), "Donate at:", font=font, fill='black')
#         y += 40
#         draw.text((20, y), share_link, font=font, fill='black')

#         buffer = io.BytesIO()
#         img.save(buffer, format="PNG")
#         buffer.seek(0)
#         response = HttpResponse(buffer, content_type='image/png')
#         response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
#         return response

#     return render(request, 'donor_patient_detail.html', context)


from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse
from django.utils import timezone
from PIL import Image, ImageDraw, ImageFont
import io
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, DonationTransaction, PatientStatus

def donor_patient_detail(request, patient_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    if user.user_type not in ['donor', 'both']:
        return render(request, 'donor_patient_detail.html', {'error': 'Only donors can view patient details'})

    # Filter patient using the status relationship from PatientStatus
    patient = Patient.objects.filter(
        patient_id=patient_id,
        status__is_active=True,
        status__status='active'
    ).prefetch_related(
        'hospitaldetails_set__assistancerequired_set',
        'hospitaldetails_set__medicalreport_set',
        'verification_set'
    ).first()

    if not patient:
        return render(request, 'donor_patient_detail.html', {'error': 'Patient not found or inactive'})

    hospital_details = patient.hospitaldetails_set.first()
    assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
    medical_reports = hospital_details.medicalreport_set.all() if hospital_details else []
    verification = patient.verification_set.first()
    # Get PatientStatus via the relationship
    patient_status = patient.status if hasattr(patient, 'status') else None

    # Calculate percentage and days left (using PatientStatus for consistency)
    total_needed = patient_status.total_needed if patient_status and patient_status.total_needed else sum(a.amount_required or 0 for a in assistances if a.amount_required) or 1
    total_received = patient_status.total_received if patient_status and patient_status.total_received else sum(a.amount_received or 0 for a in assistances if a.amount_received) or 0
    percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0
    days_left = None
    if patient_status and patient_status.end_time:
        days_left = max(0, (patient_status.end_time - timezone.now()).days)

    # Fetch earlier donations by this donor for this patient
    earlier_donations = DonationTransaction.objects.filter(
        donor=user,
        patient__patient_id=patient_id
    ).order_by('-transaction_date')

    # Generate shareable link
    share_link = request.build_absolute_uri(reverse('donor_patient_detail', args=[patient_id]))

    context = {
        'user': user,
        'patient': patient,
        'hospital_details': hospital_details,
        'assistances': assistances,
        'medical_reports': medical_reports,
        'verification': verification,
        'patient_status': patient_status,
        'percentage': percentage,
        'total_received': total_received,
        'total_needed': total_needed,
        'share_link': share_link,
        'days_left': days_left,
        'earlier_donations': earlier_donations,
    }

    if 'download' in request.GET:
        img = Image.new('RGB', (800, 800), color='white')
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("arial.ttf", 20)
            large_font = ImageFont.truetype("arial.ttf", 30)
        except:
            font = ImageFont.load_default()
            large_font = ImageFont.load_default()

        y = 20
        draw.text((20, y), f"{patient.full_name}", font=large_font, fill='black')
        y += 50

        try:
            photo_path = patient.patient_photo.path  # Use patient_photo as per your model
            photo = Image.open(photo_path).resize((200, 200), Image.LANCZOS)
            img.paste(photo, (20, y))
            y += 220
        except (AttributeError, FileNotFoundError):
            draw.text((20, y), "No photo available", font=font, fill='gray')
            y += 40

        draw.text((20, y), f"Issue: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
        y += 40
        days_text = f"{days_left} days" if days_left is not None else "Not set"
        draw.text((20, y), f"Days Left: {days_text}", font=font, fill='black')
        y += 40
        draw.text((20, y), f"Patient ID: {patient.patient_id}", font=font, fill='black')
        y += 40
        draw.text((20, y), f"Location: {hospital_details.hospital_location if hospital_details else 'N/A'}", font=font, fill='black')
        y += 40
        if assistances:
            draw.text((20, y), f"Assistance Needed: {assistances[0].assistance_type}", font=font, fill='black')
            y += 40
            if assistances[0].assistance_type == "Financial Aid":
                draw.text((20, y), f"Amount: {assistances[0].amount_required}", font=font, fill='black')
                y += 40
        draw.text((20, y), "Donate at:", font=font, fill='black')
        y += 40
        draw.text((20, y), share_link, font=font, fill='black')

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        response = HttpResponse(buffer, content_type='image/png')
        response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
        return response

    return render(request, 'donor_patient_detail.html', context)


# def user_dashboard(request):
#     user_type = request.session.get('user_type', 'donor')
#     selected_type = request.session.get('selected_type', 'donor')
#     user_id = request.session.get('user_id')

#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)

#     if request.method == 'POST' and user_type == 'both':
#         selected_type = request.POST.get('selected_type', selected_type).lower()
#         request.session['selected_type'] = selected_type
#         request.session.modified = True
#         return HttpResponseRedirect(request.path_info)

#     if user_type != 'both':
#         selected_type = user_type

#     context = {
#         'user': user,
#         'user_type': user_type,
#         'selected_type': selected_type,
#     }

#     if user.first_login and user.user_type in ['donor', 'both'] and selected_type == 'donor':
#         context['show_scratch_card'] = True

#     if selected_type == 'donor':
#         active_patients = Patient.objects.filter(
#             verification__status='Verified',
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set')
#         context['patients'] = active_patients
#         donor_coins = CareCoin.objects.filter(donor=user)
#         context['coin_transactions'] = donor_coins
#         context['coin_balance'] = donor_coins[0].current_balance if donor_coins.exists() else 0

#     if selected_type == 'patient':
#         active_patient = Patient.objects.filter(
#             user=user,
#             donation_status__is_active=True
#         ).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set').first()
#         context['active_patient'] = active_patient

#     return render(request, 'user_dashboard.html', context)

@require_POST
def reveal_scratch_card(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return JsonResponse({'error': 'User not authenticated'}, status=401)

    user = mainuser.objects.get(user_id=user_id)
    if user.user_type not in ['donor', 'both'] or not user.first_login:
        return JsonResponse({'error': 'Invalid request'}, status=403)

    scratch_card, created = ScratchCard.objects.get_or_create(user=user)
    bonus_coins = scratch_card.bonus_coins

    if created or not CareCoin.objects.filter(donor=user, donation_type='bonus').exists():
        CareCoin.objects.create(
            donor=user,
            transaction_type='earned',
            coins=bonus_coins,
            donation_type='bonus',
            description=f"First login bonus from scratch card (ID: {scratch_card.carecoin_id})"
        )

    user.first_login = False
    user.save()

    return JsonResponse({'bonus_coins': bonus_coins})

# def patient_status(request, patient_id):
#     user_id = request.session.get('user_id')
#     context =request.session.get('context')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     patient = Patient.objects.filter(patient_id=patient_id, user=user).prefetch_related('hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set').first()

#     if not patient:
#         return render(request, 'patient_status.html', {'error': 'Patient not found or unauthorized'})

#     # Calculate percentage (example logic—adjust based on your model)
#     hospital_details = "" #patient.hospitaldetails_set.first()
#     assistances = "amount" #hospital_details.assistancerequired_set.all() if hospital_details else []
#     total_needed = 100 #sum(a.amount_required for a in assistances) if assistances else 1  # Avoid division by 0
#     total_received = 100 # sum(a.amount_received for a in assistances) if assistances else 0
#     percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0

#     # Generate shareable link
#     share_link = request.build_absolute_uri(reverse('patient_status', args=[patient_id]))

#     context1 = {
#         'user': user,
#         'patient': patient,
#         'percentage': percentage,
#         'total_received': total_received,
#         'total_needed': total_needed,
#         'share_link': share_link,
#     }
#     return render(request, 'patient_status.html', context, context1)
#     # return render(request, 'success_page.html',context,context1)

from django.shortcuts import render, redirect, HttpResponse
from django.utils import timezone
from django.urls import reverse
from .models import mainuser, Patient
from PIL import Image, ImageDraw, ImageFont
import io

# def patient_status(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     patient = Patient.objects.filter(patient_id=patient_id, user=user).prefetch_related(
#         'hospitaldetails_set', 'hospitaldetails_set__assistancerequired_set',
#         'verification_set', 'donation_status_set'
#     ).first()

#     if not patient:
#         return render(request, 'patient_status.html', {'error': 'Patient not found or unauthorized'})

#     # Fetch related data
#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     total_needed = sum(a.amount_required for a in assistances) if assistances else 1  # Avoid division by 0
#     total_received = sum(a.amount_received for a in assistances) if assistances else 0
#     percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0

#     # Generate shareable link
#     share_link = request.build_absolute_uri(reverse('patient_status', args=[patient_id]))

#     context = {
#         'user': user,
#         'patient': patient,
#         'hospital': hospital_details,
#         'assistances': assistances,
#         'percentage': percentage,
#         'total_received': total_received,
#         'total_needed': total_needed,
#         'share_link': share_link,
#     }

#     if 'download' in request.GET:
#         # Generate image for download
#         img = Image.new('RGB', (800, 600), color='white')
#         draw = ImageDraw.Draw(img)
#         try:
#             font = ImageFont.truetype("arial.ttf", 20)
#         except:
#             font = ImageFont.load_default()

#         # Draw patient details
#         y = 20
#         draw.text((20, y), f"Patient Status: {patient.full_name}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Medical Problem: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Assistance Needed: {assistances[0].assistance_type if assistances else 'N/A'}", font=font, fill='black')
#         y += 40
#         if assistances and assistances[0].assistance_type == "Financial Aid":
#             draw.text((20, y), f"Amount Needed: {total_needed}", font=font, fill='black')
#             y += 40
#             draw.text((20, y), f"Amount Received: {total_received}", font=font, fill='black')
#             y += 40
#         draw.text((20, y), f"Progress: {percentage:.1f}%", font=font, fill='black')
#         y += 40
#         draw.text((20, y), "Help by donating at:", font=font, fill='black')
#         y += 40
#         draw.text((20, y), share_link, font=font, fill='black')

#         # Save image to buffer
#         buffer = io.BytesIO()
#         img.save(buffer, format="PNG")
#         buffer.seek(0)

#         # Serve as downloadable file
#         response = HttpResponse(buffer, content_type='image/png')
#         response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
#         return response

#     return render(request, 'patient_status.html', context)

from django.shortcuts import render, redirect, HttpResponse
from django.utils import timezone
from django.urls import reverse
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired
from PIL import Image, ImageDraw, ImageFont
import io

# def patient_status(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     patient = Patient.objects.filter(patient_id=patient_id, user=user).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set',
#         'hospitaldetails_set__medicalreport_set',
#         'verification_set',
#         'donation_status'
#     ).first()

#     if not patient:
#         return render(request, 'patient_status.html', {'error': 'Patient not found or unauthorized'})

#     # Fetch related data
#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     medical_reports = hospital_details.medicalreport_set.all() if hospital_details else []
#     verification = patient.verification_set.first()
#     donation_status = patient.donation_status if hasattr(patient, 'donation_status') else None

#     # Calculate percentage
#     total_needed = sum(a.amount_required or 0 for a in assistances if a.amount_required) or 1  # Avoid division by 0
#     total_received = 20000 #sum(a.amount_received or 0 for a in assistances if a.amount_received) or 0
#     percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0

#     # Generate shareable link
#     share_link = request.build_absolute_uri(reverse('patient_status', args=[patient_id]))

#     context = {
#         'user': user,
#         'patient': patient,
#         'hospital_details': hospital_details,
#         'assistances': assistances,
#         'medical_reports': medical_reports,
#         'verification': verification,
#         'donation_status': donation_status,
#         'percentage': percentage,
#         'total_received': total_received,
#         'total_needed': total_needed,
#         'share_link': share_link,
#     }

#     if 'download' in request.GET:
#         # Generate image for download
#         img = Image.new('RGB', (800, 600), color='white')
#         draw = ImageDraw.Draw(img)
#         try:
#             font = ImageFont.truetype("arial.ttf", 20)
#         except:
#             font = ImageFont.load_default()

#         # Draw patient details
#         y = 20
#         draw.text((20, y), f"Patient: {patient.full_name}", font=font, fill='black')
#         y += 40
#         draw.text((20, y), f"Medical Problem: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40
#         if assistances:
#             draw.text((20, y), f"Assistance: {assistances[0].assistance_type}", font=font, fill='black')
#             y += 40
#             if assistances[0].assistance_type == "Financial Aid":
#                 draw.text((20, y), f"Amount Needed: {total_needed}", font=font, fill='black')
#                 y += 40
#                 draw.text((20, y), f"Amount Received: {total_received}", font=font, fill='black')
#                 y += 40
#         draw.text((20, y), f"Progress: {percentage:.1f}%", font=font, fill='black')
#         y += 40
#         draw.text((20, y), "Help by donating at:", font=font, fill='black')
#         y += 40
#         draw.text((20, y), share_link, font=font, fill='black')

#         # Save image to buffer
#         buffer = io.BytesIO()
#         img.save(buffer, format="PNG")
#         buffer.seek(0)

#         # Serve as downloadable file
#         response = HttpResponse(buffer, content_type='image/png')
#         response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
#         return response

#     return render(request, 'patient_status.html', context)


from django.shortcuts import render, redirect, HttpResponse
from django.utils import timezone
from django.urls import reverse
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired
from PIL import Image, ImageDraw, ImageFont
import io
from datetime import datetime


from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse
from django.utils import timezone
from PIL import Image, ImageDraw, ImageFont
import io
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, Verification, PatientStatus

def patient_status(request, patient_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    # Filter patient using PatientStatus for authorization and active status
    patient = Patient.objects.filter(patient_id=patient_id, status__patient__user=user, status__is_active=True, status__status='active').prefetch_related(
        'hospitaldetails_set__assistancerequired_set',
        'hospitaldetails_set__medicalreport_set',
        'verification_set'
    ).first()

    if not patient:
        return render(request, 'patient_status.html', {'error': 'Patient not found or unauthorized'})

    # Fetch related data
    hospital_details = patient.hospitaldetails_set.first()
    assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
    medical_reports = hospital_details.medicalreport_set.all() if hospital_details else []
    verification = patient.verification_set.first()
    # Get PatientStatus via the relationship
    patient_status = patient.status if hasattr(patient, 'status') else None

    # Calculate percentage and days left using PatientStatus
    total_needed = patient_status.total_needed if patient_status and patient_status.total_needed else sum(a.amount_required or 0 for a in assistances if a.amount_required) or 1
    total_received = patient_status.total_received if patient_status and patient_status.total_received else sum(a.amount_received or 0 for a in assistances if a.amount_received) or 0
    percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0
    days_left = None
    if patient_status and patient_status.end_time:
        days_left = max(0, (patient_status.end_time - timezone.now()).days)

    # Generate shareable link
    share_link = request.build_absolute_uri(reverse('patient_status', args=[patient_id]))

    context = {
        'user': user,
        'patient': patient,
        'hospital_details': hospital_details,
        'assistances': assistances,
        'medical_reports': medical_reports,
        'verification': verification,
        'patient_status': patient_status,
        'percentage': percentage,
        'total_received': total_received,
        'total_needed': total_needed,
        'share_link': share_link,
        'days_left': days_left,
    }

    if 'download' in request.GET:
        # Generate image for download
        img = Image.new('RGB', (800, 800), color='white')  # Increased height for more content
        draw = ImageDraw.Draw(img)
        try:
            font = ImageFont.truetype("arial.ttf", 20)
            large_font = ImageFont.truetype("arial.ttf", 30)  # For patient name
        except:
            font = ImageFont.load_default()
            large_font = ImageFont.load_default()

        # Draw patient details
        y = 20
        # Patient Name
        draw.text((20, y), f"{patient.full_name}", font=large_font, fill='black')
        y += 50

        # Patient Photo (Using patient_photo as per your model)
        try:
            photo_path = patient.patient_photo.path
            photo = Image.open(photo_path).resize((200, 200), Image.LANCZOS)
            img.paste(photo, (20, y))
            y += 220  # Space for photo
        except (AttributeError, FileNotFoundError):
            draw.text((20, y), "No photo available", font=font, fill='gray')
            y += 40

        # Issue Facing
        draw.text((20, y), f"Issue: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
        y += 40

        # Days Left
        days_text = f"{days_left} days" if days_left is not None else "Not set"
        draw.text((20, y), f"Days Left: {days_text}", font=font, fill='black')
        y += 40

        # Patient ID
        draw.text((20, y), f"Patient ID: {patient.patient_id}", font=font, fill='black')
        y += 40

        # Location
        draw.text((20, y), f"Location: {hospital_details.hospital_location if hospital_details else 'N/A'}", font=font, fill='black')
        y += 40

        # Assistance Needed
        if assistances:
            draw.text((20, y), f"Assistance Needed: {assistances[0].assistance_type}", font=font, fill='black')
            y += 40
            if assistances[0].assistance_type == "Financial Aid":
                draw.text((20, y), f"Amount: {assistances[0].amount_required}", font=font, fill='black')
                y += 40
            elif assistances[0].assistance_type == "Blood Donation":
                draw.text((20, y), f"Blood Type: {assistances[0].blood_type}", font=font, fill='black')
                y += 40
                draw.text((20, y), f"Quantity: {assistances[0].quantity}", font=font, fill='black')
                y += 40
            elif assistances[0].assistance_type == "Other Resources":
                draw.text((20, y), f"Details: {assistances[0].description}", font=font, fill='black')
                y += 40

        # Share Link
        draw.text((20, y), "Donate at:", font=font, fill='black')
        y += 40
        draw.text((20, y), share_link, font=font, fill='black')

        # Save image to buffer
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Serve as downloadable file
        response = HttpResponse(buffer, content_type='image/png')
        response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
        return response

    return render(request, 'patient_status.html', context)

# def patient_status(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     patient = Patient.objects.filter(patient_id=patient_id, user=user).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set',
#         'hospitaldetails_set__medicalreport_set',
#         'verification_set',
#         'donation_status'
#     ).first()

#     if not patient:
#         return render(request, 'patient_status.html', {'error': 'Patient not found or unauthorized'})

#     # Fetch related data
#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     medical_reports = hospital_details.medicalreport_set.all() if hospital_details else []
#     verification = patient.verification_set.first()
#     donation_status = patient.donation_status if hasattr(patient, 'donation_status') else None

#     # Calculate percentage and days left
#     total_needed = sum(a.amount_required or 0 for a in assistances if a.amount_required) or 1  # Avoid division by 0
#     total_received = 1000 #sum(a.amount_received or 0 for a in assistances if a.amount_received) or 0
#     percentage = min((total_received / total_needed) * 100, 100) if total_needed > 0 else 0
#     days_left = None
#     if donation_status and donation_status.end_time:
#         days_left = max(0, (donation_status.end_time - timezone.now()).days)

#     # Generate shareable link
#     share_link = request.build_absolute_uri(reverse('patient_status', args=[patient_id]))

#     context = {
#         'user': user,
#         'patient': patient,
#         'hospital_details': hospital_details,
#         'assistances': assistances,
#         'medical_reports': medical_reports,
#         'verification': verification,
#         'donation_status': donation_status,
#         'percentage': percentage,
#         'total_received': total_received,
#         'total_needed': total_needed,
#         'share_link': share_link,
#         'days_left': days_left,
#     }

#     if 'download' in request.GET:
#         # Generate image for download
#         img = Image.new('RGB', (800, 800), color='white')  # Increased height for more content
#         draw = ImageDraw.Draw(img)
#         try:
#             font = ImageFont.truetype("arial.ttf", 20)
#             large_font = ImageFont.truetype("arial.ttf", 30)  # For patient name
#         except:
#             font = ImageFont.load_default()
#             large_font = ImageFont.load_default()

#         # Draw patient details
#         y = 20
#         # Patient Name
#         draw.text((20, y), f"{patient.full_name}", font=large_font, fill='black')
#         y += 50

#         # Patient Photo (Assuming a 'photo' field exists; adjust if not)
#         try:
#             photo_path = patient.patient_photo  # Adjust field name if different
#             photo = Image.open(photo_path).resize((200, 200), Image.LANCZOS)
#             img.paste(photo, (20, y))
#             y += 220  # Space for photo
#         except (AttributeError, FileNotFoundError):
#             draw.text((20, y), "No photo available", font=font, fill='gray')
#             y += 40

#         # Issue Facing
#         draw.text((20, y), f"Issue: {hospital_details.medical_problem if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40

#         # Days Left
#         days_text = f"{days_left} days" if days_left is not None else "Not set"
#         draw.text((20, y), f"Days Left: {days_text}", font=font, fill='black')
#         y += 40

#         # Patient ID
#         draw.text((20, y), f"Patient ID: {patient.patient_id}", font=font, fill='black')
#         y += 40

#         # Location
#         draw.text((20, y), f"Location: {hospital_details.hospital_location if hospital_details else 'N/A'}", font=font, fill='black')
#         y += 40

#         # Assistance Needed
#         if assistances:
#             draw.text((20, y), f"Assistance Needed: {assistances[0].assistance_type}", font=font, fill='black')
#             y += 40
#             if assistances[0].assistance_type == "Financial Aid":
#                 draw.text((20, y), f"Amount: {assistances[0].amount_required}", font=font, fill='black')
#                 y += 40
#             elif assistances[0].assistance_type == "Blood Donation":
#                 draw.text((20, y), f"Blood Type: {assistances[0].blood_type}", font=font, fill='black')
#                 y += 40
#                 draw.text((20, y), f"Quantity: {assistances[0].quantity}", font=font, fill='black')
#                 y += 40
#             elif assistances[0].assistance_type == "Other Resources":
#                 draw.text((20, y), f"Details: {assistances[0].description}", font=font, fill='black')
#                 y += 40

#         # Share Link
#         draw.text((20, y), "Donate at:", font=font, fill='black')
#         y += 40
#         draw.text((20, y), share_link, font=font, fill='black')

#         # Save image to buffer
#         buffer = io.BytesIO()
#         img.save(buffer, format="PNG")
#         buffer.seek(0)

#         # Serve as downloadable file
#         response = HttpResponse(buffer, content_type='image/png')
#         response['Content-Disposition'] = f'attachment; filename="patient_status_{patient_id}.png"'
#         return response

#     return render(request, 'patient_status.html', context)

from django.shortcuts import render, redirect
from .models import mainuser, CareCoin

def care_coins(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    if user.user_type not in ['donor', 'both']:
        return render(request, 'care_coins.html', {'error': 'Only donors can view Care-Coins'})

    # Fetch Care-Coin data
    coin_transactions = CareCoin.objects.filter(donor=user).order_by('-created_at')
    coin_balance = sum(t.coins if t.transaction_type == 'earned' else -t.coins for t in coin_transactions) or 0

    context = {
        'user': user,
        'coin_balance': coin_balance,
        'coin_transactions': coin_transactions,
    }
    return render(request, 'care_coins.html', context)






from django.shortcuts import render, redirect, HttpResponse
from django.utils import timezone
from django.urls import reverse
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin
from PIL import Image, ImageDraw, ImageFont
import io

# ... (Previous views like user_dashboard, donor_patient_detail remain unchanged)

# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     print(user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     print(hospital_details)
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     print(assistances)
#     print("1234565")
#     if request.method == 'POST':
#         print("not working...")
#         assistance_type = request.POST.get('assistance_type1')
#         print(assistance_type)
#         assistance = assistances.filter(assistance_type=assistance_type).first()
#         print(assistance)

#         if not assistance:
#             print("nbljkb;kv")
#             return render(request, 'donate_to_patient.html', {'error': 'Invalid assistance type selected', 'patient': patient, 'assistances': assistances})

#         if assistance_type == "Financial Aid":
#             amount = request.POST.get('amount')
#             print(amount)
#             if amount > 0:
#                 # Update CareCoin for donor
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='spent',
#                     coins=amount,  # Assuming 1 coin = 1 unit of currency; adjust as needed
#                     donation_type='funds',
#                     description=f"Donation to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 # Update AssistanceRequired
#                 assistance.amount_received = (assistance.amount_received or 0) + amount
#                 assistance.save()
#                 print("done.....")

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='spent',
#                     coins=50,  # Example: fixed coin value for blood donation; adjust as needed
#                     donation_type='blood',
#                     description=f"Donated {quantity} of {blood_type} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 # Update AssistanceRequired (assuming quantity is tracked elsewhere if needed)
#                 assistance.quantity = quantity  # Assuming quantity field can store this
#                 assistance.save()

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='spent',
#                     coins=20,  # Example: fixed coin value for other resources; adjust as needed
#                     donation_type='other',
#                     description=f"Donated {description} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 # Update AssistanceRequired (assuming description can be appended)
#                 assistance.description = f"{assistance.description or ''} | {description}"
#                 assistance.save()
        
#         print("....................")

#         return redirect('donor_patient_detail', patient_id=patient_id)
#     print("end...")
#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)
from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.db.models import Sum, Case, When, IntegerField, F
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin
from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.db.models import Sum, Case, When, IntegerField, F
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin

from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin

# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         print("POST Data:", request.POST)
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         print(f"Assistance Type: {assistance_type}, Assistance: {assistance}")

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))
#                 print(f"Amount entered: {amount}")
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })
#                 assistance.amount_received = (assistance.amount_received or 0) + amount
#                 assistance.save()
#                 print("Money donation processed, New amount_received:", assistance.amount_received)
#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=50,
#                     donation_type='blood',
#                     description=f"Donated {quantity} of {blood_type} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.quantity = quantity
#                 assistance.save()
#                 print("Blood donation processed")

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=20,
#                     donation_type='other',
#                     description=f"Donated {description} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.description = f"{assistance.description or ''} | {description}"
#                 assistance.save()
#                 print("Other resources donation processed")

#         return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin
import razorpay
import json

# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0)) * 100  # Convert to paise (Razorpay uses paise)
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 order_data = {
#                     'amount': amount,  # In paise
#                     'currency': 'INR',
#                     'payment_capture': 1,  # Auto-capture payment
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store order ID in session for verification
#                 request.session['razorpay_order_id'] = order['id']
#                 request.session['donation_amount'] = amount // 100  # Convert back to rupees
#                 request.session['assistance_id'] = assistance.assistance_id

#                 # Pass order details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount,
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',  # Take first UPI ID
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id]))
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=50,
#                     donation_type='blood',
#                     description=f"Donated {quantity} of {blood_type} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.quantity = quantity
#                 assistance.save()
#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=20,
#                     donation_type='other',
#                     description=f"Donated {description} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.description = f"{assistance.description or ''} | {description}"
#                 assistance.save()
#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)

# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         # Verify payment
#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             # Payment verified, update assistance
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('donation_amount')
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
#             assistance.amount_received = (assistance.amount_received or 0) + amount
#             assistance.save()
#             # Clean up session
#             del request.session['razorpay_order_id']
#             del request.session['donation_amount']
#             del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)  # Handle failure silently or log it

#     return redirect('donor_patient_detail', patient_id=patient_id)


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin
import razorpay

# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []
#     # request.session['assistance_id'] = 

#     if request.method == 'POST':
#         print("entered....")
#         assistance_type = request.POST.get('assistance_type')
#         print(assistance_type)
#         assistance = assistances.filter(assistance_type=assistance_type).first()
#         print(assistance)

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 print("11111111111")
#                 amount = int(request.POST.get('amount', 0)) * 100  # Convert to paise
#                 print(amount)
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 order_data = {
#                     'amount': amount,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 request.session['assistance_id'] = assistance.assistance_id
#                 request.session['amt'] = amount

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount,
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
#                     'is_payment': True  # Flag to show payment form
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=50,
#                     donation_type='blood',
#                     description=f"Donated {quantity} of {blood_type} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.quantity = quantity
#                 assistance.save()
#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=20,
#                     donation_type='other',
#                     description=f"Donated {description} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.description = f"{assistance.description or ''} | {description}"
#                 assistance.save()
#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)

# # def donation_callback(request, patient_id):
# #     if request.method == 'POST':
# #         payment_id = request.POST.get('razorpay_payment_id')
# #         order_id = request.POST.get('razorpay_order_id')
# #         signature = request.POST.get('razorpay_signature')

# #         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
# #         params_dict = {
# #             'razorpay_order_id': order_id,
# #             'razorpay_payment_id': payment_id,
# #             'razorpay_signature': signature
# #         }
# #         try:
# #             client.utility.verify_payment_signature(params_dict)
# #             assistance = AssistanceRequired.objects.get(assistance_id=request.session.get('assistance_id'))
# #             amount = request.session.get('donation_amount')
# #             assistance.amount_received = (assistance.amount_received)+ (amount)
# #             assistance.save()
# #             del request.session['razorpay_order_id']
# #             del request.session['donation_amount']
# #             del request.session['assistance_id']
# #             print("Payment successful, amount_received updated:", assistance.amount_received)
# #         except razorpay.errors.SignatureVerificationError:
# #             print("Payment verification failed")
# #             return redirect('donor_patient_detail', patient_id=patient_id)

# #     return redirect('donor_patient_detail', patient_id=patient_id)

# from django.shortcuts import redirect
# from django.conf import settings
# from django.urls import reverse
# import razorpay
# from .models import AssistanceRequired

# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         # Verify payment
#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             # Payment verified, update assistance
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('amt')  # Amount in rupees
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
            
#             # Handle None case for amount_received
#             current_received = assistance.amount_received if assistance.amount_received is not None else 0
#             print(current_received)
#             print(type(current_received))
#             print(amount)
#             print(type(amount))
            
#             current_received = current_received + amount
#             assistance.amount_received=current_received
            
#             assistance.save()

#             # Clean up session
#             # del request.session['razorpay_order_id']
#             # del request.session['donation_amount']
#             # del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)
#         except AssistanceRequired.DoesNotExist:
#             print("Assistance record not found")
#             return redirect('donor_patient_detail', patient_id=patient_id)

#     return redirect('donor_patient_detail', patient_id=patient_id)

from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin
import razorpay
from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin, DonationTransaction
import razorpay
import random

# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store assistance_id and amount (in rupees) in session
#                 request.session['assistance_id'] = assistance.assistance_id
#                 request.session['donation_amount'] = amount

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
#                     'is_payment': True
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for blood donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for other resources donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)

# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('donation_amount')  # Amount in rupees
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
#             user_id = request.session.get('user_id')
#             user = mainuser.objects.get(user_id=user_id)
#             patient = Patient.objects.get(patient_id=patient_id)

#             # Create donation transaction for funds
#             transaction = DonationTransaction.objects.create(
#                 donor=user,
#                 patient=patient,
#                 assistance=assistance,
#                 transaction_type='funds',
#                 amount=amount,
#                 status='completed'
#             )

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=transaction,
#                 description=f"Reward for funds donation to {patient.full_name}"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()

#             # Update assistance amount_received
#             current_received = assistance.amount_received if assistance.amount_received is not None else 0
#             assistance.amount_received = current_received + amount
#             assistance.save()

#             # Clean up session
#             # del request.session['razorpay_order_id']
#             # del request.session['donation_amount']
#             # del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)
#         except (AssistanceRequired.DoesNotExist, mainuser.DoesNotExist, Patient.DoesNotExist):
#             print("Record not found")
#             return redirect('donor_patient_detail', patient_id=patient_id)

#     return redirect('donor_patient_detail', patient_id=patient_id)


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin, DonationTransaction
import razorpay
import random


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin, DonationTransaction, PatientDonationStatus
import razorpay
import random

# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store assistance_id and amount (in rupees) in session
#                 request.session['assistance_id'] = assistance.assistance_id
#                 request.session['donation_amount'] = amount

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
#                     'is_payment': True
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for blood donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Get or create PatientDonationStatus for the patient
#                 try:
#                     patient_status = patient.donation_status
#                     if not patient_status:
#                         patient_status = PatientDonationStatus.objects.create(
#                             patient=patient,
#                             is_active=True
#                         )
#                 except PatientDonationStatus.DoesNotExist:
#                     patient_status = PatientDonationStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )

#                 # Check and update patient status
#                 if assistance.is_completed():
#                     patient_status.status = 'completed'
#                     patient_status.is_active = False
#                     patient_status.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for other resources donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Get or create PatientDonationStatus for the patient
#                 try:
#                     patient_status = patient.donation_status
#                     if not patient_status:
#                         patient_status = PatientDonationStatus.objects.create(
#                             patient=patient,
#                             is_active=True
#                         )
#                 except PatientDonationStatus.DoesNotExist:
#                     patient_status = PatientDonationStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )

#                 # Check and update patient status
#                 if assistance.is_completed():
#                     patient_status.status = 'completed'
#                     patient_status.is_active = False
#                     patient_status.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin, DonationTransaction, PatientStatus
import razorpay
import random



from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin, DonationTransaction, PatientStatus
import razorpay
import random


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, CareCoin, DonationTransaction, PatientStatus
import razorpay
import random

def donate_to_patient(request, patient_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    if user.user_type not in ['donor', 'both']:
        return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

    # Filter patient using PatientStatus for active status
    patient = Patient.objects.filter(
        patient_id=patient_id,
        status__is_active=True,
        status__status='active'
    ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()

    if not patient:
        return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

    hospital_details = patient.hospitaldetails_set.first()
    assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

    if request.method == 'POST':
        assistance_type = request.POST.get('assistance_type')
        assistance = assistances.filter(assistance_type=assistance_type).first()

        if not assistance:
            return render(request, 'donate_to_patient.html', {
                'error': 'Invalid assistance type selected',
                'patient': patient,
                'assistances': assistances
            })

        if assistance_type == "Financial Aid":
            try:
                amount = int(request.POST.get('amount', 0))  # Amount in rupees
                if amount <= 0:
                    return render(request, 'donate_to_patient.html', {
                        'error': 'Please enter a valid amount',
                        'patient': patient,
                        'assistances': assistances
                    })

                # Initialize Razorpay client
                client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

                # Create Razorpay order
                amount_in_paise = amount * 100  # Convert to paise
                order_data = {
                    'amount': amount_in_paise,
                    'currency': 'INR',
                    'payment_capture': 1,
                    'notes': {
                        'patient_id': patient_id,
                        'donor_id': user_id,
                    }
                }
                order = client.order.create(data=order_data)

                # Store assistance_id and amount (in rupees) in session
                request.session['assistance_id'] = assistance.assistance_id
                request.session['donation_amount'] = amount

                # Pass Razorpay details to template
                context = {
                    'user': user,
                    'patient': patient,
                    'assistances': assistances,
                    'razorpay_key_id': settings.RAZORPAY_KEY_ID,
                    'order_id': order['id'],
                    'amount': amount_in_paise,  # Pass to Razorpay in paise
                    'amount_in_rupees': amount,  # For display in rupees
                    'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
                    'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
                    'is_payment': True
                }
                return render(request, 'donate_to_patient.html', context)

            except ValueError:
                return render(request, 'donate_to_patient.html', {
                    'error': 'Invalid amount entered',
                    'patient': patient,
                    'assistances': assistances
                })

        elif assistance_type == "Blood Donation":
            blood_type = request.POST.get('blood_type')
            quantity = request.POST.get('quantity')
            if blood_type and quantity:
                # Create donation transaction
                transaction = DonationTransaction.objects.create(
                    donor=user,
                    patient=patient,
                    assistance=assistance,
                    transaction_type='blood',
                    blood_type=blood_type,
                    quantity=quantity,
                    status='completed'
                )

                # Award random Care-Coins (10 to 50)
                # care_coins = random.randint(10, 50)
                care_coins=random.randint(100, 150)

                CareCoin.objects.create(
                    donor=user,
                    coins=care_coins,
                    transaction_type='earned',
                    donation_transaction=transaction,
                    description=f"Reward for blood donation to {patient.full_name}"
                )
                transaction.care_coins_awarded = care_coins
                transaction.save()

                # Get or create PatientStatus for the patient
                try:
                    patient_status = patient.status
                    if not patient_status:
                        patient_status = PatientStatus.objects.create(
                            patient=patient,
                            is_active=True
                        )
                except PatientStatus.DoesNotExist:
                    patient_status = PatientStatus.objects.create(
                        patient=patient,
                        is_active=True
                    )

                # Update PatientStatus based on donation
                assistance = assistances.filter(assistance_type='Blood Donation').first()
                if assistance:
                    patient_status.total_received = 1 if assistance.quantity and assistance.quantity.strip() else 0
                    patient_status.total_needed = 1  # Placeholder for non-financial aid (adjust as needed)
                    patient_status.donation_percentage = 100 if patient_status.total_received else 0
                    if patient_status.total_received >= patient_status.total_needed:
                        patient_status.status = 'completed'
                        patient_status.is_active = False
                    patient_status.save()

                # Redirect to success page with transaction details
                success_context = {
                    'message': 'Transaction Successful!',
                    'care_coins_earned': care_coins,
                    'donation_details': f'{quantity} of {blood_type} blood to {patient.full_name}',
                    'donation_type': 'Blood Donation'
                }
                return render(request, 'donation_success.html', success_context)

        elif assistance_type == "Other Resources":
            description = request.POST.get('description')
            if description:
                # Create donation transaction
                transaction = DonationTransaction.objects.create(
                    donor=user,
                    patient=patient,
                    assistance=assistance,
                    transaction_type='other',
                    description=description,
                    status='completed'
                )

                # Award random Care-Coins (10 to 50)
                care_coins = random.randint(100, 150)
                CareCoin.objects.create(
                    donor=user,
                    coins=care_coins,
                    transaction_type='earned',
                    donation_transaction=transaction,
                    description=f"Reward for other resources donation to {patient.full_name}"
                )
                transaction.care_coins_awarded = care_coins
                transaction.save()

                # Get or create PatientStatus for the patient
                try:
                    patient_status = patient.status
                    if not patient_status:
                        patient_status = PatientStatus.objects.create(
                            patient=patient,
                            is_active=True
                        )
                except PatientStatus.DoesNotExist:
                    patient_status = PatientStatus.objects.create(
                        patient=patient,
                        is_active=True
                    )

                # Update PatientStatus based on donation
                assistance = assistances.filter(assistance_type='Other Resources').first()
                if assistance:
                    patient_status.total_received = 1 if assistance.description and assistance.description.strip() else 0
                    patient_status.total_needed = 1  # Placeholder for non-financial aid (adjust as needed)
                    patient_status.donation_percentage = 100 if patient_status.total_received else 0
                    if patient_status.total_received >= patient_status.total_needed:
                        patient_status.status = 'completed'
                        patient_status.is_active = False
                    patient_status.save()

                # Redirect to success page with transaction details
                success_context = {
                    'message': 'Transaction Successful!',
                    'care_coins_earned': care_coins,
                    'donation_details': f'{description} to {patient.full_name}',
                    'donation_type': 'Other Resources'
                }
                return render(request, 'donation_success.html', success_context)

    context = {
        'user': user,
        'patient': patient,
        'assistances': assistances,
    }
    return render(request, 'donate_to_patient.html', context)



def donation_success(request):
    # This view can be empty or handle additional logic if needed
    context = {
        'message': 'Transaction Successful!',
        'care_coins_earned': 0,  # Default, will be overridden by redirect
        'donation_details': '',  # Default, will be overridden by redirect
        'donation_type': '',     # Default, will be overridden by redirect
    }
    return render(request, 'donation_success.html', context)


# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     # Filter patient using PatientStatus for active status
#     patient = Patient.objects.filter(
#         patient_id=patient_id,
#         status__is_active=True,
#         status__status='active'
#     ).prefetch_related('hospitaldetails_set__assistancerequired_set').first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store assistance_id and amount (in rupees) in session
#                 request.session['assistance_id'] = assistance.assistance_id
#                 request.session['donation_amount'] = amount

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
#                     'is_payment': True
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for blood donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Get or create PatientStatus for the patient
#                 try:
#                     patient_status = patient.status
#                     if not patient_status:
#                         patient_status = PatientStatus.objects.create(
#                             patient=patient,
#                             is_active=True
#                         )
#                 except PatientStatus.DoesNotExist:
#                     patient_status = PatientStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )

#                 # Update PatientStatus based on donation
#                 assistance = assistances.filter(assistance_type='Blood Donation').first()
#                 if assistance:
#                     patient_status.total_received = 1 if assistance.quantity and assistance.quantity.strip() else 0
#                     patient_status.total_needed = 1  # Placeholder for non-financial aid (adjust as needed)
#                     patient_status.donation_percentage = 100 if patient_status.total_received else 0
#                     if patient_status.total_received >= patient_status.total_needed:
#                         patient_status.status = 'completed'
#                         patient_status.is_active = False
#                     patient_status.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for other resources donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Get or create PatientStatus for the patient
#                 try:
#                     patient_status = patient.status
#                     if not patient_status:
#                         patient_status = PatientStatus.objects.create(
#                             patient=patient,
#                             is_active=True
#                         )
#                 except PatientStatus.DoesNotExist:
#                     patient_status = PatientStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )

#                 # Update PatientStatus based on donation
#                 assistance = assistances.filter(assistance_type='Other Resources').first()
#                 if assistance:
#                     patient_status.total_received = 1 if assistance.description and assistance.description.strip() else 0
#                     patient_status.total_needed = 1  # Placeholder for non-financial aid (adjust as needed)
#                     patient_status.donation_percentage = 100 if patient_status.total_received else 0
#                     if patient_status.total_received >= patient_status.total_needed:
#                         patient_status.status = 'completed'
#                         patient_status.is_active = False
#                     patient_status.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)
# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, status__is_active=True, status__status='active').prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store assistance_id and amount (in rupees) in session
#                 request.session['assistance_id'] = assistance.assistance_id
#                 request.session['donation_amount'] = amount

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
#                     'is_payment': True
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for blood donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Get or create PatientStatus for the patient
#                 try:
#                     patient_status = patient.status
#                     if not patient_status:
#                         patient_status = PatientStatus.objects.create(
#                             patient=patient,
#                             is_active=True
#                         )
#                 except PatientStatus.DoesNotExist:
#                     patient_status = PatientStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )

#                 # Update and check patient status
#                 patient_status.update_status()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for other resources donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Get or create PatientStatus for the patient
#                 try:
#                     patient_status = patient.status
#                     if not patient_status:
#                         patient_status = PatientStatus.objects.create(
#                             patient=patient,
#                             is_active=True
#                         )
#                 except PatientStatus.DoesNotExist:
#                     patient_status = PatientStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )

#                 # Update and check patient status
#                 patient_status.update_status()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)

#### `donation_callback` View
# Update this view to query and update `PatientDonationStatus` via the relationship.

# # ```python
# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('donation_amount')  # Amount in rupees
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
#             user_id = request.session.get('user_id')
#             user = mainuser.objects.get(user_id=user_id)
#             patient = Patient.objects.get(patient_id=patient_id)

#             # Create donation transaction for funds
#             transaction = DonationTransaction.objects.create(
#                 donor=user,
#                 patient=patient,
#                 assistance=assistance,
#                 transaction_type='funds',
#                 amount=amount,
#                 status='completed'
#             )

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=transaction,
#                 description=f"Reward for funds donation to {patient.full_name}"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()

#             # Update assistance amount_received
#             current_received = assistance.amount_received if assistance.amount_received is not None else 0
#             assistance.amount_received = current_received + amount
#             assistance.save()

#             # Get or create PatientDonationStatus for the patient
#             try:
#                 patient_status = patient.donation_status
#                 if not patient_status:
#                     patient_status = PatientDonationStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )
#             except PatientDonationStatus.DoesNotExist:
#                 patient_status = PatientDonationStatus.objects.create(
#                     patient=patient,
#                     is_active=True
#                 )

#             # Check and update patient status for Financial Aid
#             if assistance.is_completed():
#                 patient_status.status = 'completed'
#                 patient_status.is_active = False
#                 patient_status.save()

#             # Clean up session
#             # del request.session['razorpay_order_id']
#             # del request.session['donation_amount']
#             # del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)
#         except (AssistanceRequired.DoesNotExist, mainuser.DoesNotExist, Patient.DoesNotExist):
#             print("Record not found")
#             return redirect('donor_patient_detail', patient_id=patient_id)

#     return redirect('donor_patient_detail', patient_id=patient_id)



def donation_callback(request, patient_id):
    if request.method == 'POST':
        payment_id = request.POST.get('razorpay_payment_id')
        order_id = request.POST.get('razorpay_order_id')
        signature = request.POST.get('razorpay_signature')

        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        try:
            client.utility.verify_payment_signature(params_dict)
            assistance_id = request.session.get('assistance_id')
            amount = request.session.get('donation_amount')  # Amount in rupees
            assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
            user_id = request.session.get('user_id')
            user = mainuser.objects.get(user_id=user_id)
            patient = Patient.objects.get(patient_id=patient_id)

            # Create donation transaction for funds
            transaction = DonationTransaction.objects.create(
                donor=user,
                patient=patient,
                assistance=assistance,
                transaction_type='funds',
                amount=amount,
                status='completed'
            )

            # Award random Care-Coins (10 to 50)
            if amount<100:
                care_coins=random.randint(1,50)
            else:
                care_coins = random.randint(100, amount)
                
            
            CareCoin.objects.create(
                donor=user,
                coins=care_coins,
                transaction_type='earned',
                donation_transaction=transaction,
                description=f"Reward for funds donation to {patient.full_name}"
            )
            transaction.care_coins_awarded = care_coins
            transaction.save()

            # Update assistance amount_received
            current_received = assistance.amount_received if assistance.amount_received is not None else 0
            assistance.amount_received = current_received + amount
            assistance.save()

            # Get or create PatientStatus for the patient
            try:
                patient_status = patient.status
                if not patient_status:
                    patient_status = PatientStatus.objects.create(
                        patient=patient,
                        is_active=True
                    )
            except PatientStatus.DoesNotExist:
                patient_status = PatientStatus.objects.create(
                    patient=patient,
                    is_active=True
                )

            # Update PatientStatus based on donation for Financial Aid
            if assistance.assistance_type == "Financial Aid":
                patient_status.total_needed = assistance.amount_required or 0
                patient_status.total_received = assistance.amount_received or 0
                patient_status.donation_percentage = min((patient_status.total_received / patient_status.total_needed) * 100, 100) if patient_status.total_needed > 0 else 0
                if patient_status.total_received >= patient_status.total_needed:
                    patient_status.status = 'completed'
                    patient_status.is_active = False
                patient_status.save()

            # Redirect to success page with transaction details
            success_context = {
                'message': 'Transaction Successful!',
                'care_coins_earned': care_coins,
                'donation_details': f'{amount} INR to {patient.full_name}',
                'donation_type': 'Financial Aid'
            }
            return render(request, 'donation_success.html', success_context)

        except razorpay.errors.SignatureVerificationError:
            print("Payment verification failed")
            return redirect('donor_patient_detail', patient_id=patient_id)
        except (AssistanceRequired.DoesNotExist, mainuser.DoesNotExist, Patient.DoesNotExist):
            print("Record not found")
            return redirect('donor_patient_detail', patient_id=patient_id)

    return redirect('donor_patient_detail', patient_id=patient_id)


# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('donation_amount')  # Amount in rupees
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
#             user_id = request.session.get('user_id')
#             user = mainuser.objects.get(user_id=user_id)
#             patient = Patient.objects.get(patient_id=patient_id)

#             # Create donation transaction for funds
#             transaction = DonationTransaction.objects.create(
#                 donor=user,
#                 patient=patient,
#                 assistance=assistance,
#                 transaction_type='funds',
#                 amount=amount,
#                 status='completed'
#             )

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=transaction,
#                 description=f"Reward for funds donation to {patient.full_name}"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()

#             # Update assistance amount_received
#             current_received = assistance.amount_received if assistance.amount_received is not None else 0
#             assistance.amount_received = current_received + amount
#             assistance.save()

#             # Get or create PatientStatus for the patient
#             try:
#                 patient_status = patient.status
#                 if not patient_status:
#                     patient_status = PatientStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )
#             except PatientStatus.DoesNotExist:
#                 patient_status = PatientStatus.objects.create(
#                     patient=patient,
#                     is_active=True
#                 )

#             # Update PatientStatus based on donation for Financial Aid
#             if assistance.assistance_type == "Financial Aid":
#                 patient_status.total_needed = assistance.amount_required or 0
#                 patient_status.total_received = assistance.amount_received or 0
#                 patient_status.donation_percentage = min((patient_status.total_received / patient_status.total_needed) * 100, 100) if patient_status.total_needed > 0 else 0
#                 if patient_status.total_received >= patient_status.total_needed:
#                     patient_status.status = 'completed'
#                     patient_status.is_active = False
#                 patient_status.save()

#             # Clean up session
#             # del request.session['razorpay_order_id']
#             # del request.session['donation_amount']
#             # del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)
#         except (AssistanceRequired.DoesNotExist, mainuser.DoesNotExist, Patient.DoesNotExist):
#             print("Record not found")
#             return redirect('donor_patient_detail', patient_id=patient_id)

#     return redirect('donor_patient_detail', patient_id=patient_id)

# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('donation_amount')  # Amount in rupees
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
#             user_id = request.session.get('user_id')
#             user = mainuser.objects.get(user_id=user_id)
#             patient = Patient.objects.get(patient_id=patient_id)

#             # Create donation transaction for funds
#             transaction = DonationTransaction.objects.create(
#                 donor=user,
#                 patient=patient,
#                 assistance=assistance,
#                 transaction_type='funds',
#                 amount=amount,
#                 status='completed'
#             )

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=transaction,
#                 description=f"Reward for funds donation to {patient.full_name}"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()

#             # Update assistance amount_received
#             current_received = assistance.amount_received if assistance.amount_received is not None else 0
#             assistance.amount_received = current_received + amount
#             assistance.save()

#             # Get or create PatientStatus for the patient
#             try:
#                 patient_status = patient.status
#                 if not patient_status:
#                     patient_status = PatientStatus.objects.create(
#                         patient=patient,
#                         is_active=True
#                     )
#             except PatientStatus.DoesNotExist:
#                 patient_status = PatientStatus.objects.create(
#                     patient=patient,
#                     is_active=True
#                 )

#             # Update and check patient status for Financial Aid
#             patient_status.update_status()

#             # Clean up session
#             # del request.session['razorpay_order_id']
#             # del request.session['donation_amount']
#             # del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)
#         except (AssistanceRequired.DoesNotExist, mainuser.DoesNotExist, Patient.DoesNotExist):
#             print("Record not found")
#             return redirect('donor_patient_detail', patient_id=patient_id)

#     return redirect('donor_patient_detail', patient_id=patient_id)
# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store assistance_id and amount (in rupees) in session
#                 request.session['assistance_id'] = assistance.assistance_id
#                 request.session['donation_amount'] = amount

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
#                     'is_payment': True
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for blood donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Check and update patient status
#                 patient_status = patient.donation_status
#                 if patient_status and assistance.is_completed():
#                     patient_status.status = 'completed'
#                     patient_status.is_active = False
#                     patient_status.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create donation transaction
#                 transaction = DonationTransaction.objects.create(
#                     donor=user,
#                     patient=patient,
#                     assistance=assistance,
#                     transaction_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=transaction,
#                     description=f"Reward for other resources donation to {patient.full_name}"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Check and update patient status
#                 patient_status = patient.donation_status
#                 if patient_status and assistance.is_completed():
#                     patient_status.status = 'completed'
#                     patient_status.is_active = False
#                     patient_status.save()

#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)

# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('donation_amount')  # Amount in rupees
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
#             user_id = request.session.get('user_id')
#             user = mainuser.objects.get(user_id=user_id)
#             patient = Patient.objects.get(patient_id=patient_id)

#             # Create donation transaction for funds
#             transaction = DonationTransaction.objects.create(
#                 donor=user,
#                 patient=patient,
#                 assistance=assistance,
#                 transaction_type='funds',
#                 amount=amount,
#                 status='completed'
#             )

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=transaction,
#                 description=f"Reward for funds donation to {patient.full_name}"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()

#             # Update assistance amount_received
#             current_received = assistance.amount_received if assistance.amount_received is not None else 0
#             assistance.amount_received = current_received + amount
#             assistance.save()

#             # Check and update patient status
#             patient_status = patient.donation_status
#             if patient_status and assistance.is_completed():
#                 patient_status.status = 'completed'
#                 patient_status.is_active = False
#                 patient_status.save()

#             # Clean up session
#             # del request.session['razorpay_order_id']
#             # del request.session['donation_amount']
#             # del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)
#         except (AssistanceRequired.DoesNotExist, mainuser.DoesNotExist, Patient.DoesNotExist):
#             print("Record not found")
#             return redirect('donor_patient_detail', patient_id=patient_id)

#     return redirect('donor_patient_detail', patient_id=patient_id)
# def donate_to_patient(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_patient.html', {'error': 'Only donors can donate'})

#     patient = Patient.objects.filter(patient_id=patient_id, donation_status__is_active=True).prefetch_related(
#         'hospitaldetails_set__assistancerequired_set'
#     ).first()

#     if not patient:
#         return render(request, 'donate_to_patient.html', {'error': 'Patient not found or inactive'})

#     hospital_details = patient.hospitaldetails_set.first()
#     assistances = hospital_details.assistancerequired_set.all() if hospital_details else []

#     if request.method == 'POST':
#         assistance_type = request.POST.get('assistance_type')
#         assistance = assistances.filter(assistance_type=assistance_type).first()

#         if not assistance:
#             return render(request, 'donate_to_patient.html', {
#                 'error': 'Invalid assistance type selected',
#                 'patient': patient,
#                 'assistances': assistances
#             })

#         if assistance_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_patient.html', {
#                         'error': 'Please enter a valid amount',
#                         'patient': patient,
#                         'assistances': assistances
#                     })

#                 # Convert to paise for Razorpay
#                 amount_in_paise = amount * 100

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 order_data = {
#                     'amount': amount_in_paise,  # In paise
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'patient_id': patient_id,
#                         'donor_id': user_id,
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store assistance_id and amount (in rupees) in session
#                 request.session['assistance_id'] = assistance.assistance_id
#                 request.session['donation_amount'] = amount  # Store in rupees

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'patient': patient,
#                     'assistances': assistances,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'upi_id': assistance.upi_ids.split(',')[0] if assistance.upi_ids else '',
#                     'callback_url': request.build_absolute_uri(reverse('donation_callback', args=[patient_id])),
#                     'is_payment': True
#                 }
#                 return render(request, 'donate_to_patient.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_patient.html', {
#                     'error': 'Invalid amount entered',
#                     'patient': patient,
#                     'assistances': assistances
#                 })

#         elif assistance_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=50,
#                     donation_type='blood',
#                     description=f"Donated {quantity} of {blood_type} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.quantity = quantity
#                 assistance.save()
#                 return redirect('donor_patient_detail', patient_id=patient_id)

#         elif assistance_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 CareCoin.objects.create(
#                     donor=user,
#                     transaction_type='earned',
#                     coins=20,
#                     donation_type='other',
#                     description=f"Donated {description} to Patient ID: {patient_id} ({patient.full_name})"
#                 )
#                 assistance.description = f"{assistance.description or ''} | {description}"
#                 assistance.save()
#                 return redirect('donor_patient_detail', patient_id=patient_id)

#     context = {
#         'user': user,
#         'patient': patient,
#         'assistances': assistances,
#     }
#     return render(request, 'donate_to_patient.html', context)

# def donation_callback(request, patient_id):
#     if request.method == 'POST':
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             client.utility.verify_payment_signature(params_dict)
#             assistance_id = request.session.get('assistance_id')
#             amount = request.session.get('donation_amount')  # Amount in rupees
#             assistance = AssistanceRequired.objects.get(assistance_id=assistance_id)
            
#             # Handle None case for amount_received and keep in rupees
#             current_received = assistance.amount_received if assistance.amount_received is not None else 0
#             assistance.amount_received = current_received + amount  # Amount is already in rupees
#             assistance.save()

#             # Clean up session
#             # del request.session['razorpay_order_id']
#             # del request.session['donation_amount']
#             # del request.session['assistance_id']
#             print("Payment successful, amount_received updated:", assistance.amount_received)
#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donor_patient_detail', patient_id=patient_id)
#         except AssistanceRequired.DoesNotExist:
#             print("Assistance record not found")
#             return redirect('donor_patient_detail', patient_id=patient_id)

#     return redirect('donor_patient_detail', patient_id=patient_id)





# views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.core.files.uploadedfile import InMemoryUploadedFile
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, MessageVerification

# def message_guard(request):
#     user_id = request.session.get('user_id')
#     user = mainuser.objects.get(user_id=user_id) if user_id else None

#     if request.method == 'POST':
#         patient_id_input = request.POST.get('patient_id', '')
#         issue_input = request.POST.get('issue', '')
#         message_image = request.FILES.get('message_image')

#         # Basic verification logic (simplified; enhance with AI/ML if needed)
#         patient = None
#         if patient_id_input:
#             patient = Patient.objects.filter(patient_id=patient_id_input).first()

#         verification = MessageVerification(
#             user=user,
#             patient=patient,
#             patient_id_input=patient_id_input,
#             issue_input=issue_input,
#             message_image=message_image
#         )

#         if not patient:
#             verification.status = 'fake'
#         else:
#             assistance = AssistanceRequired.objects.filter(hospital_details__patient=patient).first()
#             if assistance and assistance.amount_received and assistance.amount_received >= assistance.amount_required:
#                 verification.status = 'completed'
#             else:
#                 verification.status = 'active'

#         verification.save()
#         return redirect('message_guard_result', verification_id=verification.verification_id)

#     context = {
#         'user': user,
#     }
#     return render(request, 'message_guard.html', context)

# def message_guard_result(request, verification_id):
#     user_id = request.session.get('user_id')
#     user = mainuser.objects.get(user_id=user_id) if user_id else None

#     try:
#         verification = MessageVerification.objects.get(verification_id=verification_id)
#         patient = verification.patient
#         assistance = AssistanceRequired.objects.filter(hospital_details__patient=patient).first() if patient else None

#         context = {
#             'user': user,
#             'verification': verification,
#             'patient': patient,
#             'assistance': assistance,
#         }
#         if assistance and verification.status == 'active':
#             total_needed = assistance.amount_required or 1
#             total_received = assistance.amount_received or 0
#             context['percent_received'] = min((total_received / total_needed) * 100, 100)
#             context['percent_needed'] = 100 - context['percent_received']

#         return render(request, 'message_guard_result.html', context)
#     except MessageVerification.DoesNotExist:
#         return redirect('message_guard')



# views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.core.files.uploadedfile import InMemoryUploadedFile
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, MessageVerification
import pytesseract
from PIL import Image

# views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.core.files.uploadedfile import InMemoryUploadedFile
from .models import mainuser, Patient, HospitalDetails, AssistanceRequired, MessageVerification
import pytesseract
from PIL import Image
import re

def message_guard(request):
    user_id = request.session.get('user_id')
    user = mainuser.objects.get(user_id=user_id) if user_id else None

    if request.method == 'POST':
        patient_id_input = request.POST.get('patient_id', '').strip()
        issue_input = request.POST.get('issue', '').strip()
        message_image = request.FILES.get('message_image')

        extracted_patient_id = patient_id_input
        extracted_issue = issue_input

        # If image is uploaded and no details are provided, extract text
        if message_image and not (patient_id_input or issue_input):
            try:
                image = Image.open(message_image)
                extracted_text = pytesseract.image_to_string(image).strip()
                print("Full extracted text:", extracted_text)

                # Split into lines and clean
                lines = [line.strip() for line in extracted_text.split('\n') if line.strip()]
                print("Extracted lines:", lines)

                for line in lines:
                    # Use regex for more robust matching (case-insensitive)
                    patient_id_match = re.search(r'(?:patient\s*id|id)\s*:\s*(\d+)', line.lower())
                    issue_match = re.search(r'(?:issue|problem)\s*:\s*(.+)', line.lower())

                    if patient_id_match:
                        extracted_patient_id = patient_id_match.group(1)  # Get the number after "Patient ID:" or similar
                        print(f"Extracted Patient ID: {extracted_patient_id}")

                    if issue_match:
                        extracted_issue = issue_match.group(1).strip()  # Get text after "Issue:" or "Problem:"
                        print(f"Extracted Issue: {extracted_issue}")

            except Exception as e:
                print(f"OCR Error: {e}")
                return render(request, 'message_guard.html', {
                    'error': 'Failed to process the image. Please enter details manually.',
                    'user': user
                })

        print(f"Final extracted_patient_id: {extracted_patient_id}")
        # Basic verification logic
        patient = None
        if extracted_patient_id:
            try:
                patient = Patient.objects.get(patient_id=extracted_patient_id)  # Use get() for exact match
            except Patient.DoesNotExist:
                patient = None

        verification = MessageVerification(
            user=user,
            patient=patient,
            patient_id_input=extracted_patient_id,
            issue_input=extracted_issue,
            message_image=message_image
        )

        if not patient:
            verification.status = 'fake'
        else:
            assistance = AssistanceRequired.objects.filter(hospital_details__patient=patient).first()
            if assistance and assistance.amount_received and assistance.amount_received >= assistance.amount_required:
                verification.status = 'completed'
            else:
                verification.status = 'active'

        verification.save()
        return redirect('message_guard_result', verification_id=verification.verification_id)

    context = {
        'user': user,
    }
    return render(request, 'message_guard.html', context)
# def message_guard(request):
#     user_id = request.session.get('user_id')
#     user = mainuser.objects.get(user_id=user_id) if user_id else None

#     if request.method == 'POST':
#         patient_id_input = request.POST.get('patient_id', '').strip()
#         issue_input = request.POST.get('issue', '').strip()
#         message_image = request.FILES.get('message_image')

#         extracted_patient_id = patient_id_input
#         extracted_issue = issue_input

#         # If image is uploaded and no details are provided, extract text
#         if message_image and not (patient_id_input or issue_input):
#             try:
#                 image = Image.open(message_image)
#                 extracted_text = pytesseract.image_to_string(image).strip()
                

#                 # Simple extraction logic (assumes patient ID and issue are in text)
#                 lines = extracted_text.split('\n')
#                 print(lines)
#                 for line in lines:
#                     line = line.strip()
#                     if 'patient id' in line.lower() or 'id' in line.lower():
#                         # Extract potential patient ID (assuming format like "Patient ID: 123")
#                         parts = line.split(':')
#                         if len(parts) > 1:
#                             extracted_patient_id = parts[1].strip()
                            
#                     elif 'issue' in line.lower() or 'problem' in line.lower():
#                         # Extract potential issue
#                         parts = line.split(':')
#                         if len(parts) > 1:
#                             extracted_issue = parts[1].strip()

#             except Exception as e:
#                 print(f"OCR Error: {e}")
#                 return render(request, 'message_guard.html', {
#                     'error': 'Failed to process the image. Please enter details manually.',
#                     'user': user
#                 })
#         print("extracted_id===",extracted_patient_id)
#         # Basic verification logic
#         patient = None
#         if extracted_patient_id:
#             patient = Patient.objects.filter(patient_id=extracted_patient_id).first()

#         verification = MessageVerification(
#             user=user,
#             patient=patient,
#             patient_id_input=extracted_patient_id,
#             issue_input=extracted_issue,
#             message_image=message_image
#         )

#         if not patient:
#             verification.status = 'fake'
#         else:
#             assistance = AssistanceRequired.objects.filter(hospital_details__patient=patient).first()
#             if assistance and assistance.amount_received and assistance.amount_received >= assistance.amount_required:
#                 verification.status = 'completed'
#             else:
#                 verification.status = 'active'

#         verification.save()
#         return redirect('message_guard_result', verification_id=verification.verification_id)

#     context = {
#         'user': user,
#     }
#     return render(request, 'message_guard.html', context)

def message_guard_result(request, verification_id):
    user_id = request.session.get('user_id')
    user = mainuser.objects.get(user_id=user_id) if user_id else None

    try:
        verification = MessageVerification.objects.get(verification_id=verification_id)
        patient = verification.patient
        assistance = AssistanceRequired.objects.filter(hospital_details__patient=patient).first() if patient else None

        context = {
            'user': user,
            'verification': verification,
            'patient': patient,
            'assistance': assistance,
        }
        if assistance and verification.status == 'active':
            total_needed = assistance.amount_required or 1
            total_received = assistance.amount_received or 0
            context['percent_received'] = min((total_received / total_needed) * 100, 100)
            context['percent_needed'] = 100 - context['percent_received']

        return render(request, 'message_guard_result.html', context)
    except MessageVerification.DoesNotExist:
        return redirect('message_guard')
    
    
    


# views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from .models import mainuser, Patient, DonationTransaction, CareCoin

# def donor_donation_history(request):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donor_donation_history.html', {'error': 'Only donors can view donation history'})

#     # Fetch donor's donation transactions
#     donations = DonationTransaction.objects.filter(donor=user).order_by('-transaction_date')
    
#     # Fetch donor's Care-Coin history for rewards
#     care_coins = CareCoin.objects.filter(donor=user).order_by('-created_at')

#     context = {
#         'user': user,
#         'donations': donations,
#         'care_coins': care_coins,
#     }
#     return render(request, 'donor_donation_history.html', context)

# def patient_donation_history(request, patient_id):
#     user_id = request.session.get('user_id')
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     patient = Patient.objects.filter(patient_id=patient_id).first()

#     if not patient:
#         return render(request, 'patient_donation_history.html', {'error': 'Patient not found'})

#     # Fetch donations received by the patient
#     donations = DonationTransaction.objects.filter(patient=patient).order_by('-transaction_date')

#     context = {
#         'user': user,
#         'patient': patient,
#         'donations': donations,
#     }
#     return render(request, 'patient_donation_history.html', context)


def patient_donation_history(request, patient_id):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    patient = Patient.objects.filter(patient_id=patient_id).first()

    if not patient:
        return render(request, 'patient_donation_history.html', {'error': 'Patient not found'})

    # Fetch donations received by the patient
    donations = DonationTransaction.objects.filter(patient=patient).order_by('-transaction_date')

    context = {
        'user': user,
        'patient': patient,
        'donations': donations,
    }
    return render(request, 'patient_donation_history.html', context)


from django.shortcuts import render, redirect
from django.urls import reverse
from django.db.models import Sum
from .models import mainuser, Patient, DonationTransaction, CareCoin

def donor_donation_history(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    if user.user_type not in ['donor', 'both']:
        return render(request, 'donor_donation_history.html', {'error': 'Only donors can view donation history'})

    # Fetch donor's donation transactions
    donations = DonationTransaction.objects.filter(donor=user).order_by('-transaction_date')
    
    # Fetch donor's Care-Coin history for both earned and spent coins
    earned_coins = CareCoin.objects.filter(donor=user, transaction_type='earned').order_by('-created_at')
    spent_coins = CareCoin.objects.filter(donor=user, transaction_type='spent').order_by('-created_at')

    # Calculate total Care-Coin balance
    total_earned = CareCoin.objects.filter(donor=user, transaction_type='earned').aggregate(total=Sum('coins'))['total'] or 0
    total_spent = CareCoin.objects.filter(donor=user, transaction_type='spent').aggregate(total=Sum('coins'))['total'] or 0
    coin_balance = total_earned - total_spent

    context = {
        'user': user,
        'donations': donations,
        'earned_coins': earned_coins,
        'spent_coins': spent_coins,
        'coin_balance': coin_balance,
    }
    return render(request, 'donor_donation_history.html', context)



from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==",user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get total available resources in Care Storage
#     total_resources = CareStorageDonation.get_total_resources()
#     print(total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print(donation_type)

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==",amount)
#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': user_id,
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)

#                 # Store donation amount in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
#                     'is_payment': True
#                 }
#                 print("user context==",context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError:
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222")
#             client.utility.verify_payment_signature(params_dict)
#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             user_id = request.session.get('user_id')
#             user = mainuser.objects.get(user_id=user_id)

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=user,
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333")

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555")
#             # Clean up session
#             # del request.session['care_storage_amount']
#             # del request.session['donation_type']

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError:
#             print("Payment verification failed")
#             return redirect('donate_to_care_storage')
#         except (mainuser.DoesNotExist):
#             print("Donor not found")
#             return redirect('donate_to_care_storage')
#     print("fail...............")
#     return redirect('donate_to_care_storage')


from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get total available resources in Care Storage
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': user_id,
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['user_id'] = user_id  # Ensure user_id is in session for callback
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             user_id = request.session.get('user_id')
#             print("Session data:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'user_id': user_id
#             })

#             if not all([amount, donation_type, user_id]):
#                 raise ValueError("Missing session data for donation")

#             user = mainuser.objects.get(user_id=user_id)

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=user,
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['user_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except mainuser.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please log in again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return redirect('donate_to_care_storage')



# from django.shortcuts import render, redirect
# from django.urls import reverse
# from django.conf import settings
# from .models import mainuser, CareStorageDonation, CareCoin
# import razorpay
# import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get total available resources in Care Storage
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': user_id,
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['user_id'] = user_id  # Ensure user_id is in session for callback
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 callback_url = request.build_absolute_uri(reverse('care_storage_donation_callback'))
#                 print("Callback URL:", callback_url)
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': callback_url,
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             user_id = request.session.get('user_id')
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'user_id': user_id
#             })

#             if not all([amount, donation_type, user_id]):
#                 raise ValueError("Missing session data for donation")

#             user = mainuser.objects.get(user_id=user_id)

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=user,
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['user_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except mainuser.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please log in again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return redirect('donate_to_care_storage')


from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get total available resources in Care Storage
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': user_id,
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['user_id'] = user_id  # Ensure user_id is in session for callback
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 callback_url = request.build_absolute_uri(reverse('care_storage_donation_callback'))
#                 print("Callback URL:", callback_url)
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': callback_url,
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             user_id = request.session.get('user_id')
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'user_id': user_id
#             })

#             if not all([amount, donation_type, user_id]):
#                 raise ValueError("Missing session data for donation")

#             user = mainuser.objects.get(user_id=user_id)

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=user,
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['user_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except mainuser.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please log in again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })

from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor associated with this user
#     try:
#         donor = Donor.objects.get(user=user)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': donor_id,  # Use donor_id instead of user_id
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['donor_id'] = donor_id  # Store donor_id instead of user_id
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 callback_url = request.build_absolute_uri(reverse('care_storage_donation_callback'))
#                 print("Callback URL:", callback_url)
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': callback_url,
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor_id=user_id,  # Use donor object directly
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor_id=user_id,  # Use donor object directly
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             donor_id = request.session.get('donor_id')  # Use donor_id instead of user_id
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': donor_id
#             })

#             if not all([amount, donation_type, donor_id]):
#                 raise ValueError("Missing session data for donation")

#             donor = Donor.objects.get(donor_id=donor_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=donor,  # Use Donor object directly
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,  # Use mainuser for CareCoin, as per your model
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })

from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor associated with this user
#     try:
#         donor = Donor.objects.get(user=user)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': donor_id,  # Use donor_id instead of user_id
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['donor_id'] = donor_id  # Store donor_id instead of user_id
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 callback_url = request.build_absolute_uri(reverse('care_storage_donation_callback'))
#                 print("Callback URL:", callback_url)
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': callback_url,
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor_id=donor,  # Use donor object directly
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor_id=donor,  # Use donor object directly
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             donor_id = request.session.get('donor_id')  # Use donor_id instead of user_id
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': donor_id
#             })

#             if not all([amount, donation_type, donor_id]):
#                 raise ValueError("Missing session data for donation")

#             donor = Donor.objects.get(donor_id=donor_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=donor,  # Use Donor object directly
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,  # Use mainuser for CareCoin, as per your model
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })


from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor associated with this user
#     try:
#         donor = Donor.objects.get(user=user)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': donor_id,  # Use donor_id instead of user_id
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['donor_id'] = donor_id 
#                 request.session['user_id'] = user_id 
#                 # Store donor_id instead of user_id
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 callback_url = request.build_absolute_uri(reverse('care_storage_donation_callback'))
#                 print("Callback URL:", callback_url)
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': callback_url,
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor_id=user_id,  # Use donor object directly
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor_id=user_id,  # Use donor object directly
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             donor_id = request.session.get('donor_id')  # Use donor_id instead of user_id
#             user_id=request.session.get('user_id')
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': donor_id
#             })

#             if not all([amount, donation_type, donor_id]):
#                 raise ValueError("Missing session data for donation")

#             donor = Donor.objects.get(donor_id=donor_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=user_id,  # Use Donor object directly
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,  # Use mainuser for CareCoin, as per your model
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             # del request.session['care_storage_amount']
#             # del request.session['donation_type']
#             # del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random

from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor associated with this user
#     try:
#         donor = Donor.objects.get(user=user)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage for display
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         print("POST data received:", request.POST)  # Debug all POST data
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if not donation_type:
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Invalid donation type selected',
#                 'total_resources': total_resources,
#             })

#         if donation_type == "Financial Aid":
#             try:
#                 print("funds............")
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': donor_id,  # Use donor_id instead of user_id
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['user_id'] = user_id  # Store donor_id for callback
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,  # Use Donor object directly
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,  # Use Donor object directly
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             user_id = request.session.get('user_id')  # Use donor_id instead of user_id
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': user_id
#             })

#             if not all([amount, donation_type, user_id]):
#                 raise ValueError("Missing session data for donation")

#             donor = Donor.objects.get(user_id=user_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=user,  # Use Donor object directly
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,  # Use mainuser for CareCoin, as per your model
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })


from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
# import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor associated with this user
#     try:
#         donor = Donor.objects.get(user=user)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage for display
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if not donation_type:
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Invalid donation type selected',
#                 'total_resources': total_resources,
#             })

#         if donation_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': donor_id,  # Use donor_id instead of user_id
#                         'donation_type': 'financial aid',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['donor_id'] = donor_id  # Store donor_id for callback
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in rupees
#                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             if blood_type and quantity:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,  # Use Donor object directly
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             if description:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,  # Use Donor object directly
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,  # Use mainuser for CareCoin, as per your model
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,  # No direct DonationTransaction link
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page with transaction details
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)


# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             donor_id = request.session.get('donor_id')  # Use donor_id instead of user_id
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': donor_id
#             })

#             if not all([amount, donation_type, donor_id]):
#                 raise ValueError("Missing session data for donation")

#             donor = Donor.objects.get(donor_id=donor_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=donor,  # Use Donor object directly
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,  # Use mainuser for CareCoin, as per your model
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,  # No direct DonationTransaction link
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })

from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random
# views.py
from django.shortcuts import render, redirect
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor associated with this user
#     try:
#         donor = Donor.objects.get(user=user)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage for display
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         print("POST data received:", request.POST)  # Debug all POST data
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if not donation_type:
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Please select a valid donation type',
#                 'total_resources': total_resources,
#             })

#         if donation_type == "Financial Aid":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount greater than 0',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': user_id,
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['donor_id'] = user_id
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,
#                     'amount_in_rupees': amount,
#                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
#                     'is_payment': True
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             print("blood_type==", blood_type, "quantity==", quantity)
#             if not blood_type or not quantity:
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Blood type and quantity are required for Blood Donation',
#                     'total_resources': total_resources,
#                 })

#             try:
#                 # Validate quantity format (e.g., "500ml" or numeric)
#                 if not re.match(r'^\d+(ml)?$', quantity):
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Invalid quantity format. Use "500ml" or just numbers.',
#                         'total_resources': total_resources,
#                     })

#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#             except Exception as e:
#                 print("Error saving Blood Donation:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'Error processing Blood Donation: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             print("description==", description)
#             if not description:
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Description is required for Other Resources',
#                     'total_resources': total_resources,
#                 })

#             try:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=user,
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#             except Exception as e:
#                 print("Error saving Other Resources:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'Error processing Other Resources: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             donor_id = request.session.get('donor_id')
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': donor_id
#             })

#             if not all([amount, donation_type, donor_id]):
#                 raise ValueError("Missing session data for donation")

#             donor = Donor.objects.get(donor_id=donor_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=user,
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })


# views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random
import re

# def donate_to_care_storage(request):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor associated with this user
#     try:
#         donor = Donor.objects.get(user=user)
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage for display
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources)

#     if request.method == 'POST':
#         print("POST data received:", request.POST)  # Debug all POST data
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if not donation_type:
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Please select a valid donation type',
#                 'total_resources': total_resources,
#             })

#         if donation_type == "funds":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount greater than 0',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': donor_id,
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['donor_id'] = donor_id
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,  # Pass to Razorpay in paise
#                     'amount_in_rupees': amount,  # For display in template
#                     'user_full_name': user.full_name,
#                     'user_email': user.email,
#                     'user_phone_number': user.phone_number,
#                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Blood Donation":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             print("blood_type==", blood_type, "quantity==", quantity)
#             if not blood_type or not quantity:
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Blood type and quantity are required for Blood Donation',
#                     'total_resources': total_resources,
#                 })

#             try:
#                 # Validate quantity format (e.g., "500ml" or numeric)
#                 if not re.match(r'^\d+(ml)?$', quantity):
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Invalid quantity format. Use "500ml" or just numbers.',
#                         'total_resources': total_resources,
#                     })

#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=donor,
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,
#                     description=f"Reward for blood donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#             except Exception as e:
#                 print("Error saving Blood Donation:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'Error processing Blood Donation: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "Other Resources":
#             description = request.POST.get('description')
#             print("description==", description)
#             if not description:
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Description is required for Other Resources',
#                     'total_resources': total_resources,
#                 })

#             try:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=donor,
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50)
#                 care_coins = random.randint(10, 50)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_transaction=None,
#                     description=f"Reward for other resources donation to Care Storage"
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#             except Exception as e:
#                 print("Error saving Other Resources:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'Error processing Other Resources: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# # def donate_to_care_storage(request):
# #     user_id = request.session.get('user_id')
# #     print("user_id==", user_id)
# #     if not user_id:
# #         return redirect('user_loginpage')

# #     user = mainuser.objects.get(user_id=user_id)
# #     if user.user_type not in ['donor', 'both']:
# #         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

# #     # Get the donor associated with this user
# #     try:
# #         donor = Donor.objects.get(user=user)
# #         donor_id = donor.donor_id
# #     except Donor.DoesNotExist:
# #         return render(request, 'donate_to_care_storage.html', {
# #             'error': 'Donor profile not found. Please create a donor profile first.',
# #             'total_resources': CareStorageDonation.get_total_resources(),
# #         })

# #     # Get total available resources in Care Storage for display
# #     total_resources = CareStorageDonation.get_total_resources()
# #     print("total_resources==", total_resources)

# #     if request.method == 'POST':
# #         print("POST data received:", request.POST)  # Debug all POST data
# #         donation_type = request.POST.get('donation_type')
# #         print("donation_type==", donation_type)

# #         if not donation_type:
# #             return render(request, 'donate_to_care_storage.html', {
# #                 'error': 'Please select a valid donation type',
# #                 'total_resources': total_resources,
# #             })

# #         if donation_type == "Financial Aid":
# #             try:
# #                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
# #                 if amount <= 0:
# #                     return render(request, 'donate_to_care_storage.html', {
# #                         'error': 'Please enter a valid amount greater than 0',
# #                         'total_resources': total_resources,
# #                     })
# #                 print("amount==", amount)

# #                 # Initialize Razorpay client
# #                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

# #                 # Create Razorpay order
# #                 amount_in_paise = amount * 100  # Convert to paise
# #                 order_data = {
# #                     'amount': amount_in_paise,
# #                     'currency': 'INR',
# #                     'payment_capture': 1,
# #                     'notes': {
# #                         'donor_id': donor_id,
# #                         'donation_type': 'funds',
# #                     }
# #                 }
# #                 order = client.order.create(data=order_data)
# #                 print("Razorpay order created:", order)

# #                 # Store donation details in session
# #                 request.session['care_storage_amount'] = amount
# #                 request.session['donation_type'] = donation_type
# #                 request.session['donor_id'] = donor_id
# #                 print("Session data set:", request.session.items())

# #                 # Pass Razorpay details to template
# #                 context = {
# #                     'user': user,
# #                     'total_resources': total_resources,
# #                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
# #                     'order_id': order['id'],
# #                     'amount': amount_in_paise,
# #                     'amount_in_rupees': amount,
# #                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
# #                     'is_payment': True
# #                 }
# #                 print("user context==", context)
# #                 return render(request, 'donate_to_care_storage.html', context)

# #             except ValueError as e:
# #                 print("ValueError:", e)
# #                 return render(request, 'donate_to_care_storage.html', {
# #                     'error': 'Invalid amount entered',
# #                     'total_resources': total_resources,
# #                 })
# #             except Exception as e:
# #                 print("Unexpected error in Financial Aid:", e)
# #                 return render(request, 'donate_to_care_storage.html', {
# #                     'error': f'An error occurred: {str(e)}',
# #                     'total_resources': total_resources,
# #                 })

# #         elif donation_type == "Blood Donation":
# #             blood_type = request.POST.get('blood_type')
# #             quantity = request.POST.get('quantity')
# #             print("blood_type==", blood_type, "quantity==", quantity)
# #             if not blood_type or not quantity:
# #                 return render(request, 'donate_to_care_storage.html', {
# #                     'error': 'Blood type and quantity are required for Blood Donation',
# #                     'total_resources': total_resources,
# #                 })

# #             try:
# #                 # Validate quantity format (e.g., "500ml" or numeric)
# #                 if not re.match(r'^\d+(ml)?$', quantity):
# #                     return render(request, 'donate_to_care_storage.html', {
# #                         'error': 'Invalid quantity format. Use "500ml" or just numbers.',
# #                         'total_resources': total_resources,
# #                     })

# #                 # Create Care Storage donation transaction
# #                 transaction = CareStorageDonation.objects.create(
# #                     donor=donor,
# #                     donation_type='blood',
# #                     blood_type=blood_type,
# #                     quantity=quantity,
# #                     status='completed'
# #                 )

# #                 # Award random Care-Coins (10 to 50)
# #                 care_coins = random.randint(10, 50)
# #                 CareCoin.objects.create(
# #                     donor=user,
# #                     coins=care_coins,
# #                     transaction_type='earned',
# #                     donation_transaction=None,
# #                     description=f"Reward for blood donation to Care Storage"
# #                 )
# #                 transaction.care_coins_awarded = care_coins
# #                 transaction.save()
# #                 print("Blood donation saved:", transaction)

# #                 # Redirect to success page
# #                 success_context = {
# #                     'message': 'Transaction Successful!',
# #                     'care_coins_earned': care_coins,
# #                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
# #                     'donation_type': 'Blood Donation'
# #                 }
# #                 return render(request, 'donation_success.html', success_context)

# #             except Exception as e:
# #                 print("Error saving Blood Donation:", e)
# #                 return render(request, 'donate_to_care_storage.html', {
# #                     'error': f'Error processing Blood Donation: {str(e)}',
# #                     'total_resources': total_resources,
# #                 })

# #         elif donation_type == "Other Resources":
# #             description = request.POST.get('description')
# #             print("description==", description)
# #             if not description:
# #                 return render(request, 'donate_to_care_storage.html', {
# #                     'error': 'Description is required for Other Resources',
# #                     'total_resources': total_resources,
# #                 })

# #             try:
# #                 # Create Care Storage donation transaction
# #                 transaction = CareStorageDonation.objects.create(
# #                     donor=donor,
# #                     donation_type='other',
# #                     description=description,
# #                     status='completed'
# #                 )

# #                 # Award random Care-Coins (10 to 50)
# #                 care_coins = random.randint(10, 50)
# #                 CareCoin.objects.create(
# #                     donor=user,
# #                     coins=care_coins,
# #                     transaction_type='earned',
# #                     donation_transaction=None,
# #                     description=f"Reward for other resources donation to Care Storage"
# #                 )
# #                 transaction.care_coins_awarded = care_coins
# #                 transaction.save()
# #                 print("Other resources donation saved:", transaction)

# #                 # Redirect to success page
# #                 success_context = {
# #                     'message': 'Transaction Successful!',
# #                     'care_coins_earned': care_coins,
# #                     'donation_details': f'{description} to Care Storage',
# #                     'donation_type': 'Other Resources'
# #                 }
# #                 return render(request, 'donation_success.html', success_context)

# #             except Exception as e:
# #                 print("Error saving Other Resources:", e)
# #                 return render(request, 'donate_to_care_storage.html', {
# #                     'error': f'Error processing Other Resources: {str(e)}',
# #                     'total_resources': total_resources,
# #                 })

# #     context = {
# #         'user': user,
# #         'total_resources': total_resources,
# #     }
# #     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             donor_id = request.session.get('donor_id')
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': donor_id
#             })

#             if not all([amount, donation_type, donor_id]):
#                 raise ValueError("Missing session data for donation")

#             donor = Donor.objects.get(donor_id=donor_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=donor,
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50)
#             care_coins = random.randint(10, 50)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_transaction=None,
#                 description=f"Reward for funds donation to Care Storage"
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#             })
#     print("fail............... - Redirecting to donation page")
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#     })



# views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
from django.core.validators import MinValueValidator
import razorpay
import random
import re

# def donate_to_care_storage(request, donor_id=None):
#     user_id = request.session.get('user_id')
#     print("user_id==", user_id)
#     if not user_id:
#         return redirect('user_loginpage')

#     user = mainuser.objects.get(user_id=user_id)
#     if user.user_type not in ['donor', 'both']:
#         return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

#     # Get the donor using donor_id from URL or session
#     try:
#         if donor_id:
#             donor = Donor.objects.get(donor_id=donor_id)
#         else:
#             donor = Donor.objects.get(user=user)  # Fallback to session-based donor
#         donor_id = donor.donor_id
#     except Donor.DoesNotExist:
#         return render(request, 'donate_to_care_storage.html', {
#             'error': 'Donor profile not found. Please create a donor profile first.',
#             'total_resources': CareStorageDonation.get_total_resources(),
#         })

#     # Get total available resources in Care Storage for display
#     total_resources = CareStorageDonation.get_total_resources()
#     print("total_resources==", total_resources, "for donor_id:", donor_id)

#     if request.method == 'POST':
#         print("POST data received:", request.POST)  # Debug all POST data
#         donation_type = request.POST.get('donation_type')
#         print("donation_type==", donation_type)

#         if not donation_type:
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Please select a valid donation type',
#                 'total_resources': total_resources,
#             })

#         if donation_type == "funds":
#             try:
#                 amount = int(request.POST.get('amount', 0))  # Amount in rupees
#                 if amount <= 0:
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Please enter a valid amount greater than 0',
#                         'total_resources': total_resources,
#                     })
#                 print("amount==", amount)

#                 # Initialize Razorpay client
#                 client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

#                 # Create Razorpay order
#                 amount_in_paise = amount * 100  # Convert to paise
#                 order_data = {
#                     'amount': amount_in_paise,
#                     'currency': 'INR',
#                     'payment_capture': 1,
#                     'notes': {
#                         'donor_id': donor_id,
#                         'donation_type': 'funds',
#                     }
#                 }
#                 order = client.order.create(data=order_data)
#                 print("Razorpay order created:", order)

#                 # Store donation details in session
#                 request.session['care_storage_amount'] = amount
#                 request.session['donation_type'] = donation_type
#                 request.session['donor_id'] = donor_id
#                 print("Session data set:", request.session.items())

#                 # Pass Razorpay details to template
#                 context = {
#                     'user': user,
#                     'total_resources': total_resources,
#                     'razorpay_key_id': settings.RAZORPAY_KEY_ID,
#                     'order_id': order['id'],
#                     'amount': amount_in_paise,
#                     'amount_in_rupees': amount,
#                     'user_full_name': user.full_name,
#                     'user_email': user.email,
#                     'user_phone_number': user.phone_number,
#                     'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback', kwargs={'donor_id': donor_id})),
#                     'is_payment': True,
#                     'donor_id': donor_id  # Pass donor_id to template for URL
#                 }
#                 print("user context==", context)
#                 return render(request, 'donate_to_care_storage.html', context)

#             except ValueError as e:
#                 print("ValueError:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Invalid amount entered',
#                     'total_resources': total_resources,
#                 })
#             except Exception as e:
#                 print("Unexpected error in Financial Aid:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'An error occurred: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "blood":
#             blood_type = request.POST.get('blood_type')
#             quantity = request.POST.get('quantity')
#             print("blood_type==", blood_type, "quantity==", quantity)
#             if not blood_type or not quantity:
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Blood type and quantity are required for Blood Donation',
#                     'total_resources': total_resources,
#                 })

#             try:
#                 # Validate quantity format (e.g., "500ml" or numeric)
#                 if not re.match(r'^\d+(ml)?$', quantity):
#                     return render(request, 'donate_to_care_storage.html', {
#                         'error': 'Invalid quantity format. Use "500ml" or just numbers.',
#                         'total_resources': total_resources,
#                     })

#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=donor,
#                     donation_type='blood',
#                     blood_type=blood_type,
#                     quantity=quantity,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50, ensuring minimum 1 as per CareCoin model)
#                 care_coins = max(random.randint(10, 50), 1)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_type='blood',
#                     description=f"Reward for blood donation to Care Storage",
#                     donation_transaction=None  # No DonationTransaction link as per model
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Blood donation saved:", transaction)

#                 # Redirect to success page
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
#                     'donation_type': 'Blood Donation'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#             except Exception as e:
#                 print("Error saving Blood Donation:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'Error processing Blood Donation: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#         elif donation_type == "other":
#             description = request.POST.get('description')
#             print("description==", description)
#             if not description:
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': 'Description is required for Other Resources',
#                     'total_resources': total_resources,
#                 })

#             try:
#                 # Create Care Storage donation transaction
#                 transaction = CareStorageDonation.objects.create(
#                     donor=donor,
#                     donation_type='other',
#                     description=description,
#                     status='completed'
#                 )

#                 # Award random Care-Coins (10 to 50, ensuring minimum 1 as per CareCoin model)
#                 care_coins = max(random.randint(10, 50), 1)
#                 CareCoin.objects.create(
#                     donor=user,
#                     coins=care_coins,
#                     transaction_type='earned',
#                     donation_type='other',
#                     description=f"Reward for other resources donation to Care Storage",
#                     donation_transaction=None  # No DonationTransaction link as per model
#                 )
#                 transaction.care_coins_awarded = care_coins
#                 transaction.save()
#                 print("Other resources donation saved:", transaction)

#                 # Redirect to success page
#                 success_context = {
#                     'message': 'Transaction Successful!',
#                     'care_coins_earned': care_coins,
#                     'donation_details': f'{description} to Care Storage',
#                     'donation_type': 'Other Resources'
#                 }
#                 return render(request, 'donation_success.html', success_context)

#             except Exception as e:
#                 print("Error saving Other Resources:", e)
#                 return render(request, 'donate_to_care_storage.html', {
#                     'error': f'Error processing Other Resources: {str(e)}',
#                     'total_resources': total_resources,
#                 })

#     context = {
#         'user': user,
#         'total_resources': total_resources,
#         'donor_id': donor_id  # Pass donor_id to template for URL
#     }
#     return render(request, 'donate_to_care_storage.html', context)

# def care_storage_donation_callback(request, donor_id):
#     if request.method == 'POST':
#         print("1111111111 - Callback started for donor_id:", donor_id)
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment data missing. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#                 'donor_id': donor_id
#             })

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             session_donor_id = request.session.get('donor_id')
#             print("Session data retrieved:", {
#                 'amount': amount,
#                 'donation_type': donation_type,
#                 'donor_id': session_donor_id
#             })

#             if not all([amount, donation_type, session_donor_id]):
#                 raise ValueError("Missing session data for donation")

#             if int(session_donor_id) != int(donor_id):
#                 raise ValueError("Donor ID mismatch between URL and session")

#             donor = Donor.objects.get(donor_id=donor_id)
#             user = donor.user  # Get the mainuser from Donor for CareCoin

#             # Create Care Storage donation transaction for funds
#             transaction = CareStorageDonation.objects.create(
#                 donor=donor,
#                 donation_type='funds',
#                 amount=amount,
#                 status='completed'
#             )
#             print("33333333333 - Transaction created:", transaction)

#             # Award random Care-Coins (10 to 50, ensuring minimum 1 as per CareCoin model)
#             care_coins = max(random.randint(10, 50), 1)
#             CareCoin.objects.create(
#                 donor=user,
#                 coins=care_coins,
#                 transaction_type='earned',
#                 donation_type='funds',
#                 description=f"Reward for funds donation to Care Storage",
#                 donation_transaction=None  # No DonationTransaction link as per model
#             )
#             transaction.care_coins_awarded = care_coins
#             transaction.save()
#             print("55555555555 - Care-Coins awarded and transaction saved")

#             # Clean up session
#             del request.session['care_storage_amount']
#             del request.session['donation_type']
#             del request.session['donor_id']
#             print("Session cleaned up")

#             # Redirect to success page with transaction details
#             success_context = {
#                 'message': 'Transaction Successful!',
#                 'care_coins_earned': care_coins,
#                 'donation_details': f'{amount} INR to Care Storage',
#                 'donation_type': 'Financial Aid'
#             }
#             print("666666666 - Rendering success page")
#             return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Payment verification failed. Please try again.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#                 'donor_id': donor_id
#             })
#         except ValueError as e:
#             print("ValueError in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'Invalid data or donor mismatch: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#                 'donor_id': donor_id
#             })
#         except Donor.DoesNotExist as e:
#             print("Donor not found:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': 'Donor not found. Please create a donor profile first.',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#                 'donor_id': donor_id
#             })
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return render(request, 'donate_to_care_storage.html', {
#                 'error': f'An unexpected error occurred: {str(e)}',
#                 'total_resources': CareStorageDonation.get_total_resources(),
#                 'donor_id': donor_id
#             })
#     print("fail............... - Redirecting to donation page for donor_id:", donor_id)
#     return render(request, 'donate_to_care_storage.html', {
#         'error': 'Invalid request method or payment failed.',
#         'total_resources': CareStorageDonation.get_total_resources(),
#         'donor_id': donor_id
#     })


# views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.conf import settings
from .models import mainuser, CareStorageDonation, CareCoin, Donor
import razorpay
import random

def donate_to_care_storage(request):
    user_id = request.session.get('user_id')
    print("user_id==", user_id)
    if not user_id:
        return redirect('user_loginpage')

    user = mainuser.objects.get(user_id=user_id)
    if user.user_type not in ['donor', 'both']:
        return render(request, 'donate_to_care_storage.html', {'error': 'Only donors can donate'})

    # Get the Donor instance associated with the user
    try:
        donor = Donor.objects.get(user=user)
        donor_id=donor.donor_id
    except Donor.DoesNotExist:
        return render(request, 'donate_to_care_storage.html', {
            'error': 'Donor profile not found. Please create a donor profile first.',
        })

    # Get total available resources in Care Storage
    total_resources = CareStorageDonation.get_total_resources()
    print("total_resources==", total_resources)

    if request.method == 'POST':
        donation_type = request.POST.get('donation_type')
        print("donation_type==", donation_type)
        print("type of  donation_type===",type(donation_type))
        if donation_type=="":
            amount = request.session.pop('care_storage_amount', None)
            donor_id = request.session.pop('donor_id', None)
            user = mainuser.objects.get(user_id=request.session.get('user_id'))
            print("entered.....good news...!")
            donor = Donor.objects.get(donor_id=donor_id)

            # Create Care Storage donation transaction for funds using Donor instance
            transaction = CareStorageDonation.objects.create(
                donor=donor,  # Use Donor instance
                donation_type='funds',
                amount=amount,
                status='completed'
            )
            print("33333333333 - Transaction created:", transaction)
            if amount<100:
                care_coins = random.randint(10,50)
            else:
                care_coins = random.randint(100, int(amount/100))
            CareCoin.objects.create(
                donor=user,  # CareCoin uses mainuser as per your model
                coins=care_coins,
                transaction_type='earned',
                donation_transaction=None,  # No direct DonationTransaction link
                description=f"Reward for funds donation to Care Storage"
            )
            transaction.care_coins_awarded = care_coins
            transaction.save()
            print("55555555555 - Care-Coins awarded and transaction saved")

            # Clean up session
            # del request.session['care_storage_amount']
            # del request.session['donation_type']
            # del request.session['donor_id']
            print("Session cleaned up")

            # Redirect to success page with transaction details
            success_context = {
                'message': 'Transaction Successful!',
                'care_coins_earned': care_coins,
                'donation_details': f'{amount} INR to Care Storage',
                'donation_type': 'Financial Aid'
            }
            print("666666666 - Rendering success page")
            return render(request, 'donation_success.html', success_context)

        if donation_type == "Financial Aid":
            try:
                print("funds............")
                amount = int(request.POST.get('amount', 0))  # Amount in rupees
                if amount <= 0:
                    return render(request, 'donate_to_care_storage.html', {
                        'error': 'Please enter a valid amount',
                        'total_resources': total_resources,
                    })
                print("amount==", amount)
                # Initialize Razorpay client
                client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

                # Create Razorpay order
                amount_in_paise = amount * 100  # Convert to paise
                order_data = {
                    'amount': amount_in_paise,
                    'currency': 'INR',
                    'payment_capture': 1,
                    'notes': {
                        'donor_id': donor.donor_id,
                        'donation_type': 'funds',
                    }
                }
                order = client.order.create(data=order_data)
                print("Razorpay order created:", order)

                # Store donation amount in session
                request.session['care_storage_amount'] = amount
                request.session['donation_type'] = donation_type
                request.session['donor_id'] = donor.donor_id  # Store donor_id for callback

                # Pass Razorpay details to template
                context = {
                    'user': user,
                    'total_resources': total_resources,
                    'razorpay_key_id': settings.RAZORPAY_KEY_ID,
                    'order_id': order['id'],
                    'amount': amount_in_paise,  # Pass to Razorpay in paise
                    'amount_in_rupees': amount,  # For display in rupees
                    'callback_url': request.build_absolute_uri(reverse('care_storage_donation_callback')),
                    'is_payment': True,
                    'donor_id': donor.donor_id  # Pass donor_id to template
                }
                print("user context==", context)
                
                donor = Donor.objects.get(donor_id=donor_id)

            # # Create Care Storage donation transaction for funds using Donor instance
            #     transaction = CareStorageDonation.objects.create(
            #     donor=donor,  # Use Donor instance
            #     donation_type='funds',
            #     amount=amount,
            #     status='completed'
            # )
            #     print("33333333333 - Transaction created:", transaction)

            # # Award random Care-Coins (10 to 50)
            #     care_coins = random.randint(10, 50)
            #     CareCoin.objects.create(
            #     donor=user,  # CareCoin uses mainuser as per your model
            #     coins=care_coins,
            #     transaction_type='earned',
            #     donation_transaction=None,  # No direct DonationTransaction link
            #     description=f"Reward for funds donation to Care Storage"
            # )
            #     transaction.care_coins_awarded = care_coins
            #     transaction.save()
                
            #     success_context = {
            #     'message': 'Transaction Successful!',
            #     'care_coins_earned': care_coins,
            #     'donation_details': f'{amount} INR to Care Storage',
            #     'donation_type': 'Financial Aid'
            # }
            #     print("666666666 - Rendering success page")
            #     return render(request, 'donation_success.html', success_context)
                return render(request, 'donate_to_care_storage.html', context)

            except ValueError as e:
                print("ValueError:", e)
                return render(request, 'donate_to_care_storage.html', {
                    'error': 'Invalid amount entered',
                    'total_resources': total_resources,
                })
            except Exception as e:
                print("Unexpected error in Financial Aid:", e)
                return render(request, 'donate_to_care_storage.html', {
                    'error': f'An error occurred: {str(e)}',
                    'total_resources': total_resources,
                })
        
            
        elif donation_type == "Blood Donation":
            blood_type = request.POST.get('blood_type')
            quantity = request.POST.get('quantity')
            if blood_type and quantity:
                # Create Care Storage donation transaction using Donor instance
                transaction = CareStorageDonation.objects.create(
                    donor=donor,  # Use Donor instance instead of user
                    donation_type='blood',
                    blood_type=blood_type,
                    quantity=quantity,
                    status='completed'
                )

                # Award random Care-Coins (10 to 50)
                care_coins = random.randint(100, 150)
                CareCoin.objects.create(
                    donor=user,  # CareCoin uses mainuser as per your model
                    coins=care_coins,
                    transaction_type='earned',
                    donation_transaction=None,  # No direct DonationTransaction link
                    description=f"Reward for blood donation to Care Storage"
                )
                transaction.care_coins_awarded = care_coins
                transaction.save()
                print("Blood donation saved:", transaction)

                # Redirect to success page with transaction details
                success_context = {
                    'message': 'Transaction Successful!',
                    'care_coins_earned': care_coins,
                    'donation_details': f'{quantity} of {blood_type} blood to Care Storage',
                    'donation_type': 'Blood Donation'
                }
                return render(request, 'donation_success.html', success_context)
            else:
                return render(request, 'donate_to_care_storage.html', {
                    'error': 'Blood type and quantity are required',
                    'total_resources': total_resources,
                })

        elif donation_type == "Other Resources":
            description = request.POST.get('description')
            if description:
                # Create Care Storage donation transaction using Donor instance
                transaction = CareStorageDonation.objects.create(
                    donor=donor,  # Use Donor instance instead of user
                    donation_type='other',
                    description=description,
                    status='completed'
                )

                # Award random Care-Coins (10 to 50)
                care_coins = random.randint(100, 150)
                CareCoin.objects.create(
                    donor=user,  # CareCoin uses mainuser as per your model
                    coins=care_coins,
                    transaction_type='earned',
                    donation_transaction=None,  # No direct DonationTransaction link
                    description=f"Reward for other resources donation to Care Storage"
                )
                transaction.care_coins_awarded = care_coins
                transaction.save()
                print("Other resources donation saved:", transaction)

                # Redirect to success page with transaction details
                success_context = {
                    'message': 'Transaction Successful!',
                    'care_coins_earned': care_coins,
                    'donation_details': f'{description} to Care Storage',
                    'donation_type': 'Other Resources'
                }
                return render(request, 'donation_success.html', success_context)
            else:
                return render(request, 'donate_to_care_storage.html', {
                    'error': 'Description is required',
                    'total_resources': total_resources,
                })

    context = {
        'user': user,
        'total_resources': total_resources,
        'donor_id': getattr(donor, 'donor_id', None)  # Pass donor_id if donor exists
    }
    return render(request, 'donate_to_care_storage.html', context)


# # views.py
# def care_storage_donation_callback(request):
#     if request.method == 'POST':
#         print("1111111111 - Callback started")
#         payment_id = request.POST.get('razorpay_payment_id')
#         order_id = request.POST.get('razorpay_order_id')
#         signature = request.POST.get('razorpay_signature')

#         print("Payment data received:", {
#             'payment_id': payment_id,
#             'order_id': order_id,
#             'signature': signature
#         })

#         if not all([payment_id, order_id, signature]):
#             print("Missing Razorpay payment data")
#             return redirect('donate_to_care_storage')

#         client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
#         params_dict = {
#             'razorpay_order_id': order_id,
#             'razorpay_payment_id': payment_id,
#             'razorpay_signature': signature
#         }
#         try:
#             print("22222222 - Verifying signature")
#             client.utility.verify_payment_signature(params_dict)
#             print("Signature verified successfully")

#             amount = request.session.get('care_storage_amount')  # Amount in rupees
#             donation_type = request.session.get('donation_type')
#             donor_id = request.session.get('donor_id')
#             user = mainuser.objects.get(user_id=request.session.get('user_id'))

#             # Fetch the Donor instance
            # donor = Donor.objects.get(donor_id=donor_id)

            # # Create Care Storage donation transaction for funds using Donor instance
            # transaction = CareStorageDonation.objects.create(
            #     donor=donor,  # Use Donor instance
            #     donation_type='funds',
            #     amount=amount,
            #     status='completed'
            # )
            # print("33333333333 - Transaction created:", transaction)

            # # Award random Care-Coins (10 to 50)
            # care_coins = random.randint(10, 50)
            # CareCoin.objects.create(
            #     donor=user,  # CareCoin uses mainuser as per your model
            #     coins=care_coins,
            #     transaction_type='earned',
            #     donation_transaction=None,  # No direct DonationTransaction link
            #     description=f"Reward for funds donation to Care Storage"
            # )
            # transaction.care_coins_awarded = care_coins
            # transaction.save()
            # print("55555555555 - Care-Coins awarded and transaction saved")

            # # Clean up session
            # del request.session['care_storage_amount']
            # del request.session['donation_type']
            # del request.session['donor_id']
            # print("Session cleaned up")

            # # Redirect to success page with transaction details
            # success_context = {
            #     'message': 'Transaction Successful!',
            #     'care_coins_earned': care_coins,
            #     'donation_details': f'{amount} INR to Care Storage',
            #     'donation_type': 'Financial Aid'
            # }
            # print("666666666 - Rendering success page")
            # return render(request, 'donation_success.html', success_context)

#         except razorpay.errors.SignatureVerificationError as e:
#             print("Payment verification failed:", e)
#             return redirect('donate_to_care_storage')
#         except (mainuser.DoesNotExist, Donor.DoesNotExist) as e:
#             print("User or Donor not found:", e)
#             return redirect('donate_to_care_storage')
#         except Exception as e:
#             print("Unexpected error in callback:", e)
#             return redirect('donate_to_care_storage')
#     print("fail............... - Redirecting to donation page")
#     return redirect('donate_to_care_storage')
def care_storage_donation_callback(request):
    if request.method == 'POST':
        print("Callback started")
        payment_id = request.POST.get('razorpay_payment_id')
        order_id = request.POST.get('razorpay_order_id')
        signature = request.POST.get('razorpay_signature')

        if not all([payment_id, order_id, signature]):
            print("Missing Razorpay payment data")
            return redirect('donate_to_care_storage')

        try:
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            params_dict = {
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            }

            print("Verifying payment signature...")
            client.utility.verify_payment_signature(params_dict)
            print("Signature verified successfully!")

            amount = request.session.pop('care_storage_amount', None)
            donor_id = request.session.pop('donor_id', None)
            user = mainuser.objects.get(user_id=request.session.get('user_id'))

            donor = Donor.objects.get(donor_id=donor_id)

            transaction = CareStorageDonation.objects.create(
                donor=donor,
                donation_type='funds',
                amount=amount,
                status='completed'
            )
            print("Transaction created:", transaction)

            care_coins = random.randint(10, 50)
            CareCoin.objects.create(
                donor=user,
                coins=care_coins,
                transaction_type='earned',
                description="Reward for funds donation to Care Storage"
            )
            transaction.care_coins_awarded = care_coins
            transaction.save()
            print("Care-Coins awarded:", care_coins)

            return render(request, 'donation_success.html', {
                'message': 'Transaction Successful!',
                'care_coins_earned': care_coins,
                'donation_details': f'{amount} INR to Care Storage',
                'donation_type': 'Financial Aid'
            })

        except razorpay.errors.SignatureVerificationError as e:
            print("Payment verification failed:", e)
            return redirect('donate_to_care_storage')
        except Exception as e:
            print("Unexpected error:", e)
            return redirect('donate_to_care_storage')
    return redirect('donate_to_care_storage')




from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from .models import mainuser, Patient, DonationTransaction

def send_request_to_past_patients(request):
    if not request.session.get('user_id'):
        return redirect('user_loginpage')  # Redirect if not logged in
   
    user = mainuser.objects.get(user_id=request.session.get('user_id'))

    # Ensure the user is a patient
    try:
        # patient = Patient.objects.get(user_id=user.user_id)
        # print("pa===",patient)
        
        # Fetch all Patient objects associated with the user
        patients = Patient.objects.filter(user_id=user.user_id)  # Use filter instead of get
        print("All patients for user_id", user.user_id, ":", patients)

    # Store the last patient (assuming ordered by ID or creation date)
        patient = patients.last() if patients.exists() else None
        print("Last patient stored:", patient)
    except Patient.DoesNotExist:
        return render(request, 'send_request.html', {'error': 'You must be a registered patient to send requests'})

    # Get all donations received by the patient
    # past_donations = DonationTransaction.objects.filter(patient=patient)

    # Collect unique donors who donated to this patient
    # donor_ids = past_donations.values_list('donor', flat=True).distinct()
    
    # Collect emails of all past patients who received donations from these donors
    # past_patients = DonationTransaction.objects.filter(donor__in=donor_ids).values_list('patient', flat=True).distinct()

    # Fetch patient emails from mainuser (if user_type='both') or from Patient table
    emails = []
    # for patient_id in past_patients:
    #     patient_obj = Patient.objects.get(patient_id=patient_id)
    #     user_obj = mainuser.objects.get(user_id=patient_obj.user.user_id)

    #     if user_obj.user_type == "both":
    #         emails.append(user_obj.email)
    #     else:
    #         emails.append(patient_obj.email)

    # Remove duplicates (if any)
    # emails = list(set(emails))
    emails=['akulashivaakulashiva@gmail.com','shivakula097@gmail.com','yashwanthmogudala5@gmail.com']

    # Send email to all collected patients
    subject = "Urgent Request from a Fellow Patient"
    message = f"Hello, \n\nA fellow patient {patient.full_name} has requested help. If you are willing to assist, please reach out.\n\nThis patient {patient.full_name} is help past when you are suffering from issue\n\n so This time for you to save this Savior\n\n Thank you for your support!"
    from_email = settings.EMAIL_HOST_USER

    send_mail(subject, message, from_email, emails, fail_silently=False)

    return render(request, 'request_success.html', {'emails_sent': emails})



# views.py
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from .models import mainuser, Patient, DonationTransaction

def send_request_to_past_patients(request):
    if not request.session.get('user_id'):
        return redirect('user_loginpage')  # Redirect if not logged in

    user = mainuser.objects.get(user_id=request.session.get('user_id'))
    donor=Donor.objects.filter(user_id=user.user_id)
    # Ensure the user is a patient
    try:
       
        patients = Patient.objects.filter(user_id=user.user_id)  # Use filter instead of get
        print("All patients for user_id", user.user_id, ":", patients)

    # Store the last patient (assuming ordered by ID or creation date)
        patient = patients.last() if patients.exists() else None
        
        print("Last patient stored:", patient)
    except Patient.DoesNotExist:
        return render(request, 'send_request.html', {'error': 'You must be a registered patient to send requests'})
    patient_id=patient.patient_id
        # Fetch all Patient objects associated with the user
    #     patients = Patient.objects.filter(user_id=user.user_id)  # Use filter instead of get
    #     print("All patients for user_id", user.user_id, ":", patients)

    #     # Store the last patient (assuming ordered by ID or creation date)
    #     patient = patients.last() if patients.exists() else None
    #     print("Last patient stored:", patient)
    #     if not patient:
    #         return render(request, 'send_request.html', {'error': 'You must be a registered patient to send requests'})
    # except Patient.DoesNotExist:
    #     return render(request, 'send_request.html', {'error': 'You must be a registered patient to send requests'})
    # ass=HospitalDetails.objects.filter(patient_id=patient_id)
    # print("ass===",ass)
    ass_objects = HospitalDetails.objects.filter(patient_id=patient_id)
    print("ass as objects===", ass_objects)
    for hospital in ass_objects:
        hname=hospital.hospital_name
        p=hospital.medical_problem
        t=hospital.expected_recovery_time
        print(f"Hospital: {hospital.hospital_name}, medical_problem: {hospital.medical_problem}, expected_recovery_time: {hospital.expected_recovery_time}")

    # context = {'hospital_details': list(ass_objects)}  # Pass as list for template
    
    # # Get all donations received by the patient
    # past_donations = DonationTransaction.objects.filter(patient=patient)

    # # Collect unique donors who donated to this patient
    # donor_ids = past_donations.values_list('donor', flat=True).distinct()

    # # Collect emails of all past patients who received donations from these donors
    # past_patients = DonationTransaction.objects.filter(donor__in=donor_ids).exclude(patient=patient).values_list('patient', flat=True).distinct()

    # Fetch patient emails and details from mainuser or Patient table
    emails = []
    # patient_details = []
    # for patient_id in past_patients:
    #     patient_obj = Patient.objects.get(patient_id=patient_id)
    #     user_obj = mainuser.objects.get(user_id=patient_obj.user.user_id)
    #     if user_obj.user_type == "both":
    #         emails.append(user_obj.email)
    #     else:
    #         emails.append(patient_obj.email)
    #     # Collect patient details
    #     patient_details.append({
    #         'full_name': patient_obj.full_name,
    #         'email': patient_obj.email,
    #         'phone_number': patient_obj.phone_number if hasattr(patient_obj, 'phone_number') else 'N/A'
    #     })

    # Remove duplicates (if any)
    # emails=['akulashivaakulashiva@gmail.com','shivakula097@gmail.com']
    emails=['yashwanthmogudala5@gmail.com','sahasragteja@gmail.com']

    # emails = list(set(emails))

    # Construct HTML email message with patient and assistance details
    donation_link = request.build_absolute_uri(reverse('donate_to_care_storage', kwargs={'donor_id': patient.user.donor.donor_id})) if hasattr(patient.user, 'donor') else '#'
    html_message = f"""
    <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2>Urgent Request from a Fellow Patient</h2>
            <p>Hello,</p>
            <p>A fellow patient, <strong>{patient.full_name}</strong>, is in need of assistance. Here are the details:</p>
            <ul>
            <li><strong>Patient_ID:</strong> {patient.patient_id}</li>
                <li><strong>Full Name:</strong> {patient.full_name}</li>
                <li><strong>Email:</strong> {patient.email}</li>
                <li><strong>Phone Number:</strong> {patient.contact_number }</li>
               
               <li><strong>Alternate Phone Number:</strong> {patient.alternate_number }</li>
                <li><strong> Hospital Nmae:</strong> {hname }</li>
               <li><strong>problem:r:</strong> {p }</li>
               <li><strong>expected_recovery_time:</strong> {t }</li>
            </ul>
            <p><strong>Assistance Needed:</strong> This patient previously helped you when you were in need. Now, it's your turn to save this savior!</p>
            
            
            <p>Please consider donating to support them. Click the link below to contribute:</p>
            <a href="{donation_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Donate Now</a>
            <p>Thank you for your support!</p>
            <p>Best regards,<br>OCTATANGLECARE Team</p>
        </body>
    </html>
    """

    # Send email to all collected patients
    subject = "Urgent Request from a Fellow Patient"
    from_email = settings.EMAIL_HOST_USER
    send_mail(
        subject,
        '',  # Plain text fallback (empty since using HTML)
        from_email,
        emails,
        fail_silently=False,
        html_message=html_message
    )

    return render(request, 'request_success.html', {'emails_sent': emails})



def services_role(request):
    return render(request,'services_roles.html')

def helppage(request):
    return render(request, "help_page.html")

# views.py
def donate_resources(request):
    return render(request, 'donate_resources.html')

def index_services(request):
    return render(request, 'index_services.html')

def index_help(request):
    return render(request, 'index_help.html')


from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.contrib import messages
from django.conf import settings

def contact_us(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        message = request.POST.get("message")
        print(name,email,message)

        if not name or not email or not message:
            messages.error(request, "All fields are required!")
            return redirect("contact_us")

        subject = f"New Contact Form Submission from {name}"
        email_message = f"""
        Name: {name}
        Email: {email}
        Message: {message}
        """

        try:
            send_mail(
                subject,
                email_message,
                settings.EMAIL_HOST_USER,  # From email (configured in settings.py)
                ["octatanglecare3s@gmail.com"],  # Send to company support email
                fail_silently=False,
            )
            messages.success(request, "Your message has been sent successfully!")
        except Exception as e:
            messages.error(request, "Something went wrong. Please try again later.")

        return redirect("contact_us")

    return render(request, "index_help.html")
