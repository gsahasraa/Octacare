import random
from django.db import models

# Create your models here.

from django.db import models


from django.db import models
from django.core.validators import MinValueValidator
import random
from django.utils import timezone

# Main User Model
class mainuser(models.Model):
    USER_TYPES = [
        ('patient', 'Patient'),
        ('donor', 'Donor'),
        ('both', 'Both'),
    ]

    user_id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=50)
    email = models.EmailField()
    password = models.CharField(max_length=50)  # Store hashed passwords in production
    phone_number = models.CharField(max_length=15, unique=True)
    address = models.TextField()
    user_type = models.CharField(max_length=10, choices=USER_TYPES)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    first_login = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.full_name} ({self.user_type})"

# Donor Model
class Donor(models.Model):
    DONATION_TYPES = [
        ('funds', 'Funds'),
        ('blood', 'Blood'),
        ('other', 'Other'),
        ('all', 'All'),
    ]

    donor_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(mainuser, on_delete=models.CASCADE)
    dob = models.DateField()
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
    blood_group = models.CharField(max_length=5)
    country = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    district = models.CharField(max_length=100)
    mandal = models.CharField(max_length=100)
    village = models.CharField(max_length=100)
    house_number = models.CharField(max_length=50)
    donation_type = models.CharField(max_length=10, choices=DONATION_TYPES)

    def __str__(self):
        return f"Donor {self.user.full_name} - {self.donation_type}"

# Patient Model
class Patient(models.Model):
    patient_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(mainuser, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=200)
    age = models.IntegerField()
    dob = models.DateField()
    gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
    contact_number = models.CharField(max_length=15)
    alternate_number = models.CharField(max_length=15, blank=True)
    email = models.EmailField(unique=True, blank=True)
    address = models.TextField(max_length=200)
    aadhaar_id = models.CharField(max_length=12)
    aadhaar_card = models.FileField(upload_to='aadhaar_cards/', blank=False)
    patient_photo = models.FileField(upload_to='patient_photos/', blank=False, default="null")

    def __str__(self):
        return self.full_name

# Hospital Details Model
class HospitalDetails(models.Model):
    hospitaldetails_id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    hospital_name = models.CharField(max_length=100)
    hospital_location = models.TextField()
    doctor_name = models.CharField(max_length=100)
    doctor_contact = models.CharField(max_length=15)
    patient_id_in_hospital = models.CharField(max_length=50, blank=True, unique=True)
    medical_problem = models.CharField(max_length=200)
    problem_description = models.TextField()
    prescription = models.FileField(upload_to='prescriptions/', blank=False)
    expected_recovery_time = models.IntegerField()

    def __str__(self):
        return f"{self.patient.full_name} - {self.hospital_name}"

# Medical Report Model
class MedicalReport(models.Model):
    medicalreport_id = models.AutoField(primary_key=True)
    hospital_details = models.ForeignKey(HospitalDetails, on_delete=models.CASCADE)
    report_name = models.CharField(max_length=200)
    report_file = models.FileField(upload_to='medical_reports/', blank=False)

    def __str__(self):
        return self.report_name

# Assistance Required Model
class AssistanceRequired(models.Model):
    assistance_id = models.AutoField(primary_key=True)
    hospital_details = models.ForeignKey(HospitalDetails, on_delete=models.CASCADE)
    assistance_type = models.CharField(max_length=50, choices=[
        ('Financial Aid', 'Financial Aid'),
        ('Blood Donation', 'Blood Donation'),
        ('Other Resources', 'Other Resources')
    ])
    amount_required = models.IntegerField(null=True, blank=True)  # For Financial Aid
    bank_name = models.CharField(max_length=100, null=True, blank=True)
    account_holder_name = models.CharField(max_length=100, null=True, blank=True)
    account_number = models.CharField(max_length=20, null=True, blank=True)
    ifsc_code = models.CharField(max_length=11, null=True, blank=True)
    bank_details_file = models.FileField(upload_to='bank_details/', null=True, blank=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)  # Added for Financial Aid
    qr_code_file = models.FileField(upload_to='qr_codes/', null=True, blank=True)
    upi_ids = models.TextField(null=True, blank=True)  # Store UPI IDs as comma-separated values
    blood_type = models.CharField(max_length=10, null=True, blank=True)  # For Blood Donation
    quantity = models.CharField(max_length=50, null=True, blank=True)
    location_to_reach = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(null=True, blank=True)  # For Other Resources
    amount_received = models.IntegerField(default=0)

    def is_completed(self):
        return (self.amount_required is not None and self.amount_required <= self.amount_received) or \
               (self.assistance_type in ['Blood Donation', 'Other Resources'] and self.quantity and self.quantity.strip())

    def __str__(self):
        return f"{self.hospital_details.patient.full_name} - {self.assistance_type}"

# Verification Model
class Verification(models.Model):
    status = models.CharField(max_length=20, choices=[('Pending', 'Pending'), ('Verified', 'Verified'), ('Fake', 'Fake')], default='Verified')
    verification_id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    registered_by_patient = models.BooleanField(default=False)
    verifier_phone = models.CharField(max_length=15, null=True, blank=True)
    verifier_aadhaar = models.FileField(upload_to='verifier_aadhaar/', null=True, blank=True)
    verifier_email = models.EmailField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    ai_confidence_score = models.FloatField(null=True, blank=True)
    ai_analysis_notes = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Verification for {self.patient.full_name}"

# Hospital Model
class Hospital(models.Model):
    VERIFICATION_STATUS = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]

    hospital_id = models.AutoField(primary_key=True)
    hospital_name = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    address = models.TextField()
    registration_number = models.CharField(max_length=100, unique=True)
    verification_status = models.CharField(max_length=10, choices=VERIFICATION_STATUS, default='verified')

    def __str__(self):
        return f"{self.hospital_name} - {self.verification_status}"

# Patient Donation Status Model
class PatientDonationStatus(models.Model):
    status_id = models.AutoField(primary_key=True)
    patient = models.OneToOneField(Patient, on_delete=models.CASCADE, related_name='donation_status')
    is_active = models.BooleanField(default=False)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, default='active', choices=[
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('deactive', 'Deactive'),
    ])

    def __str__(self):
        return f"Donation Status for {self.patient.full_name} - {'Active' if self.is_active else 'Inactive'}"

    def check_status(self):
        """
        Check if the donation status should be updated based on assistance completion.
        """
        assistance = AssistanceRequired.objects.filter(hospital_details__patient=self.patient).first()
        if assistance and assistance.is_completed():
            self.status = 'completed'
            self.is_active = False
            self.save()
        return self.is_active

    def set_end_time(self, expected_recovery_days):
        """
        Set the end time based on the expected recovery time in days from HospitalDetails.
        """
        if expected_recovery_days:
            self.end_time = self.start_time + timezone.timedelta(days=expected_recovery_days)
            self.save()
        return self.end_time

# Care-Coin Model
class CareCoin(models.Model):
    carecoin_id = models.AutoField(primary_key=True)
    donor = models.ForeignKey(mainuser, on_delete=models.CASCADE, related_name='care_coins')
    transaction_type = models.CharField(max_length=10, choices=[('earned', 'Earned'), ('spent', 'Spent')], default='earned')
    coins = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    donation_type = models.CharField(max_length=20, choices=[('funds', 'Funds'), ('blood', 'Blood'), ('other', 'Other')])
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    donation_transaction = models.ForeignKey('DonationTransaction', on_delete=models.CASCADE, null=True, blank=True, related_name='care_coin_rewards')

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Care-Coin Transaction"
        verbose_name_plural = "Care-Coin Transactions"

    def __str__(self):
        return f"CareCoin #{self.carecoin_id} - {self.donor.full_name} - {self.transaction_type} {self.coins} coins ({self.donation_type})"

    @property
    def current_balance(self):
        """
        Calculate the donor's current Care-Coin balance.
        """
        earned = CareCoin.objects.filter(donor=self.donor, transaction_type='earned').aggregate(total=models.Sum('coins'))['total'] or 0
        spent = CareCoin.objects.filter(donor=self.donor, transaction_type='spent').aggregate(total=models.Sum('coins'))['total'] or 0
        return earned - spent

# Scratch Card Model
class ScratchCard(models.Model):
    user = models.OneToOneField(mainuser, on_delete=models.CASCADE, related_name='scratch_card')
    bonus_coins = models.PositiveIntegerField(validators=[MinValueValidator(100)])
    awarded_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.bonus_coins = random.randint(100, 200)
        super().save(*args, **kwargs)

# Message Verification Model
class MessageVerification(models.Model):
    VERIFICATION_STATUS = [
        ('fake', 'Fake'),
        ('completed', 'Completed'),
        ('active', 'Active'),
    ]
    
    verification_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(mainuser, on_delete=models.CASCADE, null=True, blank=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, null=True, blank=True)
    message_image = models.ImageField(upload_to='message_verifications/', null=True, blank=True)
    patient_id_input = models.CharField(max_length=50, blank=True)
    issue_input = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=10, choices=VERIFICATION_STATUS, default='fake')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Verification {self.verification_id} - {self.status}"

# Donation Transaction Model
class DonationTransaction(models.Model):
    TRANSACTION_TYPES = [
        ('funds', 'Funds'),
        ('blood', 'Blood Donation'),
        ('other', 'Other Resources'),
    ]
    
    transaction_id = models.AutoField(primary_key=True)
    donor = models.ForeignKey(mainuser, on_delete=models.CASCADE, related_name='donation_transactions')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='received_donations')
    assistance = models.ForeignKey(AssistanceRequired, on_delete=models.CASCADE, related_name='related_transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
    amount = models.IntegerField(null=True, blank=True)  # For funds (in rupees)
    blood_type = models.CharField(max_length=10, null=True, blank=True)  # For blood donation
    quantity = models.CharField(max_length=50, null=True, blank=True)  # For blood donation
    description = models.TextField(null=True, blank=True)  # For other resources
    transaction_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='completed')  # e.g., 'completed', 'pending', 'failed'
    care_coins_awarded = models.IntegerField(null=True, blank=True)  # Number of Care-Coins awarded for this transaction

    def __str__(self):
        return f"{self.donor.full_name} donated {self.transaction_type} for {self.patient.full_name} on {self.transaction_date}"
    


# models.py
from django.db import models
from django.utils import timezone

# Existing models remain unchanged; add this new model below them

class PatientStatus(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('deactive', 'Deactive'),
    ]

    status_id = models.AutoField(primary_key=True)
    patient = models.OneToOneField(Patient, on_delete=models.CASCADE, related_name='status')
    is_active = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    donation_percentage = models.FloatField(null=True, blank=True, default=0.0)  # Percentage of donations received
    total_needed = models.IntegerField(null=True, blank=True)  # Total amount/resources required
    total_received = models.IntegerField(null=True, blank=True, default=0)  # Total amount/resources received

    def __str__(self):
        return f"Status for {self.patient.full_name} - {self.status}"

    def update_status(self):
        """
        Update the status based on donation completion (e.g., total_received >= total_needed).
        """
        assistance = AssistanceRequired.objects.filter(hospital_details__patient=self.patient).first()
        if assistance:
            if assistance.assistance_type == "Financial Aid":
                self.total_needed = assistance.amount_required or 0
                self.total_received = assistance.amount_received or 0
                self.donation_percentage = min((self.total_received / self.total_needed) * 100, 100) if self.total_needed > 0 else 0
                if self.total_received >= self.total_needed:
                    self.status = 'completed'
                    self.is_active = False
            elif assistance.assistance_type in ["Blood Donation", "Other Resources"]:
                self.total_needed = 1  # Placeholder for non-financial assistance (adjust based on your logic)
                self.total_received = 1 if (assistance.quantity and assistance.quantity.strip()) or (assistance.description and assistance.description.strip()) else 0
                self.donation_percentage = 100 if self.total_received else 0
                if self.total_received:
                    self.status = 'completed'
                    self.is_active = False
            else:
                self.status = 'active'
                self.is_active = True
            self.save()
        return self.is_active

    def set_end_time(self, expected_recovery_days):
        """
        Set the end time based on the expected recovery time in days from HospitalDetails.
        """
        if expected_recovery_days:
            self.end_time = self.start_time + timezone.timedelta(days=expected_recovery_days)
            self.save()
        return self.end_time
    
    
    


# models.py
from django.db import models
from django.utils import timezone
from .models import mainuser, Donor

class CareStorageDonation(models.Model):
    DONATION_TYPES = [
        ('funds', 'Funds'),
        ('blood', 'Blood'),
        ('other', 'Other Resources'),
    ]

    donation_id = models.AutoField(primary_key=True)
    donor = models.ForeignKey(Donor, on_delete=models.CASCADE, related_name='care_storage_donations')  # Use Donor instead of mainuser
    donation_type = models.CharField(max_length=20, choices=DONATION_TYPES)
    amount = models.IntegerField(null=True, blank=True, help_text="Amount in INR for funds")  # For funds (in rupees)
    blood_type = models.CharField(max_length=10, null=True, blank=True, help_text="Blood type for blood donation")  # For blood donation
    quantity = models.CharField(max_length=50, null=True, blank=True, help_text="Quantity for blood donation, e.g., 500ml")  # For blood donation
    description = models.TextField(null=True, blank=True, help_text="Description for other resources")  # For other resources
    transaction_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='completed')  # e.g., 'completed', 'pending', 'failed'
    care_coins_awarded = models.IntegerField(null=True, blank=True, help_text="Number of Care-Coins awarded for this donation")

    def __str__(self):
        return f"{self.donor.user.full_name} donated {self.donation_type} to Care Storage on {self.transaction_date}"

    @classmethod
    def get_total_resources(cls):
        """
        Calculate the total available resources in Care Storage.
        Returns a dictionary with totals for funds (in INR), blood (by type and quantity), and other resources.
        """
        total_funds = cls.objects.filter(donation_type='funds', status='completed').aggregate(total=models.Sum('amount'))['total'] or 0
        blood_totals = {}
        other_resources = []

        blood_donations = cls.objects.filter(donation_type='blood', status='completed')
        for donation in blood_donations:
            key = f"{donation.blood_type} - {donation.quantity}"
            blood_totals[key] = blood_totals.get(key, 0) + 1  # Count occurrences of each blood type/quantity

        other_donations = cls.objects.filter(donation_type='other', status='completed').values_list('description', flat=True)
        other_resources = list(other_donations)  # List of descriptions for other resources

        return {
            'total_funds': total_funds,
            'blood_totals': blood_totals,
            'other_resources': other_resources,
        }



# models.py
from django.db import models
from django.utils import timezone
from .models import mainuser, Patient, Donor, DonationTransaction

class SaveTheSaviorRequest(models.Model):
    request_id = models.AutoField(primary_key=True)
    donor = models.ForeignKey(Donor, on_delete=models.CASCADE, related_name='savior_requests')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='received_savior_requests')
    transaction = models.ForeignKey(DonationTransaction, on_delete=models.CASCADE, related_name='savior_requests', null=True, blank=True)
    request_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='pending')  # e.g., 'pending', 'accepted', 'rejected'
    message = models.TextField(default="You have been requested to help your previous savior who is now in need.")

    def __str__(self):
        return f"Request from {self.donor.user.full_name} to {self.patient.full_name} on {self.request_date}"
    
    
    

# class Aicarecoins(models.Model):
#     ai_id=models.AutoField(primary_key=True)
#     donor = models.ForeignKey(Donor, on_delete=models.CASCADE)
#     donor_name=models.CharField()
#     donor_type=models.CharField()
#     email=models.EmailField()
#     loginstreak=models.IntegerField()
#     total_donation=models.IntegerField()
#     current_donation=models.IntegerField()

# models.py
from django.db import models
from django.utils import timezone
from .models import mainuser

# class CareStorageDonation(models.Model):
#     DONATION_TYPES = [
#         ('financial aid', 'Financial Aid'),
#         ('blood', 'Blood'),
#         ('other', 'Other Resources'),
#     ]

#     donation_id = models.AutoField(primary_key=True)
#     donor = models.ForeignKey(mainuser, on_delete=models.CASCADE, related_name='care_storage_donations')
#     donation_type = models.CharField(max_length=20, choices=DONATION_TYPES)
#     amount = models.IntegerField(null=True, blank=True)  # For funds (in rupees)
#     blood_type = models.CharField(max_length=10, null=True, blank=True)  # For blood donation
#     quantity = models.CharField(max_length=50, null=True, blank=True)  # For blood donation
#     description = models.TextField(null=True, blank=True)  # For other resources
#     transaction_date = models.DateTimeField(auto_now_add=True)
#     status = models.CharField(max_length=20, default='completed')  # e.g., 'completed', 'pending', 'failed'
#     care_coins_awarded = models.IntegerField(null=True, blank=True)  # Number of Care-Coins awarded for this donation

#     def __str__(self):
#         return f"{self.donor.full_name} donated {self.donation_type} to Care Storage on {self.transaction_date}"

#     @classmethod
#     def get_total_resources(cls):
#         """
#         Calculate the total available resources in Care Storage.
#         Returns a dictionary with totals for funds (in INR), blood (by type and quantity), and other resources.
#         """
#         total_funds = cls.objects.filter(donation_type='funds', status='completed').aggregate(total=models.Sum('amount'))['total'] or 0
#         blood_totals = {}
#         other_resources = []

#         blood_donations = cls.objects.filter(donation_type='blood', status='completed')
#         for donation in blood_donations:
#             key = f"{donation.blood_type} - {donation.quantity}"
#             blood_totals[key] = blood_totals.get(key, 0) + 1  # Count occurrences of each blood type/quantity

#         other_donations = cls.objects.filter(donation_type='other', status='completed').values_list('description', flat=True)
#         other_resources = list(other_donations)  # List of descriptions for other resources

#         return {
#             'total_funds': total_funds,
#             'blood_totals': blood_totals,
#             'other_resources': other_resources,
#         }
        

# class mainuser(models.Model):
#     USER_TYPES = [
#         ('patient', 'Patient'),
#         ('donor', 'Donor'),
#         ('both', 'Both'),
#     ]

#     user_id = models.AutoField(primary_key=True)  # Auto-incrementing Primary Key
#     full_name = models.CharField(max_length=50)
#     email = models.EmailField(unique=True)
#     password = models.CharField(max_length=50)  # Store hashed passwords in production
#     phone_number = models.CharField(max_length=15, unique=True)  # Supports international formats
#     address = models.TextField()  # Full Address
#     user_type = models.CharField(max_length=10, choices=USER_TYPES)
#     created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the user registers
#     # status = models.BooleanField(default=True)  # Active/Inactive status
#     is_active = models.BooleanField(default=False)
#     last_login = models.DateTimeField(null=True, blank=True)
#     first_login = models.BooleanField(default=True)

#     def __str__(self):
#         return f"{self.full_name} ({self.user_type})"



# class Donor(models.Model):
#     DONATION_TYPES = [
#         ('funds', 'Funds'),
#         ('blood', 'Blood'),
#         ('other', 'Other'),
#         ('all', 'All'),
#     ]

#     donor_id = models.AutoField(primary_key=True)  # Auto-incrementing Primary Key
#     user = models.ForeignKey('mainuser', on_delete=models.CASCADE)  # Foreign Key to User model
#     dob = models.DateField()  # Date of Birth
#     gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
#     blood_group = models.CharField(max_length=5)  # Example: A+, O-, B+
#     country = models.CharField(max_length=100)  # Country
#     state = models.CharField(max_length=100)  # State
#     district = models.CharField(max_length=100)  # District
#     mandal = models.CharField(max_length=100)  # Mandal
#     village = models.CharField(max_length=100)  # Village
#     house_number = models.CharField(max_length=50)  # House Number
#     donation_type = models.CharField(max_length=10, choices=DONATION_TYPES)  # Type of donation

# class Patient(models.Model):
#     patient_id = models.AutoField(primary_key=True)
#     user = models.ForeignKey('mainuser', on_delete=models.CASCADE)  # Foreign Key to User model
#     full_name = models.CharField(max_length=200)
#     age = models.IntegerField()
#     dob = models.DateField()
#     gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
#     contact_number = models.CharField(max_length=15)
#     alternate_number = models.CharField(max_length=15, blank=True)
#     email = models.EmailField(unique=True, blank=True)
#     address = models.TextField(max_length=200)
#     aadhaar_id = models.CharField(max_length=12)
#     aadhaar_card = models.FileField(upload_to='aadhaar_cards/', blank=False)
#     patient_photo = models.FileField(upload_to='patient_photos/', blank=False, default="null")
#     # patient = models.OneToOneField('Patient', on_delete=models.CASCADE, related_name='donation_status')
#     # donation_status = models.ForeignKey('PatientDonationStatus', on_delete=models.SET_NULL, null=True, blank=True, related_name='patients', unique=True)
    

#     def __str__(self):
#         return self.full_name

# class HospitalDetails(models.Model):
#     hospitaldetails_id = models.AutoField(primary_key=True)
#     patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
#     hospital_name = models.CharField(max_length=100)
#     hospital_location = models.TextField()
#     doctor_name = models.CharField(max_length=100)
#     doctor_contact = models.CharField(max_length=15)
#     patient_id_in_hospital = models.CharField(max_length=50, blank=True, unique=True)
#     medical_problem = models.CharField(max_length=200)
#     problem_description = models.TextField()
#     prescription = models.FileField(upload_to='prescriptions/', blank=False)
#     expected_recovery_time = models.IntegerField()

#     def __str__(self):
#         return f"{self.patient.full_name} - {self.hospital_name}"

# class MedicalReport(models.Model):
#     medicalreport_id = models.AutoField(primary_key=True)
#     hospital_details = models.ForeignKey(HospitalDetails, on_delete=models.CASCADE)
#     report_name = models.CharField(max_length=200)
#     report_file = models.FileField(upload_to='medical_reports/', blank=False)

#     def __str__(self):
#         return self.report_name

# class AssistanceRequired(models.Model):
#     assistance_id = models.AutoField(primary_key=True)
#     hospital_details = models.ForeignKey(HospitalDetails, on_delete=models.CASCADE)
#     assistance_type = models.CharField(max_length=50, choices=[
#         ('Financial Aid', 'Financial Aid'),
#         ('Blood Donation', 'Blood Donation'),
#         ('Other Resources', 'Other Resources')
#     ])
#     amount_required = models.IntegerField(null=True, blank=True)  # For Financial Aid
#     bank_name = models.CharField(max_length=100, null=True, blank=True)
#     account_holder_name = models.CharField(max_length=100, null=True, blank=True)
#     account_number = models.CharField(max_length=20, null=True, blank=True)
#     ifsc_code = models.CharField(max_length=11, null=True, blank=True)
#     bank_details_file = models.FileField(upload_to='bank_details/', null=True, blank=True)
#     phone_number = models.CharField(max_length=15, null=True, blank=True)  # Added for Financial Aid
#     qr_code_file = models.FileField(upload_to='qr_codes/', null=True, blank=True)
#     upi_ids = models.TextField(null=True, blank=True)  # Store UPI IDs as comma-separated values
#     blood_type = models.CharField(max_length=10, null=True, blank=True)  # For Blood Donation
#     quantity = models.CharField(max_length=50, null=True, blank=True)
#     location_to_reach = models.CharField(max_length=200, null=True, blank=True)
#     description = models.TextField(null=True, blank=True)  # For Other Resources
#     amount_received = models.IntegerField(default=0)
    
#     def is_completed(self):
#         return (self.amount_required is not None and self.amount_required <= self.amount_received) or \
#                (self.assistance_type in ['Blood Donation', 'Other Resources'] and self.quantity and self.quantity.strip())
               

#     def __str__(self):
#         return f"{self.hospital_details.patient.full_name} - {self.assistance_type}"

# class Verification(models.Model):
#     status = models.CharField(
#         max_length=20, 
#         choices=[('Pending', 'Pending'), ('Verified', 'Verified'), ('Fake', 'Fake')],
#         default='Pending'
#     )
#     verification_id = models.AutoField(primary_key=True)
#     patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
#     registered_by_patient = models.BooleanField(default=False)
#     verifier_phone = models.CharField(max_length=15, null=True, blank=True)
#     verifier_aadhaar = models.FileField(upload_to='verifier_aadhaar/', null=True, blank=True)
#     verifier_email = models.EmailField(null=True, blank=True)
#     created_at = models.DateTimeField(auto_now_add=True)
#     ai_confidence_score = models.FloatField(null=True, blank=True)  # Confidence score from AI
#     ai_analysis_notes = models.TextField(null=True, blank=True)    # Notes from AI analysis
    
#     def __str__(self):
#         return f"Verification for {self.patient.full_name}"


# # from django.db import models

# class Hospital(models.Model):
#     VERIFICATION_STATUS = [
#         ('pending', 'Pending'),
#         ('verified', 'Verified'),
#         ('rejected', 'Rejected'),
#     ]

#     hospital_id = models.AutoField(primary_key=True)  # Auto-incrementing Primary Key
#     # hospital_reg_number=models.CharField(max_length=100, unique=True)
#     hospital_name = models.CharField(max_length=255, unique=True)  # Unique hospital name
#     email = models.EmailField(unique=True)  # Unique email for hospital
#     phone_number = models.CharField(max_length=15, unique=True)  # Hospital Contact Number
#     address = models.TextField()  # Full Address
#     registration_number = models.CharField(max_length=100, unique=True)  # Unique Registration Number
#     verification_status = models.CharField(max_length=10, choices=VERIFICATION_STATUS, default='verified')  # Status of verification

#     def __str__(self):
#         return f"{self.hospital_name} - {self.verification_status}"





# from django.db import models
# from django.utils import timezone

# class PatientDonationStatus(models.Model):
#     status_id = models.AutoField(primary_key=True)  # Auto-incrementing Primary Key
#     patient = models.OneToOneField('Patient', on_delete=models.CASCADE, related_name='donation_status')  # One-to-One relationship with Patient
#     is_active = models.BooleanField(default=False)  # Whether donations are currently active
#     start_time = models.DateTimeField(auto_now_add=True)  # When the status was activated (set when created)
#     end_time = models.DateTimeField(null=True, blank=True)  # When donations should deactivate (based on recovery time)
#     last_updated = models.DateTimeField(auto_now=True)  # Last time the status was updated
#     status = models.CharField(max_length=20, default='active', choices=[
#         ('active', 'Active'),
#         ('completed', 'Completed'),
#         ('deactive', 'Deactive'),
#     ])
#     def __str__(self):
#         return f"Donation Status for {self.patient.full_name} - {'Active' if self.is_active else 'Inactive'}"


#     def check_status(self):
#         """
#         Check if the donation status should be updated based on assistance completion.
#         """
#         assistance = AssistanceRequired.objects.filter(hospital_details__patient=self.patient).first()
#         if assistance and assistance.is_completed():
#             self.status = 'completed'
#             self.is_active = False
#             self.save()
#         return self.is_active

#     def set_end_time(self, expected_recovery_days):
#         """
#         Set the end time based on the expected recovery time in days from HospitalDetails.
#         """
#         if expected_recovery_days:
#             self.end_time = self.start_time + timezone.timedelta(days=expected_recovery_days)
#             self.save()
#         return self.end_time



# from django.db import models
# from django.contrib.auth.models import User
# from django.core.validators import MinValueValidator

# class CareCoin(models.Model):
#     """
#     Simplified model to track Care-Coins for donors.
#     """
#     carecoin_id = models.AutoField(
#         primary_key=True,
#         help_text="Unique autoincrement ID for each Care-Coin transaction."
#     )
    
#     donor = models.ForeignKey(
#         mainuser,
#         on_delete=models.CASCADE,
#         related_name='care_coins',
#         help_text="The donor associated with this transaction."
#     )
    
#     TRANSACTION_TYPES = (
#         ('earned', 'Earned'),
#         ('spent', 'Spent'),
#     )
    
#     transaction_type = models.CharField(
#         max_length=10,
#         choices=TRANSACTION_TYPES,
#         default='earned',
#         help_text="Type of transaction: earned or spent."
#     )
    
#     coins = models.PositiveIntegerField(
#         validators=[MinValueValidator(1)],
#         help_text="Number of Care-Coins earned or spent."
#     )
    
#     DONATION_TYPES = (
#         ('funds', 'Funds'),
#         ('blood', 'Blood'),
#         ('other', 'Other'),
#     )
    
#     donation_type = models.CharField(
#         max_length=20,
#         choices=DONATION_TYPES,
#         help_text="Type of donation triggering this transaction."
#     )
    
#     description = models.TextField(
#         blank=True,
#         help_text="Optional description of the transaction (e.g., 'Donated $50')."
#     )
    
#     created_at = models.DateTimeField(
#         auto_now_add=True,
#         help_text="Timestamp when the transaction was created."
#     )
#     donation_transaction = models.ForeignKey('DonationTransaction', on_delete=models.CASCADE, null=True, blank=True, related_name='care_coin_rewards')
    
#     class Meta:
#         ordering = ['-created_at']
#         verbose_name = "Care-Coin Transaction"
#         verbose_name_plural = "Care-Coin Transactions"
    

#     def __str__(self):
#         return f"CareCoin #{self.carecoin_id} - {self.donor.username} - {self.transaction_type} {self.coins} coins ({self.donation_type})"

#     @property
#     def current_balance(self):
#         """
#         Calculate the donor's current Care-Coin balance.
#         """
#         earned = CareCoin.objects.filter(donor=self.donor, transaction_type='earned').aggregate(total=models.Sum('coins'))['total'] or 0
#         spent = CareCoin.objects.filter(donor=self.donor, transaction_type='spent').aggregate(total=models.Sum('coins'))['total'] or 0
#         return earned - spent
    
    

# class ScratchCard(models.Model):
#     user = models.OneToOneField('mainuser', on_delete=models.CASCADE, related_name='scratch_card')
#     bonus_coins = models.PositiveIntegerField(validators=[MinValueValidator(100)])
#     awarded_at = models.DateTimeField(auto_now_add=True)

#     def save(self, *args, **kwargs):
#         if not self.pk:
#             self.bonus_coins = random.randint(100, 200)
#         super().save(*args, **kwargs)




# # models.py
# from django.db import models
# from .models import mainuser, Patient, HospitalDetails, AssistanceRequired

# class MessageVerification(models.Model):
#     VERIFICATION_STATUS = [
#         ('fake', 'Fake'),
#         ('completed', 'Completed'),
#         ('active', 'Active'),
#     ]
    
#     verification_id = models.AutoField(primary_key=True)
#     user = models.ForeignKey(mainuser, on_delete=models.CASCADE, null=True, blank=True)
#     patient = models.ForeignKey(Patient, on_delete=models.CASCADE, null=True, blank=True)
#     message_image = models.ImageField(upload_to='message_verifications/', null=True, blank=True)
#     patient_id_input = models.CharField(max_length=50, blank=True)
#     issue_input = models.CharField(max_length=200, blank=True)
#     status = models.CharField(max_length=10, choices=VERIFICATION_STATUS, default='fake')
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"Verification {self.verification_id} - {self.status}"
    


# class DonationTransaction(models.Model):
#     TRANSACTION_TYPES = [
#         ('funds', 'Funds'),
#         ('blood', 'Blood Donation'),
#         ('other', 'Other Resources'),
#     ]
    
#     transaction_id = models.AutoField(primary_key=True)
#     donor = models.ForeignKey(mainuser, on_delete=models.CASCADE, related_name='donation_transactions')
#     patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='received_donations')
#     assistance = models.ForeignKey(AssistanceRequired, on_delete=models.CASCADE, related_name='related_transactions')
#     transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES)
#     amount = models.IntegerField(null=True, blank=True)  # For funds (in rupees)
#     blood_type = models.CharField(max_length=10, null=True, blank=True)  # For blood donation
#     quantity = models.CharField(max_length=50, null=True, blank=True)  # For blood donation
#     description = models.TextField(null=True, blank=True)  # For other resources
#     transaction_date = models.DateTimeField(auto_now_add=True)
#     status = models.CharField(max_length=20, default='completed')  # e.g., 'completed', 'pending', 'failed'
#     care_coins_awarded = models.IntegerField(null=True, blank=True)  # Number of Care-Coins awarded for this transaction

#     def __str__(self):
#         return f"{self.donor.full_name} donated {self.transaction_type} for {self.patient.full_name} on {self.transaction_date}"

# # from django.db import models
# #  # hospital = models.ForeignKey('Hospital', on_delete=models.CASCADE)  # ForeignKey to Hospital Model
# # class Patient(models.Model):
# #     patient_id = models.AutoField(primary_key=True)
# #     user = models.ForeignKey('mainuser', on_delete=models.CASCADE)  # Foreign Key to User model
# #     full_name = models.CharField(max_length=255)
# #     age = models.IntegerField()
# #     dob = models.DateField()
# #     gender = models.CharField(max_length=10, choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')])
# #     contact_number = models.CharField(max_length=15, unique=True)
# #     alternate_number = models.CharField(max_length=15, blank=True, null=True)
# #     email = models.EmailField(unique=True, blank=True, null=True)
# #     address = models.TextField()
# #     aadhaar_id = models.CharField(max_length=20, unique=True)
# #     aadhaar_card = models.FileField(upload_to='aadhaar_cards/')

# # class MedicalDetails(models.Model):
# #     medical_id = models.AutoField(primary_key=True)
# #     patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name="medical_details")
# #     hospital_name = models.CharField(max_length=255)
# #     hospital_location = models.TextField()
# #     doctor_name = models.CharField(max_length=255)
# #     doctor_contact = models.CharField(max_length=15)
# #     problem = models.CharField(max_length=255)
# #     description = models.TextField()
# #     prescription = models.FileField(upload_to='prescriptions/')
# #     expected_recovery_time = models.IntegerField(help_text='Time in days')
# #     patient_id_in_hospital=models.IntegerField(default=0)

# # # NEW: Model to handle multiple medical reports
# # class MedicalReport(models.Model):
# #     medical_reportid = models.AutoField(primary_key=True)
# #     medical_details = models.ForeignKey(MedicalDetails, on_delete=models.CASCADE, related_name="medical_reports")
# #     report_file = models.FileField(upload_to='medical_reports/')
# #     report_name=models.CharField(max_length=100)
# #     uploaded_at = models.DateTimeField(auto_now_add=True)


# # from django.db import models

# # class AssistanceRequired(models.Model):
# #     assistance_id = models.AutoField(primary_key=True)
# #     patient = models.ForeignKey('Patient', on_delete=models.CASCADE, related_name="assistance")
# #     assistance_type = models.CharField(max_length=20, choices=[
# #         ('Financial Aid', 'Financial Aid'), 
# #         ('Blood Donation', 'Blood Donation'), 
# #         ('Other Resources', 'Other Resources')
# #     ])
# #     created_at = models.DateTimeField(auto_now_add=True)

# #     def __str__(self):
# #         return f"{self.patient.full_name} - {self.assistance_type}"

# # class FinancialAid(models.Model):
# #     FinancialAid_id =models.AutoField(primary_key=True)
# #     assistance = models.OneToOneField(AssistanceRequired, on_delete=models.CASCADE, related_name="financial_aid")
# #     expected_fund_required = models.DecimalField(max_digits=10, decimal_places=2)
# #     banck_account_name=models.CharField(max_length=200, default="null")
# #     bank_account_holder_name = models.CharField(max_length=255)
# #     bank_account_number = models.CharField(max_length=30)
# #     ifsc_code = models.CharField(max_length=20)
# #     bank_passbook_image = models.FileField(upload_to='bank_passbooks/', blank=True, null=True)
# #     qr_code_image = models.FileField(upload_to='qr_codes/', blank=True, null=True)
# #     upi_ids = models.JSONField(default=list)  # To store multiple UPI IDs as a list

# #     def __str__(self):
# #         return f"Financial Aid for {self.assistance.patient.full_name}"

# # class BloodDonation(models.Model):
# #     BloodDonation_id =models.AutoField(primary_key=True)
# #     assistance = models.OneToOneField(AssistanceRequired, on_delete=models.CASCADE, related_name="blood_donation")
# #     required_blood_group = models.CharField(max_length=5, choices=[
# #         ('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'),
# #         ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-')
# #     ])
# #     blood_quantity = models.IntegerField()
# #     blood_donation_location = models.TextField()

# #     def __str__(self):
# #         return f"Blood Donation for {self.assistance.patient.full_name}"

# # class OtherResources(models.Model):
# #     resources_id=models.AutoField(primary_key=True)
# #     assistance = models.OneToOneField(AssistanceRequired, on_delete=models.CASCADE, related_name="other_resources")
# #     resources_name = models.TextField()

# #     def __str__(self):
# #         return f"Other Resources for {self.assistance.patient.full_name}"




# # from django.db import models

# # class Verification(models.Model):
# #     verification_id = models.AutoField(primary_key=True)
# #     patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name="verifications")
# #     registered_by_patient = models.BooleanField(default=False)
    
# #     # Fields that should be required if registered_by_patient is False
# #     phone_number = models.CharField(max_length=15, blank=True, null=True)
# #     aadhar_card = models.FileField(upload_to='aadhar_cards/', blank=True, null=True)
    
    

# #     status = models.CharField(
# #         max_length=20, 
# #         choices=[
# #             ('Pending', 'Pending'),
# #             ('Verified', 'Verified'),
# #             ('Fake', 'Fake')
# #         ], 
# #         default='Pending'
# #     )

# #     created_at = models.DateTimeField(auto_now_add=True)

# #     def save(self, *args, **kwargs):
# #         """
# #         Override the save method to enforce field requirements based on `registered_by_patient`
# #         """
# #         if self.registered_by_patient:
# #             # If registered by the patient, remove additional info
# #             self.phone_number = None
# #             self.aadhar_card = None
# #         super().save(*args, **kwargs)

# #     def __str__(self):
# #         return f"Verification {self.verification_id} - {self.patient.p_name}"
