from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views
urlpatterns = [
      path('', views.openingpage, name='openingpage'),
      
    path('index/', views.index, name='index'),
   path('about',views.about,name="about"),
    path('overview',views.overviewpage, name="overviewpage"),
    path('selectuser',views.selectuser, name="selectuser"),
    path('patient',views.user_patient, name="patient"),
    path('patient_homepage',views.patient_homepage,name="patient_homepage"),
    path('user_signup', views.user_signup, name="user_signup"),
    
    
    path('password_options/',views.password_options,name="password_options"),
    path('forgotpassword/',views.forgotpass, name='forgotpassword'),
    path('password_reset/', views.password_reset_request, name='password_reset'),
    path('password_reset/done/', views.password_reset_done, name='password_reset_done'),
    path('fgpm', views.fgpm, name='fgpm'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
       path('reset/done/', views.password_reset_complete, name='password_reset_complete'),
    
    
    
    path('register_user',views.register_user, name="register_user"),
    
       path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    
    path('user_login',views.user_login, name="user_login"),
    
    path('user_login_operation',views.user_login_operation,name="user_login_operation"),
    path('user_logout', views.user_logout, name='user_logout'),
    
    
    
    
    path('user_dashboard',views.user_dashboard,name="user_dashboard"),
    path('reveal-scratch-card/', views.reveal_scratch_card, name='reveal_scratch_card'),
    
   #  path('patient-status/<int:patient_id>/', views.patient_status, name='patient_status'),
   path('patient-status/<int:patient_id>/', views.patient_status, name='patient_status'),
    
    
    
    path('patient_request_for_slot',views.patient_request_for_slot,name="patient_request_for_slot"),
    
    
    path('patient_registration',views.patient_registration,name="patient_registration"),
path('patient/<int:patient_id>/', views.patient_detail, name='patient_detail'),
    path('donate/<int:patient_id>/', views.donate, name='donate'),
    path('share/<int:patient_id>/<str:platform>/', views.share_patient, name='share_patient'),
    
    
    path('care-coins/', views.care_coins, name='care_coins'),
    
    
    path('donor-patient-detail/<int:patient_id>/', views.donor_patient_detail, name='donor_patient_detail'),
    
    
    path('donate-to-patient/<int:patient_id>/', views.donate_to_patient, name='donate_to_patient'),
    
    path('donation-callback/<int:patient_id>/', views.donation_callback, name='donation_callback'),
    
    
    path('message-guard/', views.message_guard, name='message_guard'),
    path('message-guard-result/<int:verification_id>/', views.message_guard_result, name='message_guard_result'),
    # Existing paths...
    
    
    path('donor-donation-history/', views.donor_donation_history, name='donor_donation_history'),
    path('patient-donation-history/<int:patient_id>/', views.patient_donation_history, name='patient_donation_history'),
    
    
    path('donation-success/', views.donation_success, name='donation_success'),  # Add this line


path('donate-to-care-storage/', views.donate_to_care_storage, name='donate_to_care_storage'),
    path('care-storage-donation-callback/', views.care_storage_donation_callback, name='care_storage_donation_callback'),
    
   #  path('donate-to-care-storage/<int:donor_id>/', views.donate_to_care_storage, name='donate_to_care_storage'),
   #  path('care-storage-donation-callback/<int:donor_id>/', views.care_storage_donation_callback, name='care_storage_donation_callback'),
    
    
   #  path('view-savior-requests/<int:patient_id>/', views.view_savior_requests, name='view_savior_requests'),
   #  path('view-patient-details/<int:donor_id>/', views.view_patient_details, name='view_patient_details'),
    
    
   #  path('register-as-both-sides/<int:donor_id>/', views.register_as_both_sides, name='register_as_both_sides'),
   #  path('view-savior-requests/<int:patient_id>/', views.view_savior_requests, name='view_savior_requests'),
    path('view-patient-details/<int:donor_id>/', views.view_patient_details, name='view_patient_details'),
path('register-as-both-sides/<int:donor_id>/', views.register_as_both_sides, name='register_as_both_sides'),
    path('view-savior-requests/<int:patient_id>/', views.view_savior_requests, name='view_savior_requests'),



 path('send-request/', views.send_request_to_past_patients, name='send_request_to_past_patients'),


path("services_role",views.services_role,name="services_role"),
path("helppage",views.helppage,name="helppage"),

path('donate-resources/', views.donate_resources, name='donate_resources'),
path('index_services',views.index_services,name="index_services"),
path("index_help",views.index_help,name="index_help"),

 path("contact-us/", views.contact_us, name="contact_us"),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


