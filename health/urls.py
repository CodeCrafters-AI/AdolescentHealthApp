# health/urls.py
from django.urls import path
from .views import (RegisterUser, LoginUser, LogoutUser, DashboardView, UpdateDashboard, SymptomChecker,
                    MentalHealthResources, MentalHealthSelfAssessment, BookTherapistSession,
                    ReproductiveHealthArticles, MenstrualTracker, AskConfidentialQuestion,
                    BookAppointment, AppointmentReminders, NutritionPlan, FitnessTracker,
                    GuardianAccessRequest, GuardianViewData)

urlpatterns = [
    path('register/', RegisterUser.as_view(), name='register'),
    path('login/', LoginUser.as_view(), name='login'),
    path('logout/', LogoutUser.as_view(), name='logout'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('dashboard/update/', UpdateDashboard.as_view(), name='dashboard-update'),
    path('symptoms/check/', SymptomChecker.as_view(), name='symptoms-check'),
    path('mentalhealth/resources/', MentalHealthResources.as_view(), name='mentalhealth-resources'),
    path('mentalhealth/self-assessment/', MentalHealthSelfAssessment.as_view(), name='mentalhealth-self-assessment'),
    path('mentalhealth/book-session/', BookTherapistSession.as_view(), name='mentalhealth-book-session'),
    path('reproductive-health/articles/', ReproductiveHealthArticles.as_view(), name='reproductive-health-articles'),
    path('reproductive-health/menstrual-tracker/', MenstrualTracker.as_view(), name='menstrual-tracker'),
    path('reproductive-health/ask-question/', AskConfidentialQuestion.as_view(), name='ask-question'),
    path('appointments/book/', BookAppointment.as_view(), name='book-appointment'),
    path('appointments/reminders/', AppointmentReminders.as_view(), name='appointment-reminders'),
    path('nutrition/plan/', NutritionPlan.as_view(), name='nutrition-plan'),
    path('fitness/tracker/', FitnessTracker.as_view(), name='fitness-tracker'),
    path('guardian/access-request/', GuardianAccessRequest.as_view(), name='guardian-access-request'),
    path('guardian/view-data/', GuardianViewData.as_view(), name='guardian-view-data'),
]
