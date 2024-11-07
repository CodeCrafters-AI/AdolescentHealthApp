# health/views.py

from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import CustomUser, HealthMetrics, MentalHealth, PeriodTracker, DietSuggestion
from .serializers import (CustomUserSerializer, HealthMetricsSerializer, MentalHealthSerializer,
                          PeriodTrackerSerializer, DietSuggestionSerializer)
from rest_framework.exceptions import PermissionDenied


# --- User Management ---

class RegisterUser(APIView):
    """
    POST /register
    Register a new user (adolescent or guardian)
    """

    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginUser(APIView):
    """
    POST /login
    Authenticate user and issue JWT token
    """

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutUser(APIView):
    """
    POST /logout
    Invalidate the session token
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# --- Health Dashboard ---

class DashboardView(APIView):
    """
    GET /dashboard
    Retrieve the overview of adolescent’s health metrics
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        health_metrics = HealthMetrics.objects.filter(user=request.user).last()
        if health_metrics:
            serializer = HealthMetricsSerializer(health_metrics)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"error": "No health metrics found"}, status=status.HTTP_404_NOT_FOUND)


class UpdateDashboard(APIView):
    """
    POST /dashboard/update
    Update the user's health data (sleep, exercise, water intake, mood)
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        health_metrics = HealthMetrics.objects.filter(user=request.user).last()
        serializer = HealthMetricsSerializer(health_metrics, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# --- Symptom Checker ---

class SymptomChecker(APIView):
    """
    POST /symptoms/check
    Submit a list of symptoms and receive health advice
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        symptoms = request.data.get('symptoms')
        if not symptoms:
            return Response({"error": "No symptoms provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Simulated health advice logic
        advice = "Based on your symptoms, it's advised to rest and stay hydrated."
        return Response({"advice": advice}, status=status.HTTP_200_OK)


# --- Mental Health Support ---

class MentalHealthResources(APIView):
    """
    GET /mentalhealth/resources
    Access mental health resources (articles, videos, tips)
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        resources = {
            "articles": ["5 Tips for Managing Stress", "How to Practice Mindfulness"],
            "videos": ["Mental Wellness 101", "Guided Meditation"],
            "tips": ["Take deep breaths", "Exercise regularly"]
        }
        return Response(resources, status=status.HTTP_200_OK)


class MentalHealthSelfAssessment(APIView):
    """
    POST /mentalhealth/self-assessment
    Submit responses to a mental health self-assessment survey
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = MentalHealthSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({"message": "Self-assessment submitted successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BookTherapistSession(APIView):
    """
    POST /mentalhealth/book-session
    Book an appointment with a therapist or counselor
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        therapist = request.data.get("therapist")
        session_time = request.data.get("session_time")
        if therapist and session_time:
            # Simulated booking logic
            return Response({"message": f"Session booked with {therapist} at {session_time}"},
                            status=status.HTTP_201_CREATED)
        return Response({"error": "Missing therapist or session time"}, status=status.HTTP_400_BAD_REQUEST)


# --- Sexual and Reproductive Health ---

class ReproductiveHealthArticles(APIView):
    """
    GET /reproductive-health/articles
    Access articles related to sexual and reproductive health for adolescents
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        articles = [
            "Understanding Puberty",
            "Managing Menstrual Health"
        ]
        return Response({"articles": articles}, status=status.HTTP_200_OK)


class MenstrualTracker(APIView):
    """
    POST /reproductive-health/menstrual-tracker
    Submit menstrual cycle data for tracking
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PeriodTrackerSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response({"message": "Menstrual data submitted successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AskConfidentialQuestion(APIView):
    """
    POST /reproductive-health/ask-question
    Submit a confidential health question to a professional
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        question = request.data.get("question")
        if question:
            # Simulated confidential question submission
            return Response({"message": "Question submitted successfully"}, status=status.HTTP_201_CREATED)
        return Response({"error": "Question not provided"}, status=status.HTTP_400_BAD_REQUEST)


# --- Appointments and Reminders ---

class BookAppointment(APIView):
    """
    POST /appointments/book
    Book an appointment with a healthcare provider
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        provider = request.data.get("provider")
        appointment_time = request.data.get("appointment_time")
        if provider and appointment_time:
            # Simulated appointment booking
            return Response({"message": f"Appointment booked with {provider} at {appointment_time}"},
                            status=status.HTTP_201_CREATED)
        return Response({"error": "Missing provider or appointment time"}, status=status.HTTP_400_BAD_REQUEST)


class AppointmentReminders(APIView):
    """
    GET /appointments/reminders
    Retrieve upcoming appointment and vaccination reminders
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        reminders = {
            "appointments": ["Doctor visit on 2024-10-25", "Vaccination on 2024-11-05"],
        }
        return Response(reminders, status=status.HTTP_200_OK)


# --- Fitness and Nutrition ---

class NutritionPlan(APIView):
    """
    GET /nutrition/plan
    Receive a personalized nutrition plan
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        plan = {
            "breakfast": "Oatmeal with fruits",
            "lunch": "Grilled chicken with vegetables",
            "dinner": "Salmon with quinoa"
        }
        return Response(plan, status=status.HTTP_200_OK)


class FitnessTracker(APIView):
    """
    POST /fitness/tracker
    Log daily fitness activities
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        activity = request.data.get("activity")
        if activity:
            # Simulated fitness tracking logic
            return Response({"message": "Activity logged successfully"}, status=status.HTTP_201_CREATED)
        return Response({"error": "Activity not provided"}, status=status.HTTP_400_BAD_REQUEST)

# --- Guardian Access ---

class GuardianAccessRequest(APIView):
    """
    POST /guardian/access-request
    Request access to an adolescent’s health data (with adolescent consent)
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Assume guardian requests access from an adolescent
        adolescent_id = request.data.get("adolescent_id")
        adolescent = CustomUser.objects.filter(id=adolescent_id, is_adolescent=True).first()
        if adolescent:
            # Simulate sending a consent request to the adolescent
            return Response({"message": "Access request sent to adolescent"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid adolescent ID"}, status=status.HTTP_400_BAD_REQUEST)


class GuardianViewData(APIView):
    """
    GET /guardian/view-data
    View the permitted health data for the adolescent
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Assume guardian has access to adolescent's health data
        adolescent_id = request.query_params.get("adolescent_id")
        adolescent = CustomUser.objects.filter(id=adolescent_id, is_adolescent=True).first()

        if adolescent and request.user.is_guardian:
            health_metrics = HealthMetrics.objects.filter(user=adolescent).last()
            mental_health = MentalHealth.objects.filter(user=adolescent).last()
            period_data = PeriodTracker.objects.filter(user=adolescent).last()

            data = {
                "health_metrics": HealthMetricsSerializer(health_metrics).data if health_metrics else None,
                "mental_health": MentalHealthSerializer(mental_health).data if mental_health else None,
                "period_data": PeriodTrackerSerializer(period_data).data if period_data else None,
            }
            return Response(data, status=status.HTTP_200_OK)

        return Response({"error": "Unauthorized or adolescent data not found"}, status=status.HTTP_403_FORBIDDEN)

# Error Handling Views (customized)
def handle_400_bad_request(request, exception=None):
    return Response({"error": "Invalid input data"}, status=status.HTTP_400_BAD_REQUEST)

def handle_401_unauthorized(request, exception=None):
    return Response({"error": "Missing or invalid authentication token"}, status=status.HTTP_401_UNAUTHORIZED)

def handle_403_forbidden(request, exception=None):
    return Response({"error": "Unauthorized access to the resource"}, status=status.HTTP_403_FORBIDDEN)

def handle_404_not_found(request, exception=None):
    return Response({"error": "Resource not found"}, status=status.HTTP_404_NOT_FOUND)

def handle_500_server_error(request):
    return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Registering custom error handlers
def custom_error_handlers(app):
    app.add_error_handler(400, handle_400_bad_request)
    app.add_error_handler(401, handle_401_unauthorized)
    app.add_error_handler(403, handle_403_forbidden)
    app.add_error_handler(404, handle_404_not_found)
    app.add_error_handler(500, handle_500_server_error)
