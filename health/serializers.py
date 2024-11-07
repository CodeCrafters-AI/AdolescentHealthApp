# health/serializers.py
from rest_framework import serializers
from .models import CustomUser, HealthMetrics, MentalHealth, PeriodTracker, DietSuggestion

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'is_adolescent', 'is_guardian']

class HealthMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = HealthMetrics
        fields = '__all__'

class MentalHealthSerializer(serializers.ModelSerializer):
    class Meta:
        model = MentalHealth
        fields = '__all__'

class PeriodTrackerSerializer(serializers.ModelSerializer):
    class Meta:
        model = PeriodTracker
        fields = '__all__'

class DietSuggestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = DietSuggestion
        fields = '__all__'
