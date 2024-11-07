# health/models.py

from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    is_adolescent = models.BooleanField(default=False)
    is_guardian = models.BooleanField(default=False)

class HealthMetrics(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    sleep_hours = models.FloatField()
    exercise_hours = models.FloatField()
    water_intake = models.FloatField()
    mood = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

class MentalHealth(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    assessment_score = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

class PeriodTracker(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    last_period_date = models.DateField()
    cycle_length = models.IntegerField()

class DietSuggestion(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    suggestion = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
