from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'events', views.EventViewSet)
router.register(r'alerts', views.AlertViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('ingest/', views.ingest, name='ingest'),
    path('alerts/<int:alert_id>/status/', views.update_alert_status, name='update_alert_status'),
]
