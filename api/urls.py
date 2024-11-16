# scanner/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanViewSet,VulnerabilityViewSet

router = DefaultRouter()
router.register(r'scans', ScanViewSet)

router.register(r'vulns', VulnerabilityViewSet)


urlpatterns = [
    path('', include(router.urls)),
]
