# scanner/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanViewSet,VulnerabilityViewSet,CVEViewSet

router = DefaultRouter()
router.register(r'scans', ScanViewSet)

router.register(r'vulns', VulnerabilityViewSet)
router.register(r'CVE', CVEViewSet)


urlpatterns = [
    path('', include(router.urls)),
]
