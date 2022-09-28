
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

from rest_api.views import UserViewSet, UserLoginView, PartnerUpdate

router = routers.SimpleRouter()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/example', PartnerUpdate.as_view(), name='example'),
    path('users/', include([
            path('login/', UserLoginView.as_view()),
            path('register/', UserViewSet.as_view({'post': 'create'})),

        ]))
]
