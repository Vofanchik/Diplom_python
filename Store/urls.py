
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

from rest_api.views import UserViewSet, UserLoginView, PartnerUpdate, ProductInfoView, AccountDetails

router = routers.SimpleRouter()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('products/', ProductInfoView.as_view(), name='products'),
    path('update/', PartnerUpdate.as_view(), name='example'),
    path('users/', include([
            path('login/', UserLoginView.as_view()),
            path('register/', UserViewSet.as_view({'post': 'create'})),
            path('account/', AccountDetails.as_view(), name='acc'),

        ])),


]
