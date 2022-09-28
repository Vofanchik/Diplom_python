from webbrowser import get
from django.core.validators import URLValidator
from django.http import JsonResponse
from django.shortcuts import render
from rest_framework import viewsets, generics
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from yaml import load as load_yaml, Loader

from rest_api.models import ProductInfo, Product, Category, Shop, ProductParameter, Parameter, User
from rest_api.serializers import UserSerializer, LoginSerializer

from .models import USER_TYPE_CHOICES


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    http_method_names = ['get', 'post', 'patch']
    serializer_class = UserSerializer


    def get_object(self):
        user = User.objects.filter(pk=self.request.user.pk)
        if user:
            return user.first()
        raise ValidationError({'error': 'token not provided'})

    def create(self, request, *args, **kwargs):
        if request.data['type'] not in ['shop', 'buyer']:
            return ValidationError(
                {'role': f'correct choices: {USER_TYPE_CHOICES}'}
            )
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = User.objects.create(**serializer.validated_data)
        user.set_password(password)
        user.save()
        return Response(self.serializer_class(user).data)


class UserLoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = User.objects.filter(email=email)
        if not user:
            raise ValidationError({'error': 'user not found'})
        if not user or not user.first().check_password(password):
            return Response(
                {'error': 'wrong credentials'},
                status=401
            )
        token, _ = Token.objects.get_or_create(user=user.first())
        return Response({'token': token.key})


class PartnerUpdate(APIView):
    """
    Класс для обновления прайса от поставщика
    """
    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        url = request.query_params.get('url')
        print(url)
        if url:
            validate_url = URLValidator()
            try:
                validate_url(url)
            except ValidationError as e:
                return JsonResponse({'Status': False, 'Error': str(e)})
            else:
                stream = get(url).content

                # stream = open(url, 'r')
                data = load_yaml(stream, Loader=Loader)

                shop, _ = Shop.objects.get_or_create(name=data['shop'], user_id=request.user.id)
                for category in data['categories']:
                    category_object, _ = Category.objects.get_or_create(id=category['id'], name=category['name'])
                    category_object.shops.add(shop.id)
                    category_object.save()
                ProductInfo.objects.filter(shop_id=shop.id).delete()
                for item in data['goods']:
                    product, _ = Product.objects.get_or_create(name=item['name'], category_id=item['category'])

                    product_info = ProductInfo.objects.create(product_id=product.id,
                                                              external_id=item['id'],
                                                              model=item['model'],
                                                              price=item['price'],
                                                              price_rrc=item['price_rrc'],
                                                              quantity=item['quantity'],
                                                              shop_id=shop.id)
                    for name, value in item['parameters'].items():
                        parameter_object, _ = Parameter.objects.get_or_create(name=name)
                        ProductParameter.objects.create(product_info_id=product_info.id,
                                                        parameter_id=parameter_object.id,
                                                        value=value)

                return JsonResponse({'Status': True})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})
