# # =================================token implememtation......====================================
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from .forms import RegistrationForm, LoginForm
from .models import UserToken
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from django.contrib import messages
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from calendar import timegm
from datetime import datetime
import json
# token generation.......
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# ############################# REGISTRATION ##############################
# @csrf_exempt
# def registration(request):
#     if request.method == 'POST':
#         form = RegistrationForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             email = form.cleaned_data['email']
#             password1 = form.cleaned_data['password1']
#             password2 = form.cleaned_data['password2']
#             # Check if the email already exists
#             if User.objects.filter(email=email).exists():
#                 messages.error(request, 'Email already exists. Please use a different email.')
#                 return redirect('registration')  
#             user = User.objects.create_user(username=username, email=email, password=password1)
#             tokens = get_tokens_for_user(user)
#             access_token = tokens['access']
#             custom_token, created = UserToken.objects.get_or_create(user=user)
#             refresh_token =  tokens['refresh']
#             custom_token.access_token = access_token
#             custom_token.refresh_token = refresh_token
#             custom_token.save()
#             # Log in the user using the access token
#             user = authenticate(request, username=username, password=password1)
#             if user is not None:
#                 login(request, user)              
#                 print("at line number 288----------",type(access_token))
#                 # Prepare the access token for sending to the frontend
#                 access_token_dict = {
#                     'access_token': access_token,
#                 }
#                 messages.success(request, 'Registration successful')
#                 # Return the access token to the frontend
#                 response =JsonResponse(access_token_dict)
#                 # Store the access token in local storage
#                 response.set_cookie('access_token', access_token, max_age=3600, httponly=True, samesite='Lax') # Adjust the max_age as needed
#                 return response
#             else:
#                 messages.error(request, 'Failed to authenticate user.')
#         else:
#             messages.error(request, 'Invalid form data')
#     else:
#         form = RegistrationForm()

#     return render(request, 'registration.html', {'form': form})


@csrf_exempt
def registration(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']
            
            # Check if the email already exists
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists. Please use a different email.')
                return redirect('registration')  
            
            user = User.objects.create_user(username=username, email=email, password=password1)
            tokens = get_tokens_for_user(user)
            access_token = tokens['access']
            
            # Save the access token in your UserToken model
            custom_token, created = UserToken.objects.get_or_create(user=user)
            custom_token.access_token = access_token
            custom_token.refresh_token = tokens['refresh']
            custom_token.save()
            
            # Prepare the access token for sending to the frontend
            access_token_dict = {
                'access_token': access_token,
            }
            
            # Return the access token to the frontend
            response = JsonResponse(access_token_dict)
            
            # Store the access token in a cookie
            response.set_cookie('access_token', access_token, max_age=3600*3, httponly=True, samesite='Lax')  # Adjust the max_age as needed
            
            return response

    # If the request is not a POST or form validation fails, render the registration form
    form = RegistrationForm()
    return render(request, 'registration.html', {'form': form})


##################################  LOGIN  ########################################

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        print("sunitha--------------------",data)
        username = data['username']
        password = data['password']
        user = authenticate(request, username=username, password=password)
        print("getting user object................................................", user)
        if user:
            try:
                user_token, created = UserToken.objects.get_or_create(user=user)
                refresh = RefreshToken(user_token.refresh_token)
                access_token = user_token.access_token
                print("line----------------131")
            except UserToken.DoesNotExist:
                access_token = None
            print("access token------------------",type(access_token))
            if access_token :
                print("line----------------137")
                return JsonResponse({'message': 'Login successful', 'access_token': access_token})
            else:
                print("line----------------140")
                return JsonResponse({'error': 'Access token not found'}, status=400)
        else:
            print("line----------------143")
            return JsonResponse({'error': 'Invalid username or password'}, status=400)
    else:
        print("The request method is: ", request.method)
        form = LoginForm()
        return render(request, 'login.html', {'form': form, 'error_message': 'Invalid username or password'})

    return JsonResponse({'error': 'Invalid form data', 'form_errors': form.errors}, status=400)



#########################  HOME ###########################################################


# #############################################  home page with default jwt validation-------
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect
from rest_framework_simplejwt.authentication import JWTAuthentication as BaseJSONWebTokenAuthentication
from django.views.decorators.csrf import csrf_exempt
class CustomJWTAuthentication(BaseJSONWebTokenAuthentication):
    def get_jwt_value(self, request):
        return request.COOKIES.get('access_token')

from django.http import JsonResponse

@csrf_exempt
def home(request):
    print("home request00000000000000", request.body)
    try:
        authentication = CustomJWTAuthentication()
        user, auth = authentication.authenticate(request)
        if user is not None:
            return render(request, 'home.html')
    except:
        # If authentication fails or the token is expired, redirect to login
        return JsonResponse({'error': 'Authentication failed or token expired'}, status=401)

@csrf_exempt
def get_user_details(request):
    user = request.user
    if user.is_authenticated:
        user_data = {
            'username': user.username,
            'email': user.email,
        }
        print("GET USER DETAILS--------------------------------------------", user_data)
        return JsonResponse(user_data)
    else:
        return HttpResponseBadRequest("Invalid or expired token")


