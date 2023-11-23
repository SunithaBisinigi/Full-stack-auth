# # =================================token implememtation......====================================
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .forms import RegistrationForm, LoginForm
from .models import UserToken
import logging
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.contrib import messages
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
import json

# token generation.......
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# ############################# REGISTRATION ##############################
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
            refresh_token =  tokens['refresh']
            custom_token, created = UserToken.objects.get_or_create(user=user)
            custom_token.access_token = access_token
            custom_token.refresh_token = refresh_token
            custom_token.save()
            # Log in the user using the access token
            user = authenticate(request, username=username, password=password1)
            if user is not None:
                login(request, user)              
                print("at line number 288----------",type(access_token))
                # Prepare the access token for sending to the frontend
                access_token_dict = {
                    'access_token': access_token,
                }
                messages.success(request, 'Registration successful')
                # Return the access token to the frontend
                response =JsonResponse(access_token_dict)
                # Store the access token in local storage
                response.set_cookie('access_token', access_token, max_age=3, httponly=True)  # Adjust the max_age as needed
                return response
            else:
                messages.error(request, 'Failed to authenticate user.')
        else:
            messages.error(request, 'Invalid form data')
    else:
        form = RegistrationForm()

    return render(request, 'registration.html', {'form': form})

##################################  LOGIN  ########################################
@csrf_exempt  # Disable CSRF protection for this view
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        print("form data-------------------------", request)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            print("getting user object................................................", user)
            if user:
                # login(request, user)
                try:
                    user_token, created = UserToken.objects.get_or_create(user=user)
                    refresh = RefreshToken(user_token.refresh_token)
                    access_token = user_token.access_token
                except Token.DoesNotExist:
                    access_token = None
                if access_token:
                    return JsonResponse({'message': 'Login successful', 'access_token': access_token})
                else:
                    return JsonResponse({'error': 'Access token not found'}, status=400)
            else:
                return JsonResponse({'error': 'Invalid username or password'}, status=400)
        else:
            return JsonResponse({'error': 'Invalid form data', 'form_errors': form.errors}, status=400)
    else:
        form = LoginForm()
        return render(request, 'login.html', {'form': form, 'error_message': 'Invalid username or password'})


#########################  HOME ###########################################################
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def home(request):
    if request.user.is_authenticated:
        return render(request, 'home.html')
    else:
        return redirect('login')
def get_user_details(request):
    user = request.user
    user_data = {
        'username': user.username,
        'email': user.email,
    }
    print("GET USER DETAILS--------------------------------------------", user_data)
    return JsonResponse(user_data)

