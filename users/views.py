import os
import requests
from django.shortcuts import render, redirect, reverse
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import FormView
from django.contrib.auth import authenticate, login, logout
from . import forms, models


# Create your views here.
# class LoginView(View):
#     def get(self, request):
#         form = forms.LoginForm(initial={'email': 'admin@gmail.com'})
#         return render(request, 'users/login.html', {
#             'form': form,
#         })
#
#     def post(self, request):
#         form = forms.LoginForm(request.POST)
#         if form.is_valid():
#             email = form.cleaned_data.get('email')
#             password = form.cleaned_data.get('password')
#             user = authenticate(request, username=email, password=password)
#             if user is not None:
#                 login(request, user)
#                 return redirect('core:home')
#         return render(request, 'users/login.html', {
#             'form': form,
#         })

class LoginView(FormView):
    template_name = 'users/login.html'
    form_class = forms.LoginForm
    success_url = reverse_lazy('core:home')
    initial = {
        'email': 'webdornald@gmail.com'
    }

    def form_valid(self, form):
        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password')
        user = authenticate(self.request, username=email, password=password)
        if user is not None:
            login(self.request, user)
        return super().form_valid(form)


def log_out(request):
    logout(request)
    return redirect('core:home')


class SignUpView(FormView):
    template_name = 'users/signup.html'
    form_class = forms.SignUpForm
    success_url = reverse_lazy('core:home')
    initial = {
        'first_name': 'jaeseong',
        'last_name': 'kim',
        'email': 'webdornald@naver.com',
    }

    def form_valid(self, form):
        form.save()
        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password1')
        user = authenticate(self.request, username=email, password=password)
        if user is not None:
            login(self.request, user)
        user.verify_email()
        return super().form_valid(form)


def complete_verification(request, key):
    try:
        user = models.User.objects.get(email_secret=key)
        user.email_verified = True
        user.email_secret = ''
        user.save()
        # todo: add success message
    except models.User.DoesNotExist:
        # todo: add error message
        pass
    return redirect('core:home')


def github_login(request):
    client_id = os.environ.get('GITHUB_ID')
    redirect_uri = 'http://127.0.0.1:8000/users/login/github/callback'
    return redirect(f'https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=read:user')


class GithubException(Exception):
    pass


def github_callback(request):
    try:
        client_id = os.environ.get('GITHUB_ID')
        client_secret = os.environ.get('GITHUB_SECRET')
        code = request.GET.get('code', None)
        if code is not None:
            token_request = requests.post(f'https://github.com/login/oauth/access_token?client_id={client_id}&client_secret={client_secret}&code={code}', headers={
                "Accept": 'application/json'
            })
            token_json = token_request.json()
            error = token_json.get('error', None)
            if error is not None:
                raise GithubException()
            else:
                access_token = token_json.get('access_token')
                profile_request = requests.get('https://api.github.com/user', headers={
                    'Authorization': f'token {access_token}',
                    'Accept': 'application/json',
                })
                profile_json = profile_request.json()
                username = profile_json.get('login', None)
                if username is not None:
                    name = profile_json.get('name')
                    email = profile_json.get('email')
                    bio = profile_json.get('bio')
                    name = username if name is None else name
                    email = name if email is None else email
                    bio = "" if bio is None else bio
                    try:
                        print(name, email, bio)
                        user = models.User.objects.get(email=email)
                        if user.login_method != models.User.LOGIN_GITHUB:
                            raise GithubException()
                    except models.User.DoesNotExist:
                        user = models.User.objects.create(email=email, first_name=name, username=email, bio=bio, login_method=models.User.LOGIN_GITHUB)
                        user.set_unusable_password()
                        user.save()
                    login(request, user)
                    return redirect('core:home')
                else:
                    raise GithubException()
        else:
            raise GithubException()
    except GithubException:
        # send error message
        return redirect('users:login')