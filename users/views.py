import os
import requests
from django.contrib.auth.views import PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
from django.shortcuts import render, redirect, reverse
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import FormView, DetailView, UpdateView
from django.contrib.auth import authenticate, login, logout
from django.core.files.base import ContentFile
from django.contrib import messages
from . import forms, models, mixins


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

class LoginView(mixins.LoggedOutOnlyView, FormView):
    template_name = 'users/login.html'
    form_class = forms.LoginForm
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

    # 넥스트 아규먼트의 값을 받아와 다음 url로 변경한다.
    def get_success_url(self):
        next_arg = self.request.GET.get('next')
        if next_arg is not None:
            return next_arg
        else:
            return reverse('core:home')


def log_out(request):
    messages.info(request, f'See you later {request.user.first_name}')
    logout(request)
    return redirect('core:home')


class SignUpView(FormView):
    template_name = 'users/signup.html'
    form_class = forms.SignUpForm
    success_url = reverse_lazy('core:home')

    def form_valid(self, form):
        form.save()
        email = form.cleaned_data.get('email')  # ModelForm 사용시 'username'을 'email'로 바꿔야 한다.
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
    return redirect(
        f'https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=read:user')


class GithubException(Exception):
    pass


def github_callback(request):
    try:
        client_id = os.environ.get('GITHUB_ID')
        client_secret = os.environ.get('GITHUB_SECRET')
        code = request.GET.get('code', None)
        if code is not None:
            token_request = requests.post(
                f'https://github.com/login/oauth/access_token?client_id={client_id}&client_secret={client_secret}&code={code}',
                headers={
                    "Accept": 'application/json'
                })
            token_json = token_request.json()
            error = token_json.get('error', None)
            if error is not None:
                raise GithubException("Can't get access token")
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
                            raise GithubException(f'Please log in with: {user.login_method}')
                    except models.User.DoesNotExist:
                        user = models.User.objects.create(
                            email=email,
                            first_name=name,
                            username=email,
                            bio=bio,
                            login_method=models.User.LOGIN_GITHUB,
                            email_verified=True,
                        )
                        user.set_unusable_password()
                        user.save()
                    login(request, user)
                    messages.success(request, f'Welcome back {user.first_name}')
                    return redirect('core:home')
                else:
                    raise GithubException("Can't get your profile")
        else:
            raise GithubException("Can't get code")
    except GithubException as e:
        messages.error(request, e)
        return redirect('users:login')


def kakao_login(request):
    REST_API_KEY = os.environ.get('KAKAO_ID')
    REDIRECT_URI = 'http://127.0.0.1:8000/users/login/kakao/callback'
    return redirect(
        f'https://kauth.kakao.com/oauth/authorize?client_id={REST_API_KEY}&redirect_uri={REDIRECT_URI}&response_type=code')


class KakaoException(Exception):
    pass


def kakao_callback(request):
    try:
        code = request.GET.get('code')
        client_id = os.environ.get('KAKAO_ID')
        redirect_uri = 'http://127.0.0.1:8000/users/login/kakao/callback'
        token_request = requests.get(
            f'https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={redirect_uri}&code={code}')
        token_json = token_request.json()
        error = token_json.get('error', None)
        if error is not None:
            raise KakaoException("Can't get authorization code.")
        access_token = token_json.get('access_token')
        profile_request = requests.get('https://kapi.kakao.com/v2/user/me',
                                       headers={'Authorization': f'Bearer {access_token}'})
        profile_json = profile_request.json()
        email = profile_json.get('kakao_account').get('email')
        if email is None:
            raise KakaoException('Please also give me your email.')
        properties = profile_json.get('properties')
        nickname = properties.get('nickname')
        profile_image = properties.get('profile_image')
        try:
            user = models.User.objects.get(email=email)
            if user.login_method != models.User.LOGIN_KAKAO:
                raise KakaoException(f"Please log in with {user.login_method}")
        except models.User.DoesNotExist:
            user = models.User.objects.create(
                email=email,
                username=email,
                first_name=nickname,
                login_method=models.User.LOGIN_KAKAO,
                email_verified=True,
            )
            user.set_unusable_password()
            user.save()
            if profile_image is not None:
                photo_request = requests.get(profile_image)
                user.avatar.save(f'{nickname}-avatar.jpeg', ContentFile(photo_request.content))
        login(request, user)
        messages.success(request, f'Welcome back {user.first_name}')
        return redirect('core:home')
    except KakaoException as e:
        messages.error(request, e)
        return redirect('users:login')


class UserProfileView(DetailView):
    model = models.User
    context_object_name = 'user_obj'


class UpdateProfileView(mixins.LoggedInOnlyView, SuccessMessageMixin, UpdateView):
    model = models.User
    template_name = 'users/update_profile.html'
    fields = (
        "first_name",
        "last_name",
        "gender",
        "bio",
        "birthdate",
        "language",
        "currency",
    )
    success_message = 'Profile Updated'

    def get_object(self, queryset=None):
        return self.request.user

    # 만약 email을 변경할 수 있다면 거기에 맞춰 username을 변경한다.(validate 테스트는?)
    # def form_valid(self, form):
    #     email = form.clean_data.get('email')
    #     self.object.username = email
    #     self.object.save()
    #     return super().form_valid(form)

    def get_form(self, form_class=None):
        form = super().get_form(form_class=form_class)
        form.fields['first_name'].widget.attrs = {'placeholder': 'First name'}
        form.fields['last_name'].widget.attrs = {'placeholder': 'Last name'}
        form.fields['gender'].widget.attrs = {'placeholder': 'Gender'}
        form.fields['bio'].widget.attrs = {'placeholder': 'Bio'}
        form.fields['birthdate'].widget.attrs = {'placeholder': 'Birthdate'}
        form.fields['language'].widget.attrs = {'placeholder': 'Language'}
        form.fields['currency'].widget.attrs = {'placeholder': 'Currency'}
        return form


class UpdatePasswordView(
    mixins.EmailLoginOnlyView,
    mixins.LoggedInOnlyView,
    SuccessMessageMixin,
    PasswordChangeView
):
    template_name = 'users/update_password.html'
    success_message = 'Password Updated'

    def get_form(self, form_class=None):
        form = super().get_form(form_class=form_class)
        form.fields['old_password'].widget.attrs = {'placeholder': 'Current password'}
        form.fields['new_password1'].widget.attrs = {'placeholder': 'New password'}
        form.fields['new_password2'].widget.attrs = {'placeholder': 'Confirm password'}
        return form

    def get_success_url(self):
        return self.request.user.get_absolute_url()