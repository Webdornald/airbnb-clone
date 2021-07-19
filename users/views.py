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