from django import forms
from . import models


class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'placeholder': 'Email'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))

    def clean(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')
        try:
            user = models.User.objects.get(email=email)
            if user.check_password(password):
                return self.cleaned_data
            else:
                self.add_error('password', forms.ValidationError('Password is wrong'))
        except models.User.DoesNotExist:
            self.add_error('email', forms.ValidationError('User does not exist'))


class SignUpForm(forms.ModelForm):
    class Meta:
        model = models.User
        fields = ('first_name', 'last_name', 'email')
        widgets = {
            'first_name': forms.TextInput(attrs={'placeholder': 'First Name'}),
            'last_name': forms.TextInput(attrs={'placeholder': 'Last Name'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Email Name'}),
        }

    password1 = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}))

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 != password2:
            raise forms.ValidationError('Password confirmation does not match')
        else:
            return password1

    def save(self, *args, **kwargs):
        user = super().save(commit=False)
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password1')
        user.username = email
        user.set_password(password)
        user.save()


# UserCreationForm을 사용하는 경우
# class SignUpForm(UserCreationForm):
#     username = forms.EmailField(label='Email')
#
#     class Meta:
#         model = models.User
#         fields = ['username', 'password1', 'password2']


# ModelForm을 상속받는 경우
# class SignUpForm(forms.ModelForm):
#     class Meta:
#         model = models.User
#         fields = ['first_name', 'last_name', 'email']
#
#     password1 = forms.CharField(widget=forms.PasswordInput, label='Password')
#     password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')
#
#     def clean_password2(self):
#         password1 = self.cleaned_data.get('password1')
#         password2 = self.cleaned_data.get('password2')
#
#         if password1 != password2:
#             raise forms.ValidationError('Password confirmation does not match')
#         else:
#             return password1
#
#     def save(self, *args, **kwargs):
#         user = super().save(commit=False)
#         email = self.cleaned_data.get('email')
#         password = self.cleaned_data.get('password1')
#         user.username = email
#         user.set_password(password)
#         user.save()


# 그냥 폼을 쓰는 경우
# class SignUpForm(forms.Form):
#     first_name = forms.CharField(max_length=80)
#     last_name = forms.CharField(max_length=80)
#     email = forms.EmailField()
#     password1 = forms.CharField(widget=forms.PasswordInput, label='Password')
#     password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')
#
#     def clean_email(self):
#         email = self.cleaned_data.get('email')
#         try:
#             models.User.objects.get(email=email)
#             raise forms.ValidationError('User already exists with that email')
#         except models.User.DoesNotExist:
#             return email
#
#     def clean_password2(self):
#         password1 = self.cleaned_data.get('password1')
#         password2 = self.cleaned_data.get('password2')
#
#         if password1 != password2:
#             raise forms.ValidationError('Password confirmation does not match')
#         else:
#             return password1
#
#     def save(self):
#         first_name = self.cleaned_data.get('first_name')
#         last_name = self.cleaned_data.get('last_name')
#         email = self.cleaned_data.get('email')
#         password1 = self.cleaned_data.get('password1')
#
#         user = models.User.objects.create_user(email, email, password1) # 암호화된 비밀번호로 유저를 생성
#         user.first_name = first_name
#         user.last_name = last_name
#         user.save()