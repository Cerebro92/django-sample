from django.urls import include, path
from . import views


app_name = 'accounts'
urlpatterns = [
    path('', views.CreateUserView.as_view(), name='user-create'),
    path('email/change/', views.ChangeEmailView.as_view(), name='email-change'),
    path('login/', views.LogInView.as_view(), name='login'),
    path('password/', include([
        path(
            'change/',
            views.ChangePasswordView.as_view(),
            name='password-change',
        ),
        path(
            'forgot/',
            views.ForgotPasswordView.as_view(),
            name='password-forgot',
        ),
        path(
            'reset/',
            views.ResetPasswordView.as_view(),
            name='password-reset',
        ),
    ])),
    path('retrieve/', views.RetrieveUserView.as_view(), name='user-retrieve'),
    path('update/', views.UpdateUserView.as_view(), name='user-update'),
    path('verify/', include([
        path(
            '',
            views.VerifyUserView.as_view(),
            name='verify',
        ),
        path(
            'resend/',
            views.ResendVerificationEmailView.as_view(),
            name='resend-verification',
        ),
    ])),
]
