from django.contrib.auth import authenticate
from django.urls import resolve
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from .utils import (
    create_user,
    get_auth_token,
    update_or_create_verification_token,
)


class AccountTests(APITestCase):
    def setUp(self):
        self.password = 'testpassword'
        self.user = create_user({
            'email': 'testuser@gmail.com',
            'password': self.password,
            'first_name': 'Test',
            'last_name': 'User',
        })
        self.token = get_auth_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token}')

    def test_can_create_account(self):
        url = reverse('accounts:user-create')
        data = {
            'email': 'newuser@gmail.com',
            'password': 'newpassword',
            'first_name': 'New',
            'last_name': 'User',
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data.get('user').get('email'), data['email'])

    def test_can_log_in(self):
        url = reverse('accounts:login')
        data = {'email': self.user.email, 'password': self.password}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('token'), self.token.key)

    def test_can_retrieve_user(self):
        url = reverse('accounts:user-retrieve')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_can_verify_user(self):
        url = reverse('accounts:verify')
        verification_token = update_or_create_verification_token(self.user)
        data = {'verification_token': verification_token.token}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_can_resend_verification(self):
        url = reverse('accounts:resend-verification')
        response = self.client.post(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_can_forget_password(self):
        url = reverse('accounts:password-forgot')
        response = self.client.post(url, {'email': 'testuser@gmail.com'})
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_can_reset_password(self):
        url = reverse('accounts:password-reset')
        verification_token = update_or_create_verification_token(self.user)
        data = {
            'email': self.user.email,
            'password': 'newpassword',
            'verification_token': verification_token.token,
        }
        response = self.client.post(url, data)
        user = authenticate(username=data['email'], password=data['password'])
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(user)

    def test_can_change_password(self):
        url = reverse('accounts:password-change')
        data = {
            'email': self.user.email,
            'current_password': self.password,
            'new_password': 'newpassword'
        }
        response = self.client.patch(url, data)
        user = authenticate(
            username=data['email'],
            password=data['new_password'],
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(user)

    def test_can_change_email(self):
        url = reverse('accounts:email-change')
        data = {'email': 'newemail@gmail.com'}
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get('user').get('email'), data['email'])

    def test_can_update_user(self):
        url = reverse('accounts:user-update')
        data = {'first_name': 'New'}
        response = self.client.patch(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data.get('user').get('first_name'),
            data['first_name'],
        )
