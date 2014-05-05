# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import slugify

from contextlib import contextmanager
from datetime import datetime
from urlparse import urlparse, parse_qs

import httpretty

from flask import url_for, session

from udata.auth import current_user
from udata.models import User
from udata.settings import Testing
from udata.tests.factories import UserFactory, faker
from udata.tests.frontend import FrontTestCase

from udata_youckan import init_app, encode_state, decode_state


class YouckanSettings(Testing):
    # SERVER_NAME = 'udata.dev'
    TEST_WITH_PLUGINS = True
    PLUGINS = ['youckan']
    YOUCKAN_URL = 'https://youckan/'
    YOUCKAN_CONSUMER_KEY = 'key',
    YOUCKAN_CONSUMER_SECRET = 'secret'


def youckan_api_response(**kwargs):
    '''A YouCKAN ME API response factory'''
    data = {
        'profile': {
            'website': faker.url(),
            'city': faker.city(),
            'about': faker.text(),
            'avatar': faker.url() + 'avatar.png',
        },
        'first_name': faker.first_name(),
        'last_name': faker.last_name(),
        'email': faker.email(),
        'is_active': True,
        'is_superuser': False,
        'date_joined': datetime.now().isoformat(),
        'slug': None,
    }
    for key in data.keys():
        if key in kwargs:
            data[key] = kwargs[key]

    data['fullname'] = ' '.join((data['first_name'], data['last_name']))

    if not data['slug']:
        data['slug'] = slugify.slugify(data['fullname'].lower())

    return data


class YouckanTest(FrontTestCase):
    settings = YouckanSettings

    def create_app(self):
        app = super(YouckanTest, self).create_app()
        init_app(app)
        return app

    @contextmanager
    def mock_authorize(self, **kwargs):
        token = {
            'access_token': 'token',
            'token_type': 'Bearer',
            'expires_in': '3600',
            'refresh_token': 'refresh-token',
        }
        profile = youckan_api_response(**kwargs)

        httpretty.register_uri(httpretty.POST, self.app.config['YOUCKAN_ACCESS_TOKEN_URL'],
            body=json.dumps(token),
            content_type='application/json'
        )
        httpretty.register_uri(httpretty.GET, self.app.config['YOUCKAN_BASE_URL'] + 'me',
            body=json.dumps(profile),
            content_type='application/json'
        )

        with self.app.test_client() as client:
            yield profile, client

    def test_login_redirect_to_youckan(self):
        '''Login should redirect to youckan login'''
        next_url = 'http://someurl/'
        response = self.get(url_for('security.login', next=next_url))

        self.assertStatus(response, 302)

        response_url = urlparse(response.location)
        qs = parse_qs(response_url.query)
        expected_url = urlparse(YouckanSettings.YOUCKAN_URL + 'login')
        self.assertEqual(response_url.hostname, expected_url.hostname)
        self.assertEqual(response_url.path, expected_url.path)
        self.assertEqual(qs['next'][0], next_url)

    def test_logout_redirect_to_youckan(self):
        '''Logout should trigger a YouCKAN logout'''
        with self.app.test_client() as client:
            self.login(client=client)

            response = self.get(url_for('security.logout'), base_url='https://localhost', client=client)

            self.assertStatus(response, 302)
            self.assertFalse(current_user.is_authenticated())

            expected_url = urlparse(YouckanSettings.YOUCKAN_URL + 'logout')
            response_url = urlparse(response.location)
            self.assertEqual(response_url.hostname, expected_url.hostname)
            self.assertEqual(response_url.path, expected_url.path)

    @httpretty.activate
    def test_log_user_on_authorize_callback(self):
        '''Should log the user in on authorize callback'''
        user = UserFactory()

        with self.mock_authorize(slug=user.slug) as (profile, client):
            response = self.get(url_for('youckan.authorized', code='code'), client=client)
            self.assertRedirects(response, url_for('front.home'))
            self.assertIn('youckan.token', session)
            self.assertTrue(current_user.is_authenticated())

        self.assertEqual(len(User.objects), 1)

    @httpretty.activate
    def test_log_admin_user_on_authorize_callback(self):
        '''Should log the user with the admin role in on authorize callback'''
        user = UserFactory()

        with self.mock_authorize(slug=user.slug, is_superuser=True) as (profile, client):
            response = self.get(url_for('youckan.authorized', code='code'), client=client)
            self.assertRedirects(response, url_for('front.home'))
            self.assertIn('youckan.token', session)
            self.assertTrue(current_user.is_authenticated())
            self.assertTrue(current_user.has_role('admin'))

        self.assertEqual(len(User.objects), 1)

    @httpretty.activate
    def test_log_inactive_user_on_authorize_callback(self):
        '''Should log the user with the admin role in on authorize callback'''
        user = UserFactory(active=False)

        with self.mock_authorize(slug=user.slug, is_active=True) as (profile, client):
            response = self.get(url_for('youckan.authorized', code='code'), client=client)
            self.assertRedirects(response, url_for('front.home'))
            self.assertIn('youckan.token', session)
            self.assertTrue(current_user.is_authenticated())
            self.assertTrue(current_user.is_active())

        self.assertEqual(len(User.objects), 1)

    @httpretty.activate
    def test_fetch_token_and_create_user_on_authorize_callback(self):
        '''Should create the user on authorize callback'''
        with self.mock_authorize() as (profile, client):
            response = self.get(url_for('youckan.authorized', code='code'), client=client)

            self.assertRedirects(response, url_for('front.home'))
            self.assertIn('youckan.token', session)
            self.assertTrue(current_user.is_authenticated())
            self.assertTrue(current_user.is_active())
            self.assertEqual(current_user.slug, profile['slug'])
            self.assertEqual(current_user.first_name, profile['first_name'])
            self.assertEqual(current_user.last_name, profile['last_name'])
            self.assertEqual(current_user.email, profile['email'])
            self.assertEqual(current_user.has_role('admin'), profile['is_superuser'])
            self.assertEqual(current_user.avatar_url, profile['profile']['avatar'])

        self.assertEqual(len(User.objects), 1)

    def test_redirect_authenticated_users_to_https(self):
        self.login()
        response = self.get('/somewhere')
        self.assertStatus(response, 302)
        self.assertEqual(response.location, 'https://localhost/somewhere')

    def test_trigger_oauth_login_on_cookie(self):
        '''Should trigger a OAuth handshake if YouCKAN cookie is present'''
        with self.app.test_client() as client:
            self.assertFalse(current_user.is_authenticated())
            client.set_cookie('udata.dev', 'youckan.session', 'session_id')
            client.set_cookie('udata.dev', 'youckan.auth', 'whatever')
            response = self.get('/somewhere', client=client)

        self.assertStatus(response, 302)

        response_url = urlparse(response.location)
        expected_url = urlparse(self.app.config['YOUCKAN_AUTHORIZE_URL'])
        self.assertEqual(response_url.hostname, expected_url.hostname)
        self.assertEqual(response_url.path, expected_url.path)
        qs = parse_qs(response_url.query)
        self.assertIn('state', qs)
        state = decode_state(qs['state'][0])
        self.assertEqual(state['next_url'], 'https://localhost/somewhere')

    @httpretty.activate
    def test_oauth_authorization_should_preserve_current_page(self):
        '''OAuth handshake should preserve current viewed page'''
        user = UserFactory()
        next_url = '/somewhere'
        state = encode_state(url=next_url)

        with self.mock_authorize(slug=user.slug) as (profile, client):
            response = self.get(url_for('youckan.authorized', code='code', state=state), client=client)

        self.assertRedirects(response, next_url)

    def test_force_logout_if_cookie_is_missing(self):
        '''Should silently idsonnect user if YouCKAN cookie is missing'''
        with self.app.test_client() as client:
            self.login(client=client)

            response = self.get(url_for('front.home'), base_url='https://localhost', client=client)
            self.assert200(response)
            self.assertFalse(current_user.is_authenticated())
