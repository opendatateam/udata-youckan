# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import logging
import time

from base64 import b64decode, b64encode
from urlparse import urljoin

from flask import Blueprint, request, current_app, redirect, session, url_for, abort
from flask_oauthlib.client import OAuth, OAuthException
from flask_security.utils import login_user, logout_user

from werkzeug.urls import url_encode

from udata.auth import current_user
from udata.models import datastore
from udata.commands import manager

log = logging.getLogger(__name__)

bp = Blueprint('youckan', __name__)

oauth = OAuth()

youckan = oauth.remote_app(
    'youckan',
    app_key='YOUCKAN',
    request_token_url=None,
    access_token_method='POST',
)


def encode_state(session_id=None, url=None):
    next_url = (url or request.url).replace('http://', 'https://')
    state = {
        'timestamp': time.time(),
        'next_url': next_url
    }

    if session_id:
        state['session_id'] = session_id

    return b64encode(bytes(json.dumps(state)))


def decode_state(state):
    return json.loads(b64decode(state))


@bp.before_app_request
def check_youckan_cookie():
    # Do not interfere with authorize endpoint
    if request.endpoint == 'youckan.authorized':
        return

    # Force session open and close depending on the youckan session state
    session_cookie_name = current_app.config['YOUCKAN_SESSION_COOKIE']
    logged_cookie_name = '{0}.logged'.format(current_app.config['YOUCKAN_AUTH_COOKIE'])

    if session_cookie_name in request.cookies and logged_cookie_name in request.cookies:
        session_id = request.cookies[session_cookie_name]

        if not current_user.is_authenticated or 'youckan.token' not in session:
            return youckan.authorize(
                callback=url_for('youckan.authorized', _external=True, _scheme='https'),
                state=encode_state(session_id),
                next=request.url.replace('http://', 'https://')
            )
    elif current_user.is_authenticated:
        logout_user()


def login():
    '''Redirect user to YouCKAN'''
    url = urljoin(current_app.config['YOUCKAN_URL'], 'login')
    params = {}
    if 'next' in request.args:
        next_url = request.args['next']
        if not next_url.startswith('http'):
            next_url = ''.join(['https://', current_app.config['SERVER_NAME'], next_url])
        params['next'] = next_url
    if 'message' in request.args:
        params['message'] = request.args['message']
    if params:
        url += '?' + url_encode(params)
    return redirect(url)


def logout():
    '''Perform a local logout and redirect to youckan'''
    session.pop('youckan.token', None)
    logout_user()
    return redirect(urljoin(current_app.config['YOUCKAN_URL'], 'logout'))


@bp.route('/youckan/authorized')
def authorized():
    resp = youckan.authorized_response()
    if resp is None or isinstance(resp, OAuthException):
        # TODO: better error handling
        abort(403)

    session['youckan.token'] = (resp['access_token'], '')
    response = youckan.get('me')
    data = response.data

    user = datastore.find_user(email=data['email'])
    if not user:
        user = datastore.create_user(
            slug=data['slug'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            active=data['is_active'],
            avatar_url=data['profile'].get('avatar') or None,
            website=data['profile'].get('website') or None,
            about=data['profile'].get('about') or None
        )
    else:
        user.first_name = data['first_name']
        user.last_name = data['last_name']
        user.active = data['is_active']
        user.avatar_url = data['profile'].get('avatar') or None
        user.website = data['profile'].get('website') or None
        user.about = data['profile'].get('about') or None

    admin_role = datastore.find_or_create_role('admin')
    if data['is_superuser'] and not user.has_role(admin_role):
        datastore.add_role_to_user(user, admin_role)

    user.save()
    login_user(user)

    redirect_to = url_for('site.home')
    if 'state' in request.args:
        state = request.args.get('state')
        decoded_state = json.loads(b64decode(state))
        redirect_to = decoded_state.get('next_url', redirect_to)
    return redirect(redirect_to)


@youckan.tokengetter
def get_youckan_oauth_token():
    return session.get('youckan.token')


def init_app(app):
    if 'YOUCKAN_URL' not in app.config:
        raise ValueError('YOUCKAN_URL parameter is mandatory')
    elif 'YOUCKAN_CONSUMER_KEY' not in app.config:
        raise ValueError('YOUCKAN_CONSUMER_KEY parameter is mandatory')
    elif 'YOUCKAN_CONSUMER_SECRET' not in app.config:
        raise ValueError('YOUCKAN_CONSUMER_SECRET parameter is mandatory')

    youckan_url = app.config.get('YOUCKAN_URL')

    app.config.setdefault('YOUCKAN_SESSION_COOKIE', 'youckan.session')
    app.config.setdefault('YOUCKAN_AUTH_COOKIE', 'youckan.auth')
    app.config.setdefault('YOUCKAN_BASE_URL', urljoin(youckan_url, '/api/'))
    app.config.setdefault('YOUCKAN_ACCESS_TOKEN_URL', urljoin(youckan_url, '/oauth2/token/'))
    app.config.setdefault('YOUCKAN_AUTHORIZE_URL', urljoin(youckan_url, '/oauth2/authorize/'))

    oauth.init_app(app)
    app.register_blueprint(bp)

    # Hijack Flask-Security URL: must find a better way
    app.view_functions['security.login'] = login
    app.view_functions['security.logout'] = logout

    # Hijack Flask-Login flash message
    app.login_manager.login_message = None


@manager.command
def update_youckan_users():
    '''Update youckan users by their slug'''
    # if not 'YOUCKAN_ADMIN' in manager.app.config:
    #     raise ValueError('YOUCKAN_ADMIN should be defined')
    print youckan.get('users')
