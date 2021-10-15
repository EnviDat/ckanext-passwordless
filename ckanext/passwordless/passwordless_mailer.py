# encoding: utf-8
from ckanext.passwordless import util

import ckan.lib.mailer as mailer
from ckan.common import config
import ckan.plugins.toolkit as toolkit

from flask import render_template
import ckan.lib.base as base

import logging

log = logging.getLogger(__name__)
render = base.render


def passwordless_send_reset_link(user):
    mailer.create_reset_key(user)
    # log.debug("passwordless_send_reset_link user = " + str(user))
    body = passwordless_get_reset_link_body(user)
    extra_vars = {
        'site_title': config.get('ckan.site_title')
    }
    subject = render('emails/reset_password_subject.txt', extra_vars)

    # Make sure we only use the first line
    subject = subject.split('\n')[0]

    mailer.mail_user(user, subject, body)


def passwordless_get_reset_link_body(user):
    login_link = toolkit.url_for(controller='user', action='login', qualified=True)
    reset_link = mailer.get_reset_link(user)
    reset_key = user.reset_key[2:-1]
    extra_vars = {
        'login_link': login_link,
        'reset_link': reset_link,
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_name': user.name,
        'user_fullname': user.fullname,
        'user_email': user.email,
        'key': reset_key
    }
    log.debug("KEY {0}".format(reset_key))
    # NOTE: This template is translated
    return render('emails/reset_password.txt', extra_vars)


def passwordless_send_welcome_email(user):

    body = passwordless_get_welcome_email_body(user)
    subject = "Welcome to {0}".format(config.get('ckan.site_title'))

    #log.debug("passwordless_mailer: Welcome email subject: '{0}',  body: \n {1}".format(subject, body))
    mailer.mail_recipient(user.get('name'), user.get('email'), subject, body)

def passwordless_get_welcome_email_body(user):

    extra_vars = {
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'site_org': config.get('ckan.site_org', 'our organization'),
        'email_to': config.get('email_to'),
        'user_name': user.get('name'),
        'user_fullname': user.get('fullname'),
        'user_email': user.get('email'),
    }

    # NOTE: This template is translated
    welcome_template = config.get("passwordless.welcome_template", 'emails/welcome_user.txt')
    return render(welcome_template, extra_vars)



