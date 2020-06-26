# encoding: utf-8
from ckanext.passwordless import util 

import ckan.lib.mailer as mailer
from ckan.lib.base import render_jinja2
from ckan.common import config
import ckan.plugins.toolkit as toolkit

import logging
log = logging.getLogger(__name__)

def passwordless_send_reset_link(user):
    mailer.create_reset_key(user)
    log.debug("passwordless_send_reset_link user = " + str(user))
    log.debug(str(user.reset_key))
    body = passwordless_get_reset_link_body(user)
    extra_vars = {
        'site_title': config.get('ckan.site_title')
    }
    subject = render_jinja2('emails/reset_password_subject.txt', extra_vars)

    # Make sure we only use the first line
    subject = subject.split('\n')[0]

    mailer.mail_user(user, subject, body)

def passwordless_get_reset_link_body(user):
    login_link = toolkit.url_for(controller='user', action='login', qualified=True)
    reset_link = mailer.get_reset_link(user)
    extra_vars = {
        'login_link':login_link,
        'reset_link': reset_link,
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_name': user.name,
        'user_fullname': user.fullname,
        'user_email': user.email,
        'key':util.get_key_from_link(reset_link)
        }
    # NOTE: This template is translated
    return render_jinja2('emails/reset_password.txt', extra_vars)
