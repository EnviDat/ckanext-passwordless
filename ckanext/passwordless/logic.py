import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckan.lib.mailer as mailer
import ckan.controllers.user as user

from ckanext.passwordless import util
from ckanext.passwordless.passwordless_mailer import passwordless_send_reset_link
from ckan.common import request, response, session, g
from logging import getLogger

import requests

log = getLogger(__name__)

# CKAN 2.7
try:
    import pylons
except:
    log.debug("cannot import Pylons")

# CKAN 2.8
try:
    import flask
except:
    log.debug("cannot import Flask")


@toolkit.side_effect_free
def perform_reset(context, data_dict):
    '''Request a passwordless login token to be sent by email.

    :param email: the user email
    :type email: string
    :format email: string

    :returns: success
    :rtype: string
    '''

    log.debug("Action reset: {0} ".format(data_dict))
    result = _reset(context, data_dict)
    return result


@toolkit.side_effect_free
def user_login(context, data_dict):
    '''Perform the user login.

    :param email: the user email
    :type email: string
    :format email: string

    :param key: the received token
    :type key: string
    :format key: string

    :returns: success
    :rtype: string
    '''

    log.debug("Action login: {0} ".format(data_dict))
    result = _login(context, data_dict)
    return result


@toolkit.side_effect_free
def user_logout(context, data_dict):
    '''Perform the user logout.

    :param email: the user email
    :type email: string
    :format email: string

    :param key: the received token
    :type key: string
    :format key: string

    :returns: success
    :rtype: string
    '''

    log.debug("Action logout: {0} ".format(data_dict))
    log.debug("Action logout: {0} ".format(context))

    user_controller = user.UserController()
    user_controller.logout()

    if session.id:
        log.debug(u'Deleting Session: %r', session.items())
        session.delete()

    # Clear flask session
    try:
        flask.session.clear()
    except:
        log.error("flask session could no be deleted")

    # Clear pylons session
    try:
        pylons.session.clear()
    except:
        log.error("pylons session could no be deleted")

    # check if user remains in context
    if toolkit.c.user:
        log.warning('user could be still logged in ({0})'.format(toolkit.c.user))

    # check if authorization cookie remains
    for cookie in request.cookies:
        if cookie == u'auth_tkt':
            log.warning("found cookie {0}, user needs to log out from UI".format(cookie))
            raise logic.NotAuthorized("found cookie {0}, user needs to log out from UI".format(cookie))

    return "logout successful"


def _reset(context, data_dict):
    # Check email is present
    try:
        email = data_dict['email']
        email = email.lower()
    except KeyError:
        raise toolkit.ValidationError({'email': 'missing email'})

    # Check email is valid
    if not util.check_email(email):
        raise toolkit.ValidationError({'email': 'invalid email'})

    # get existing user from email
    user = util.get_user(email)

    if not user:
        # A user with this email address doesn't yet exist in CKAN,
        # so create one.
        user = _create_user(email)
        log.debug('passwordless_request_reset: created user = ' + str(email))

    if user:
        # make sure is not deleted
        if user.get('state') == 'deleted':
            raise toolkit.ValidationError({'user': 'user with email {0} was deleted, contact an admin'.format(email)})
        # token request
        _request_token(user.get('id'))
    else:
        raise toolkit.ValidationError({'user': 'cannot retrieve or create user with given email'})

    log.debug("controller redirecting: user.login, email =  " + str(email))
    return "reset successful"


def _login(context, data_dict):
    if toolkit.c.user:
        # Don't offer the reset form if already logged in
        log.warning("User already logged in")
        raise toolkit.NotAuthorized('user already logged in, logout first')

    # Check if parameters are present
    try:
        user_id = data_dict.get('id')
        if not user_id:
            email = data_dict['email'].lower()
            user_id = util.get_user_id(email)
    except KeyError:
        raise toolkit.ValidationError({'email': 'missing email or id'})
    try:
        key = data_dict['key']
    except KeyError:
        raise toolkit.ValidationError({'key': 'missing key'})

    log.debug('login: {0} ({1})'.format(user_id, key))

    # get whether to return context (UI) or just a message (API)
    return_context = data_dict.get('return_context', False)

    try:
        data_dict = {'id': user_id}
        user_dict = logic.get_action('user_show')(context, data_dict)
        user_obj = context['user_obj']
        email = user_dict.get('email')
    except logic.NotFound:
        raise logic.NotFound('"%s" matched several users' % user_id)
    except toolkit.NotAuthorized:
        raise toolkit.NotAuthorized('Exception (Not Authorized) email = ' + str(email) + 'id = ' + str(user_id))

    log.debug(user_dict)
    log.debug(user_obj)

    if not user_obj or not mailer.verify_reset_link(user_obj, key):
        raise toolkit.NotAuthorized('Invalid token. Please try again.')

    # CKAN 2.7 - 2.8
    try:
        pylons.session['ckanext-passwordless-user'] = user_dict['name']
        pylons.session.save()
    except:
        log.debug("login: pylons session not available")
        flask.session['ckanext-passwordless-user'] = user_dict['name']

    # remove token
    mailer.create_reset_key(user_obj)

    # log the user in programmatically
    try:
        _set_repoze_user_only(user_dict['name'])
    except TypeError as e:
        log.warning("Exception at login: {0}".format(e))

    if return_context:
        return context
    else:
        return "login success"


def _create_user(email):
    data_dict = {'email': email.lower(),
                 'fullname': util.generate_user_fullname(email),
                 'name': _get_new_username(email),
                 'password': util.generate_password()}
    user = toolkit.get_action('user_create')(
        context={'ignore_auth': True},
        data_dict=data_dict)
    return user


def _get_new_username(email):
    offset = 0
    email = email.lower()
    username = util.generate_user_name(email)
    while offset < 100000:
        log.debug(username)
        try:
            user_dict = toolkit.get_action('user_show')(data_dict={'id': username})
        except logic.NotFound:
            return username
        offset += 1
        username = util.generate_user_name(email, offset)
    return None


def _request_token(user_id):
    if toolkit.c.user:
        # Don't offer the reset form if already logged in
        log.warning("User already logged in {}".format(toolkit.c.user))
        raise toolkit.NotAuthorized('user already logged in, logout first')

    context = {'user': toolkit.c.user}

    data_dict = {'id': user_id}
    user_obj = None
    try:
        user_dict = toolkit.get_action('user_show')(context, data_dict)
        user_obj = context['user_obj']
    except logic.NotFound:
        # Try searching the user
        del data_dict['id']
        data_dict['q'] = user_id

        if user_id and len(user_id) > 2:
            user_list = toolkit.get_action('user_list')(context, data_dict)
            if len(user_list) == 1:
                # This is ugly, but we need the user object for the mailer,
                # and user_list does not return them
                del data_dict['q']
                data_dict['id'] = user_list[0]['id']
                user_dict = toolkit.get_action('user_show')(context, data_dict)
                user_obj = context['user_obj']
            elif len(user_list) > 1:
                raise logic.NotFound('"%s" matched several users' % user_id)
            else:
                raise logic.NotFound('No such user: %s' % user_id)
        else:
            raise logic.NotFound('No such user: %s' % user_id)

    if user_obj:
        try:
            passwordless_send_reset_link(user_obj)

        except mailer.MailerException, e:
            log.error('Could not send token link: %s' % unicode(e))
            raise mailer.MailerException

    return


def _set_repoze_user_only(user_id):
    '''Set the repoze.who cookie to match a given user_id'''
    if 'repoze.who.plugins' in request.environ:
        rememberer = request.environ['repoze.who.plugins']['friendlyform']
        identity = {'repoze.who.userid': user_id}
        response.headerlist += rememberer.remember(request.environ, identity)
        log.debug("cookie set")
