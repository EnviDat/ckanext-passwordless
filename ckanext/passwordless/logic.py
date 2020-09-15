import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckan.lib.mailer as mailer
import ckan.views.user as user
from ckan.lib.navl.dictization_functions import DataError
import ckan.lib.helpers as h

from ckanext.passwordless import util
from ckanext.passwordless.passwordless_mailer import passwordless_send_reset_link
from ckan.common import request, session, g
from logging import getLogger

import sqlalchemy
import flask

from ckan.lib.redis import connect_to_redis
from datetime import datetime, timedelta
import dateutil.parser

log = getLogger(__name__)


@toolkit.side_effect_free
def perform_reset(context, data_dict):
    """Request a passwordless login token to be sent by email.

    :param email: the user email
    :type email: string
    :format email: string

    :returns: success
    :rtype: string
    """

    log.debug("Action reset: {0} ".format(data_dict))
    result = _reset(context, data_dict)
    return result


@toolkit.side_effect_free
def user_login(context, data_dict):
    """Perform the user login.

    :param email: the user email
    :type email: string
    :format email: string

    :param key: the received token
    :type key: string
    :format key: string

    :returns: success
    :rtype: string
    """

    log.debug("Action login: {0} ".format(data_dict))
    result = _login(context, data_dict)
    return result


@toolkit.side_effect_free
def user_logout(context, data_dict):
    """Perform the user logout.

    :param email: the user email
    :type email: string
    :format email: string

    :param key: the received token
    :type key: string
    :format key: string

    :returns: success
    :rtype: string
    """

    user.logout()

    if session.id:
        log.debug(u'Deleting Session: %r', session.items())
        session.delete()

    # Clear flask session
    try:
        flask.session.clear()
    except:
        log.error("flask session could no be deleted")

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
    # No one is logged in already
    if toolkit.c.user:
        log.warning("User already logged in {}".format(toolkit.c.user))
        raise toolkit.NotAuthorized('user already logged in, logout first')

    # Check email is present
    try:
        email = data_dict['email']
        email = email.lower()
    except KeyError:
        raise toolkit.ValidationError({'email': 'missing email'})

    # Check email is valid
    if not util.check_email(email):
        raise toolkit.ValidationError({'email': 'invalid email'})

    # control attempts (exception raised on fail)
    _check_reset_attempts(email.encode())

    # get existing user from email
    user = util.get_user(email)
    # log.debug('passwordless_request_reset: USER is = ' + str(user))

    if not user:
        # A user with this email address doesn't yet exist in CKAN,
        # so create one.
        user = _create_user(email)
        log.debug('passwordless_request_reset: created user = ' + str(email))

    if user:
        # make sure is not deleted
        if user.get('state') == 'deleted':
            raise toolkit.ValidationError({'user': 'user with email {0} was deleted'.format(email)})
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
            # Check email is valid
            if not util.check_email(email):
                raise toolkit.ValidationError({'email': 'invalid email'})
            # get the user id
            user_id = util.get_user_id(email)
            if not user_id:
                raise toolkit.ValidationError({'email': 'email does not correspond to a registered user'})
    except KeyError:
        raise toolkit.ValidationError({'email': 'missing email'})
    try:
        orig_key = data_dict['key']
    except KeyError:
        raise toolkit.ValidationError({'key': 'missing token'})

    if len(orig_key)<=32:
        key = "b'{0}'".format(orig_key)
    else:
        key = orig_key
    log.debug('login: {0} ({1}) => {2}'.format(user_id, orig_key, key))

    # get whether to return context (UI) or just a message (API)
    return_context = data_dict.get('return_context', False)

    try:
        data_dict = {'id': user_id}
        user_dict = logic.get_action('user_show')(context, data_dict)
        user_obj = context['user_obj']
        email = user_dict.get('email', user_obj.email)
    except logic.NotFound:
        raise logic.NotFound('"%s" matched several users' % user_id)
    except toolkit.NotAuthorized:
        raise toolkit.NotAuthorized('Exception (Not Authorized) email = ' + str(email) + 'id = ' + str(user_id))

    if not user_obj or not mailer.verify_reset_link(user_obj, key):
        raise toolkit.ValidationError({'key': 'token provided is not valid'})

    flask.session['ckanext-passwordless-user'] = user_dict['name']

    # remove token
    mailer.create_reset_key(user_obj)

    # log the user in programmatically
    try:
        _set_repoze_user_only(user_dict['name'])
    except TypeError as e:
        log.warning("Exception at login: {0}".format(e))

    # delete attempts from Redis
    log.debug("Redis: reset attempts for {0}".format(email))
    redis_conn = connect_to_redis()
    redis_conn.delete(email)

    # make sure the master API key exists
    apikey = util.renew_master_token(user_dict['name'])

    # return message or context
    if return_context:
        return context
    else:
        user_obj = context.get('user_obj', None)
        result_json = {'user': {'email': user_obj.email, 'id': user_obj.id, 'name': user_obj.name,
                                'apikey': apikey, 'fullname': user_obj.fullname},
                       'message': "login success"}
        return result_json


def _create_user(email):
    # first check temporary quota
    _check_new_user_quota()

    try:
        data_dict = {'email': email.lower(),
                     'fullname': util.generate_user_fullname(email),
                     'name': _get_new_username(email),
                     'password': util.generate_password()}
        user = toolkit.get_action('user_create')(
            context={'ignore_auth': True},
            data_dict=data_dict)
    except sqlalchemy.exc.InternalError as error:
        exception_message = "{0}".format(error)
        log.error("failed to create user: {0}".format(error))
        if exception_message.find("quota") >= 0:
            raise DataError("error creating a new user, daily new user quota exceeded")
        else:
            raise DataError("internal error creating a new user")

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

        except mailer.MailerException as e:
            log.error('Could not send token link: %s' % str(e))
            raise mailer.MailerException('could not send token link by mail: %s' % str(e))

    return


def _set_repoze_user_only(user_id):
    """Set the repoze.who cookie to match a given user_id"""
    if 'repoze.who.plugins' in request.environ:
        rememberer = request.environ['repoze.who.plugins']['friendlyform']
        identity = {'repoze.who.userid': user_id}
        resp = h.redirect_to(u'user.me')
        resp.headers.extend(rememberer.remember(request.environ, identity))
        log.debug("cookie set")

def _check_reset_attempts(email):
    redis_conn = connect_to_redis()
    if email not in redis_conn.keys():
        log.debug("Redis: first login attempt for {0}".format(email))
        redis_conn.hmset(email, {'attempts': 1, 'latest': datetime.now().isoformat()})
    else:
        base = 3
        attempts = int(redis_conn.hmget(email, 'attempts')[0])
        latest = dateutil.parser.parse(redis_conn.hmget(email, 'latest')[0])

        waiting_seconds = base ** attempts
        limit_date = latest + timedelta(seconds=waiting_seconds)

        log.debug('Redis: wait {0} seconds after {1} attempts => after date {2}'.format(waiting_seconds, attempts,
                                                                                        limit_date.isoformat()))

        if limit_date > datetime.now():
            raise logic.ValidationError({'user': "User should wait {0} seconds till {1} for a new token request".format(
                int((limit_date - datetime.now()).total_seconds()),
                limit_date.isoformat())})
        else:
            # increase counter
            redis_conn.hmset(email, {'attempts': attempts + 1, 'latest': datetime.now().isoformat()})


def _check_new_user_quota():
    redis_conn = connect_to_redis()
    new_users_list = 'new_latest_users'
    if 'new_latest_users' not in redis_conn.keys():
        redis_conn.lpush(new_users_list, datetime.now().isoformat())
    else:
        # TODO: read this rom config
        max_new_users = 10
        period = 60 * 10
        begin_date = datetime.now() - timedelta(seconds=period)

        count = 0
        elements_to_remove = []

        for i in range(0, redis_conn.llen(new_users_list)):
            value = redis_conn.lindex(new_users_list, i)
            new_user_creation_date = dateutil.parser.parse(value)
            if new_user_creation_date >= begin_date:
                count += 1
            else:
                elements_to_remove += [value]

        for value in elements_to_remove:
            redis_conn.lrem(new_users_list, value)

        if count >= max_new_users:
            log.error("new user temporary quota exceeded ({0})".format(count))
            raise logic.ValidationError({'user': "new user temporary quota exceeded, wait {0} minutes for a new request"
                                        .format(period / 60)})
        else:
            # add new user creation
            redis_conn.lpush(new_users_list, datetime.now().isoformat())
