import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckan.lib.base as base
import ckan.model as model
import ckan.lib.helpers as h
import ckan.lib.mailer as mailer
import ckan.lib.captcha as captcha

from ckanext.passwordless import util

from ckan.common import _, request, g, config
from flask import Blueprint
import flask

from logging import getLogger

log = getLogger(__name__)

NotAuthorized = logic.NotAuthorized
NotFound = logic.NotFound

check_access = logic.check_access
render = base.render
abort = base.abort


def get_blueprints(name, module):
    # Create Blueprint for plugin
    blueprint = Blueprint(name, module)

    blueprint.add_url_rule(
        u'/user/login',
        u'login',
        passwordless_user_login,
        methods=[u'GET', u'POST']
    )

    blueprint.add_url_rule(
        u'/user/reset',
        u'request_reset',
        passwordless_request_reset,
        methods=[u'GET', u'POST']
    )

    blueprint.add_url_rule(
        u'/user/reset/<id>',
        'perform_reset',
        passwordless_perform_reset,
        methods=[u'GET', u'POST']
    )

    return blueprint

def before_request():
    try:
        context = dict(model=model, user=g.user, auth_user_obj=g.userobj)
        logic.check_access(u'site_read', context)
    except logic.NotAuthorized:
        blueprint, action = plugins.toolkit.get_endpoint()
        if action not in (
                u'login',
                u'request_reset',
                u'perform_reset',
        ):
            base.abort(403, _(u'Not authorized to see this page'))

def passwordless_user_login():
    log.debug(" ** PASSWORDLESS_LOGIN")
    before_request()

    if toolkit.c.user:
        # Don't offer the reset form if already logged in
        log.warning('user already logged in ' + str(toolkit.c.user))
        return render('user/logout_first.html')

    # Get the params that were posted to /user/login.
    params = {k: v for (k, v) in toolkit.request.form.items() if v and len(v.strip()) > 0}

    if 'key' in params.keys():
        params['key'] = params['key'].strip()
        if len(params['key']) <= 32 and not params['key'].startswith("b'"):
            # add the b'<key>' wrapper
            params['key'] = "b'{0}'".format(params['key'])

    # get the url params too
    for k, v in toolkit.request.args.items():
        if v:
            params[k] = v

    log.debug('login: params = ' + str(params))

    # If there are no params redirect to login
    if not params:
        log.debug('login: NO params')
        return _login_error_redirect()

    key = params.get('key')
    user_id = params.get('id')
    email = params.get('email', '')
    method = toolkit.request.method

    if email and not key:
        if method == 'POST':
            error_msg = _(u'Login failed (reset key not provided)')
            h.flash_error(error_msg)
        log.debug("email but no key, reload")
        return _login_error_redirect(email=email)

    # FIXME 403 error for invalid key is a non helpful page
    context = {'model': model, 'session': model.Session,
               'user': user_id,
               'keep_email': True}

    if not user_id and email:
        if not util.check_email(email):
            error_msg = _(u'Login failed (email not valid)')
            h.flash_error(error_msg)
            return _login_error_redirect()
        user_id = util.get_user_id(email)
        log.debug('login: id (email) = ' + str(user_id))

    try:
        context = toolkit.get_action(
            'passwordless_user_login')(
            context,
            {'email': email, 'key': key, 'id': user_id, 'return_context': True}
        )
    except logic.NotFound as e:
        h.flash_error(_('User not found, exception: {0}'.format(e.message)))
        return _login_error_redirect(email=email, key=key, id=user_id)
    except NotAuthorized as e:
        h.flash_error(_('Exception (Not Authorized): {0}'.format(e.message)))
        return _login_error_redirect(email=email, key=key, id=user_id)
    except toolkit.ValidationError as e:
        message = ""
        for k, v in e.error_dict.items():
            message += " validation of field {0} failed: {1}".format(k, v)
        h.flash_error(_('ValidationError: {0}'.format(message)))
        return _login_error_redirect(email=email, key=key, id=user_id)

    debug_msg = _(u'Successfully logged in ({0}).'.format(context['user_obj'].name))
    h.flash_success(debug_msg)
    return toolkit.h.redirect_to(config.get(u'ckan.route_after_login', u'dashboard.index'))


def passwordless_request_reset():
    '''
    Request a new user token
    '''
    log.debug(" ** REQUEST_RESET")

    before_request()

    context = {'model': model, 'session': model.Session, 'user': g.user,
               'auth_user_obj': toolkit.c.userobj}

    log.debug("request_reset got {1} request from {0}".format(request.remote_addr, request.method))

    try:
        check_access('request_reset', context)
    except NotAuthorized:
        abort(401, _('Unauthorized to request a token.'))

    if toolkit.c.user or g.user:
        # Don't offer the reset form if already logged in
        return render('user/logout_first.html')

    if request.method == 'POST':

        # Get the params that were posted
        params = toolkit.request.form
        email = params.get('email')

        if params:
            # error if no mail
            if not util.check_email(email):
                error_msg = _(u'Please introduce a valid mail.')
                h.flash_error(error_msg)
                return render('user/request_reset.html', extra_vars={'email': email})

            # Check captcha
            try:
                captcha.check_recaptcha(request)
            except captcha.CaptchaError:
                error_msg = _(u'Bad Captcha. Please try again.')
                h.flash_error(error_msg)
                return render('user/request_reset.html', extra_vars={'email': email})

            # call action
            try:
                result = toolkit.get_action(
                    'passwordless_perform_reset')(
                    context,
                    {'email': email}
                )
                log.debug(result)
                h.flash_success(_('Please check your inbox for an access token.'))

            except toolkit.ValidationError as e:
                error_msg = _(u'Reset failed {0}. Please try again.'.format(str(e)))
                h.flash_error(error_msg)
                return render('user/request_reset.html', extra_vars={'email': email})
            except toolkit.NotAuthorized:
                return render('user/logout_first.html')
            except logic.NotFound as e:
                error_msg = _(u'Reset failed, problem retrieving the user associated to the email {0}.'.format(e))
                h.flash_error(error_msg)
                return render('user/request_reset.html', extra_vars={'email': email})
            except mailer.MailerException as e:
                h.flash_error(_('Could not send token link: %s') % str(e))

        log.debug("controller redirecting: user.login, email =  " + str(email))
        return toolkit.h.redirect_to('user.login', email=email)

    return render('user/request_reset.html')


def passwordless_perform_reset(id=None):
    before_request()

    log.debug(" ** PERFORM_RESET id = {0}".format(id))
    if toolkit.c.user:
        # Don't offer the reset form if already logged in
        return render('user/logout_first.html')

    key = request.params.get('key')

    return toolkit.h.redirect_to('user.login', id=id, key=key)


def _login_error_redirect(email='', key='', id=''):
    log.debug("_login_error_redirect rendering user/login.html key = {0}".format(key))
    if key.strip().startswith("b'"):
        key = key.replace("b'", "").replace("'", "")
    return render('user/login.html', extra_vars={'email': email, 'key': key, 'id': id})
