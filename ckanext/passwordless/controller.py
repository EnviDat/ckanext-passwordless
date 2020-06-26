import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckan.lib.base as base
import ckan.model as model
import ckan.lib.helpers as h
import ckan.lib.mailer as mailer
import ckan.lib.captcha as captcha

from ckanext.passwordless import util

from ckan.common import _, request, response

from logging import getLogger

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

NotAuthorized = logic.NotAuthorized
NotFound = logic.NotFound

check_access = logic.check_access
render = base.render
abort = base.abort


class PasswordlessController(toolkit.BaseController):

    def __before__(self, action, **env):
        base.BaseController.__before__(self, action, **env)
        try:
            context = {'model': model, 'user': toolkit.c.user or toolkit.c.author,
                       'auth_user_obj': toolkit.c.userobj}
            check_access('site_read', context)
        except NotAuthorized:
            if toolkit.c.action not in ('passwordless_user_login',
                                        'passwordless_request_reset',
                                        'passwordless_perform_reset',):
                abort(401, _('Not authorized to see this page (action)'))

    def passwordless_user_login(self):
        log.debug(" ** PASSWORDLESS_LOGIN")

        if toolkit.c.user:
            # Don't offer the reset form if already logged in
            log.warning('user already logged in ' + str(toolkit.c.user))
            return render('user/logout_first.html')

        # Get the params that were posted to /user/login.
        params = toolkit.request.params
        log.debug('login: params = ' + str(params))

         # If there are no params redirect to login
        if not params:
            log.debug('login: NO params')
            return self._login_error_redirect()

        key = params.get('key')
        user_id = params.get('id')
        email = params.get('email', '')
        method = toolkit.request.method

        if email and not key:
            if (method == 'POST'):
                error_msg = _(u'Login failed (reset key not provided)')
                h.flash_error(error_msg)
            log.debug("email but no key, reload")
            return self._login_error_redirect(email=email)

        # FIXME 403 error for invalid key is a non helpful page
        context = {'model': model, 'session': model.Session,
                   'user': user_id,
                   'keep_email': True}

        if not user_id and email:
            if not util.check_email(email):
                error_msg = _(u'Login failed (email not valid)')
                h.flash_error(error_msg)
                return self._login_error_redirect()
            user_id = util.get_user_id(email)
            log.debug('login: id (email) = ' + str(user_id))

        try:
            context = toolkit.get_action(
                'passwordless_user_login')(
                context,
                {'email': email, 'key': key, 'id': user_id, 'return_context': True}
            )
            log.debug(context)
        except logic.NotFound as e:
            h.flash_error(_('User not found, exception: {0}'.format(e.message)))
            return self._login_error_redirect(email=email, key=key, id=user_id)
        except NotAuthorized as e:
            h.flash_error(_('Exception (Not Authorized): {0}'.format(e.message)))
            return self._login_error_redirect(email=email, key=key, id=user_id)

        debug_msg = _(u'Successfully logged in ({0}).'.format(context['user_obj'].name))
        h.flash_success(debug_msg)
        h.redirect_to(controller='user', action='dashboard')

    def passwordless_request_reset(self):
        '''
        Request a new user token
        '''
        log.debug(" ** REQUEST_RESET")

        context = {'model': model, 'session': model.Session, 'user': toolkit.c.user,
                   'auth_user_obj': toolkit.c.userobj}

        log.debug("got request from {0}".format(request.remote_addr))

        try:
            check_access('request_reset', context)
        except NotAuthorized:
            abort(401, _('Unauthorized to request a token.'))

        if toolkit.c.user:
            # Don't offer the reset form if already logged in
            return render('user/logout_first.html')

        if request.method == 'POST':

            # Get the params that were posted        
            params = toolkit.request.params
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
                    error_msg = _(u'Reset failed {0}. Please try again.'.format(unicode(e)))
                    h.flash_error(error_msg)
                    return render('user/request_reset.html', extra_vars={'email': email})
                except toolkit.NotAuthorized:
                    return render('user/logout_first.html')
                except logic.NotFound as e:
                    error_msg = _(u'Reset failed, problem retrieving the user associated to the email {0}.'.format(e))
                    h.flash_error(error_msg)
                    return render('user/request_reset.html', extra_vars={'email': email})
                except mailer.MailerException as e:
                    h.flash_error(_('Could not send token link: %s') % unicode(e))

            log.debug("controller redirecting: user.login, email =  " + str(email))
            toolkit.redirect_to(controller='user', action='login', email=email)

        return render('user/request_reset.html')

    def passwordless_perform_reset(self, id=None):
        '''
        
        '''
        log.debug(" ** PERFORM_RESET")
        if toolkit.c.user:
            # Don't offer the reset form if already logged in
            return render('user/logout_first.html')

        key = request.params.get('key')

        toolkit.redirect_to(controller='user', action='login',
                            id=id, key=key)

    def _login_error_redirect(self, email='', key='', id=''):
        log.debug("rendering user/login.html")
        return render('user/login.html', extra_vars={'email': email, 'key': key, 'id': id})
