import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckan.lib.base as base
import ckan.model as model
import ckan.lib.helpers as h
import ckan.lib.mailer as mailer
import ckan.lib.captcha as captcha

from ckan.common import _, g, request, response

from logging import getLogger

from ckanext.passwordless import util
from ckanext.passwordless.passwordless_mailer import passwordless_send_reset_link

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

import json

NotAuthorized = logic.NotAuthorized
NotFound = logic.NotFound

check_access = logic.check_access
render = base.render
abort = base.abort

log = getLogger(__name__)

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
            return render('user/logout_first.html')
            
        # Get the params that were posted to /user/login.
        params = toolkit.request.params
        log.debug('login: params = ' + str(params))
        
        # If there are no params redirect to login
        if not params:
            log.debug('login: NO params' )
            return self._login_error_redirect()
            
        key = params.get('key')
        id = params.get('id')
        email = params.get('email','')
        method = toolkit.request.method
    
        if email and not key:
            if (method == 'POST'):
                error_msg = _(u'Login failed (reset key not provided)')
                h.flash_error(error_msg)
            log.debug("email but no key, reload")
            return self._login_error_redirect(email=email)

        # FIXME 403 error for invalid key is a non helpful page
        context = {'model': model, 'session': model.Session,
                   'user': id,
                   'keep_email': True}
        if not id and email:
            if not util.check_email(email):
                error_msg = _(u'Login failed (email not valid)')
                h.flash_error(error_msg)
                return self._login_error_redirect()
            id = util.get_user_id(email)
            log.debug('login: id (email) = ' + str(id))
    
        user_obj = None
        try:
            data_dict = {'id': id}
            user_dict = logic.get_action('user_show')(context, data_dict)
            user_obj = context['user_obj']
        except logic.NotFound, e:
            h.flash_error(_('User not found'))
            return self._login_error_redirect(email=email, key=key, id=id)

        if not user_obj or not mailer.verify_reset_link(user_obj, key):
            h.flash_error(_('Invalid token. Please try again.'))
            return self._login_error_redirect(email=email, key=key, id=id)
        
        # CKAN 2.7 - 2.8
        try:
            pylons.session['ckanext-passwordless-user'] = user_dict['name']
            pylons.session.save()
        except:
            log.debug("login: pylons session not available")

            flask.session['ckanext-passwordless-user'] = user_dict['name']

        #remove token
        mailer.create_reset_key(user_obj)
    
        debug_msg = _(u'Successfully logged in ({username}).'.format(username=user_dict['name']))
        h.flash_success(debug_msg)
        toolkit.redirect_to(controller='user', action='dashboard')

    def passwordless_request_reset(self):
        '''
        
        '''
        log.debug(" ** REQUEST_RESET")

        context = {'model': model, 'session': model.Session, 'user': toolkit.c.user,
                   'auth_user_obj': toolkit.c.userobj}
        data_dict = {'id': request.params.get('user')}

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
            log.debug('passwordless_request_reset (POST): params = ' + str(params))
            
            email = params.get('email')
            log.debug('passwordless_request_reset: email = ' + str(email))
        
            if params:
                # error if no mail
                if not util.check_email(email):
                    error_msg = _(u'Please introduce a valid mail.')
                    h.flash_error(error_msg)
                    return render('user/request_reset.html', extra_vars={'email':email})
                
                email = email.lower()
                
                # Check captcha
                try:
                    captcha.check_recaptcha(request)
                except captcha.CaptchaError:
                    error_msg = _(u'Bad Captcha. Please try again.')
                    h.flash_error(error_msg)
                    return render('user/request_reset.html', extra_vars={'email':email})
                    
                user = util.get_user(email)
            
                if not user:
                    # A user with this email address doesn't yet exist in CKAN,
                    # so create one.
                    user = self._create_user(email)
                    log.debug('passwordless_request_reset: created user = ' + str(email))

                if user:
                    # token request
                    self._request_token(user.get('id'))
            
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
                       
    def _create_user(self, email):   
        data_dict =  {'email': email.lower(),
                       'fullname': util.generate_user_fullname(email),
                       'name': self._get_new_username(email),
                       'password': util.generate_password()}
        user = toolkit.get_action('user_create')(
            context={'ignore_auth': True},
            data_dict=data_dict)
        return user

    def _get_new_username(self, email):
        offset = 0
        email = email.lower()
        username = util.generate_user_name(email)
        while offset<100000:
            log.debug(username)
            try:
                user_dict = toolkit.get_action('user_show')(data_dict={'id': username})
            except logic.NotFound:
                return username
            offset += 1
            username = util.generate_user_name(email,offset)
        return None


    def _request_token(self, id):

        if toolkit.c.user:
            # Don't offer the reset form if already logged in
            return render('user/logout_first.html')
        
        context = {'model': model,
                   'user': toolkit.c.user}

        data_dict = {'id': id}
        user_obj = None
        try:
            user_dict = toolkit.get_action('user_show')(context, data_dict)
            user_obj = context['user_obj']
        except logic.NotFound:
            # Try searching the user
            del data_dict['id']
            data_dict['q'] = id

            if id and len(id) > 2:
                user_list = toolkit.get_action('user_list')(context, data_dict)
                if len(user_list) == 1:
                    # This is ugly, but we need the user object for the
                    # mailer,
                    # and user_list does not return them
                    del data_dict['q']
                    data_dict['id'] = user_list[0]['id']
                    user_dict = toolkit.get_action('user_show')(context, data_dict)
                    user_obj = context['user_obj']
                elif len(user_list) > 1:
                    h.flash_error(_('"%s" matched several users') % (id))
                else:
                    h.flash_error(_('No such user: %s') % id)
            else:
                h.flash_error(_('No such user: %s') % id)

        if user_obj:
            try:
                passwordless_send_reset_link(user_obj)
                h.flash_success(_('Please check your inbox for '
                                'an access token.'))
            except mailer.MailerException, e:
                h.flash_error(_('Could not send token link: %s') %
                              unicode(e))
        return

    def _login_error_redirect(self, email='', key='', id=''):
        log.debug("rendering user/login.html")
        return render('user/login.html', extra_vars = {'email': email, 'key':key, 'id':id})
