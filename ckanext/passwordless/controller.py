import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckan.lib.base as base
import ckan.model as model
import ckan.lib.helpers as h
import ckan.lib.mailer as mailer
import ckan.lib.captcha as captcha

from ckan.common import _, c, g, request, response
from logging import getLogger

from ckanext.passwordless import util 
from ckanext.passwordless.passwordless_mailer import passwordless_send_reset_link

import json

NotAuthorized = logic.NotAuthorized
NotFound = logic.NotFound

check_access = logic.check_access
render = base.render
log = getLogger(__name__)

class PasswordlessController(toolkit.BaseController):

    def __before__(self, action, **env):
        base.BaseController.__before__(self, action, **env)
        try:
            context = {'model': model, 'user': c.user or c.author,
                       'auth_user_obj': c.userobj}
            check_access('site_read', context)
        except NotAuthorized:
            if c.action not in ('passwordless_request_reset', 'passwordless_perform_reset',):
                abort(401, _('Not authorized to see this page (action)'))

    def passwordless_request_reset(self):
        '''
        
        '''
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        data_dict = {'id': request.params.get('user')}

        try:
            check_access('request_reset', context)
        except NotAuthorized:
            abort(401, _('Unauthorized to request a token.'))

        if c.user:
            # Don't offer the reset form if already logged in
            return render('user/logout_first.html')
        
        if request.method == 'POST':

            # Get the params that were posted        
            params = toolkit.request.params
            log.debug('passwordless_request_reset (POST): params = ' + str(params))
            
            email = params.get('email')
            log.debug('passwordless_request_reset: email = ' + str(email))
        
            if params:
                if not util.check_email(email):
                    error_msg = _(u'Please introduce a valid mail.')
                    h.flash_error(error_msg)
                    return render('user/request_reset.html', extra_vars={'email':email})
                    
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
                    # token
                    self.request_token(user.get('id'))
            h.redirect_to(controller='user', action='login', email=email)
        return render('user/request_reset.html')

    def passwordless_perform_reset(self, id=None):
        '''
        
        '''
        if c.user:
            # Don't offer the reset form if already logged in
            return render('user/logout_first.html')

        key = request.params.get('key')

        h.redirect_to(controller='user', action='login',
                       id=id, key=key)
                       
    def _create_user(self, email):   
        data_dict =  {'email': email,
                       'fullname': util.generate_user_fullname(email),
                       'name': self._get_new_username(email),
                       'password': util.generate_password()}
        user = toolkit.get_action('user_create')(
            context={'ignore_auth': True},
            data_dict=data_dict)
        return user

    def _get_new_username(self, email):
        offset = 0
        username = util.generate_user_name(email)
        while offset<100000:
            try:
                user_dict = toolkit.get_action('user_show')(data_dict={'id': username})
            except logic.NotFound:
                return username
            offset += 1
            username = util.generate_user_name(email,offset)
        return None


    def request_token(self, id):

        if c.user:
            # Don't offer the reset form if already logged in
            return render('user/logout_first.html')
        
        context = {'model': model,
                   'user': c.user}

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
        
    def passwordless_retry_login(self):
        if c.user:
            # Don't offer the reset form if already logged in
            return render('user/logout_first.html')
        params = toolkit.request.params
        log.debug('login: params = ' + str(params))
        
        email = params.get( 'email', '')
        key = params.get( 'key', '')
        id = params.get( 'id', '')

        return render('user/login.html', extra_vars={'email':email, 'key':key})
