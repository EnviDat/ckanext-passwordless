import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.lib.base as base
import ckan.lib.mailer as mailer
import ckan.logic as logic
import ckan.model
import uuid
import re
import datetime

from ckan.common import _

import ckan.lib.helpers as h

import pylons
import pylons.config as config

from ckanext.passwordless import util 

abort = base.abort

from logging import getLogger
log = getLogger(__name__)

class PasswordlessPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IAuthenticator, inherit=True)
 
    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'passwordless')
    
    # IRoutes
    def before_map(self, map_):
        map_.connect(
            'request_reset',
            '/user/reset',
            controller='ckanext.passwordless.controller:PasswordlessController',
            action = 'passwordless_request_reset'
        )
        map_.connect(
            '',
            '/user/reset/{id:.*}',
            controller='ckanext.passwordless.controller:PasswordlessController',
            action = 'passwordless_perform_reset'
        )
        map_.connect(
            '',
            '/user/retry_login',
            controller='ckanext.passwordless.controller:PasswordlessController',
            action = 'passwordless_retry_login'
        )
        return map_       
        
    def after_map(self, map_):
        #log.debug(map_)
        return map_       
  
    # IAuthenticator
    def login(self):
        '''Handle an attempt to login
        '''
        # Get the params that were posted to /user/login.
        params = toolkit.request.params
        log.debug('login: params = ' + str(params))
        
        # If there are no params redirect to reset
        if not params:
            log.debug('ERROR: login: NO params' )
            return self._login_error_redirect()
                
        key = params.get('key')
        id = params.get('id')
        email = params.get('email','')
        method = toolkit.request.method
        
        if email and not key:
            if (method == 'POST'):
                error_msg = _(u'Login failed (reset key not provided)')
                h.flash_error(error_msg)
            return self._login_error_redirect(email=email)

        # FIXME 403 error for invalid key is a non helpful page
        context = {'model': ckan.model, 'session': ckan.model.Session,
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

        pylons.session['ckanext-passwordless-user'] = user_dict['name']
        pylons.session.save()
        #remove token
        mailer.create_reset_key(user_obj)
        
        #debug_msg = _(u'Successfully logged in ({username}).'.format(username=user_dict['name']))
        #h.flash_success(debug_msg)
        h.redirect_to(controller='user', action='dashboard')

    def identify(self):
        '''Identify which user (if any) is logged-in 
        If a logged-in user is found, set toolkit.c.user to be their user name.
        '''
        # Try to get the item that login() placed in the session.
        user = pylons.session.get('ckanext-passwordless-user')
        if user:
            # We've found a logged-in user. Set c.user to let CKAN know.
            toolkit.c.user = user
        else:
            toolkit.c.user = None
    
    def _delete_session_items(self):
        import pylons
        if 'ckanext-passwordless-user' in pylons.session:
            del pylons.session['ckanext-passwordless-user']
        if 'ckanext-passwordless-email' in pylons.session:
            del pylons.session['ckanext-passwordless-email']
        pylons.session.save()

    def logout(self):
        '''Handle a logout.'''
        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()

    def abort(self, status_code, detail, headers, comment):
        '''Handle an abort.'''

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()

    def _login_error_redirect(self, email='', key='', id=''):
        h.redirect_to(controller='ckanext.passwordless.controller:PasswordlessController', 
                                  action='passwordless_retry_login', 
                                  email=email, key=key, id=id)




