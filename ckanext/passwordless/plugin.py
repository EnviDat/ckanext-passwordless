import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model
import uuid
import re
import datetime

from ckan.common import _

import ckan.lib.helpers as h

import pylons
import pylons.config as config

from ckanext.passwordless import util 

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
        return map_       
    
    # IAuthenticator
    def login(self):
        '''Handle an attempt to login
        '''
        # Get the params that were posted to /user/login.
        params = toolkit.request.params
        log.debug('login: params = ' + str(params))
        
        token = params.get('token')
        log.debug('login: token = ' + str(token))
        email = token
        
        if params:
            if not util.check_email(email):
                error_msg = _(u'Please introduce a valid mail.')
                h.flash_error(error_msg)
            else:
                user = util.get_user(email)
                log.debug('login: user = ' + str(user))
            
                if not user:
                    error_msg = _(u'No user with that mail.')
                    h.flash_error(error_msg)
                else:
                    log.debug('login: toolkit.c = ' + str(toolkit.c))
                    log.debug('login: name = ' + str(user['name']))
                    pylons.session['ckanext-passwordless-user'] = user['name']
                    log.debug('login: email = ' + str(email))
                    pylons.session['ckanext-passwordless-email'] = email
                    pylons.session.save()
                    error_msg = _(u'Successfully logged in.')
                    h.flash_success(error_msg)
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





