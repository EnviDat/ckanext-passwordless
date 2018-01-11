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

from logging import getLogger
log = getLogger(__name__)

class PasswordlessPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'passwordless')
        
    # IAuthenticator
    def login(self):
        '''Handle an attempt to login
        '''
        # Get the params that were posted to /user/login.
        params = toolkit.request.params
        log.debug('login: params = ' + str(params))
        
        email = params.get('email')
        log.debug('login: email = ' + str(email))
        
        if params:
            if not check_email(email):
                error_msg = _(u'Please introduce a valid mail.')
                h.flash_error(error_msg)
            else:
                user = get_user(email)
                log.debug('login: user = ' + str(user))
            
                if not user:
                    # A user with this email address doesn't yet exist in CKAN,
                    # so create one.
                    log.debug('login: create user = ' + str(email))
                    user = toolkit.get_action('user_create')(
                        context={'ignore_auth': True},
                        data_dict={'email': email,
                                   'fullname': generate_user_fullname(email),
                                   'name': generate_user_name(email),
                                   'password': generate_password()})
                if user:
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


def get_user(email):
    '''Return the CKAN user with the given email address.
    :rtype: A CKAN user dict
    '''
    # We do this by accessing the CKAN model directly, because there isn't a
    # way to search for users by email address using the API yet.
    users = ckan.model.User.by_email(email)
    
    if users:
        # But we need to actually return a user dict, so we need to convert it
        # here.
        user = users[0]
        user_dict = toolkit.get_action('user_show')(data_dict={'id': user.id})
        return user_dict
    # delete, just for test
    else:
        user = ckan.model.User.get(email)
        log.debug('_get_user: user.get = ' + str(user))
        if user:
            # But we need to actually return a user dict, so we need to convert it
            # here.
            user_dict = toolkit.get_action('user_show')(data_dict={'id': user.id})
            return user_dict
        
    return None

def generate_user_name(email):
    '''Generate a random user name for the given email address.
    '''
    # FIXME: Generate a better user name, based on the email, but still making
    # sure it's unique.
    #return str(uuid.uuid4())
    unique_num = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    return(email.replace('@', '-').replace('.', '_') + '_' + unique_num)


def generate_user_fullname(email):
    '''Generate a random user name for the given email address.
    '''
    # FIXME: Generate a better user name, based on the email, but still making
    # sure it's unique.
    #return str(uuid.uuid4())
    return(email.split('@')[0].replace('.', ' ').title())


def generate_password():
    '''Generate a random password.
    '''
    # FIXME: Replace this with a better way of generating passwords, or enable
    # users without passwords in CKAN.
    return str(uuid.uuid4())

def check_email(email):
    if email:
        if re.match(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", email):
            return True
    return False