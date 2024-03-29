import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckanext.passwordless.logic
import ckanext.passwordless.blueprints as blueprints

import flask

from logging import getLogger

log = getLogger(__name__)


class PasswordlessPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IBlueprint, inherit=True)

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')

    # IAuthenticator
    def identify(self):
        """Identify which user (if any) is logged-in 
        If a logged-in user is found, set toolkit.c.user to be their user name.
        """

        user = None

        # Try to get the item that login() placed in the session.
        user = flask.session.get('ckanext-passwordless-user')

        if user:
            # We've found a logged-in user. Set c.user to let CKAN know.
            toolkit.c.user = user
            # log.debug("identify: USER is " + str(user))
        else:
            # log.debug("identify: NO USER")
            toolkit.c.user = None

    def _delete_session_items(self):
        if 'ckanext-passwordless-user' in flask.session:
            del flask.session['ckanext-passwordless-user']
        if 'ckanext-passwordless-email' in flask.session:
            del flask.session['ckanext-passwordless-email']

    def logout(self):
        """Handle a logout."""
        # Delete the session item, so that identify() will no longer find it.
        log.debug("passwordless IAuth logout")
        self._delete_session_items()

    def abort(self, status_code, detail, headers, comment):
        """Handle an abort."""

        # Delete the session item, so that identify() will no longer find it.
        self._delete_session_items()

    # IActions
    def get_actions(self):
        return {
            'passwordless_perform_reset':
                ckanext.passwordless.logic.perform_reset,
            'passwordless_user_login':
                ckanext.passwordless.logic.user_login,
            'passwordless_user_logout':
                ckanext.passwordless.logic.user_logout
        }

    # IBlueprint
    def get_blueprint(self):
        return blueprints.get_blueprints(self.name, self.__module__)
