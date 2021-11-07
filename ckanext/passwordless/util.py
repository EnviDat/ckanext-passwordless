import ckan.plugins.toolkit as toolkit
import ckan.model
import re
import datetime
import uuid

from logging import getLogger

log = getLogger(__name__)


def check_email(email):
    if email:
        if re.match(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", email):
            return True
    return False


def get_user_id(email):
    """Return the CKAN user id with the given email address.
    :rtype: A CKAN user id
    """
    # make case insensitive
    email = email.lower()

    # We do this by accessing the CKAN model directly, because there isn't a
    # way to search for users by email address using the API yet.
    users = ckan.model.User.by_email(email)

    if users:
        user = users[0]
        return user.id
    return None


def get_user(email):
    """Return the CKAN user with the given email address.
    :rtype: A CKAN user dict
    """

    id = get_user_id(email)

    if id:
        user_dict = toolkit.get_action('user_show')(data_dict={'id': id})
        return user_dict
    return None


def generate_user_name(email, offset=0):
    """Generate a user name for the given email address (offset should be unique).
    """
    # unique_num = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
    max_len = 99
    username = email.lower().replace('@', '-').replace('.', '_')[0:max_len]

    if offset > 0:
        str_offset = '_' + str(offset)
        username = username[0:max_len - len(str_offset)]
        username += str_offset
    return username


def generate_user_fullname(email):
    """Generate a random user name for the given email address.
    """
    # FIXME: Generate a better user name, based on the email, but still making
    # sure it's unique.
    # return str(uuid.uuid4())
    return email.split('@')[0].replace('.', ' ').title()


def generate_password():
    """Generate a random password.
    """
    # FIXME: Replace this with a better way of generating passwords, or enable
    # users without passwords in CKAN.
    return str(uuid.uuid4())


def renew_master_token(user_name = None):

    log.debug("renew_master_token: Renewing API KEY token **")
    user = toolkit.c.user

    if user or user_name:
        # check if there is one already and delete it
        user_id = user_name if user_name else user.get('id')
        data_dict = {u'user': user_id}
        api_keys = toolkit.get_action('api_token_list')(
            context={'ignore_auth': True},
            data_dict=data_dict)
        log.debug("renew_master_token ({1}) api_keys = {0}".format(", ".join([k['name'] for k in api_keys]), data_dict[u'user']))
        for key in api_keys:
            if key.get('name') == 'master':
                log.debug("renew_master_token deleting key = {0}".format(key))
                toolkit.get_action('api_token_revoke')(
                    context={'ignore_auth': True},
                    data_dict={u'jti': key['id']})

        # generate new API KEY for user that lasts 7 days
        new_api_key = toolkit.get_action('api_token_create')(
                context={'ignore_auth': True},
                data_dict={'user': user_id, 'name': 'master', 'expires_in': 7, 'unit': 86400})
        log.debug('renew_master_token new API key: {0}'.format(new_api_key))
        return new_api_key['token']
    else:
        return None
