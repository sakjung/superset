# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# This file is included in the final Docker image and SHOULD be overridden when
# deploying the image to prod. Settings configured here are intended for use in local
# development environments. Also note that superset_config_docker.py is imported
# as a final step as a means to override "defaults" configured here
#
import logging
import os
from datetime import timedelta
from typing import Optional

from cachelib.file import FileSystemCache
from celery.schedules import crontab
from flask_appbuilder.security.manager import AUTH_DB
from flask_login import LoginManager

from superset.security import SupersetSecurityManager

logger = logging.getLogger()


def get_env_variable(var_name: str, default: Optional[str] = None) -> str:
    """Get the environment variable or raise exception."""
    try:
        return os.environ[var_name]
    except KeyError:
        if default is not None:
            return default
        else:
            error_msg = "The environment variable {} was missing, abort...".format(
                var_name
            )
            raise EnvironmentError(error_msg)


DATABASE_DIALECT = get_env_variable("DATABASE_DIALECT")
DATABASE_USER = get_env_variable("DATABASE_USER")
DATABASE_PASSWORD = get_env_variable("DATABASE_PASSWORD")
DATABASE_HOST = get_env_variable("DATABASE_HOST")
DATABASE_PORT = get_env_variable("DATABASE_PORT")
DATABASE_DB = get_env_variable("DATABASE_DB")

# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = "%s://%s:%s@%s:%s/%s" % (
    DATABASE_DIALECT,
    DATABASE_USER,
    DATABASE_PASSWORD,
    DATABASE_HOST,
    DATABASE_PORT,
    DATABASE_DB,
)

REDIS_HOST = get_env_variable("REDIS_HOST")
REDIS_PORT = get_env_variable("REDIS_PORT")
REDIS_CELERY_DB = get_env_variable("REDIS_CELERY_DB", "0")
REDIS_RESULTS_DB = get_env_variable("REDIS_RESULTS_DB", "1")
REDIS_DATA_CACHE_DB = get_env_variable("REDIS_RESULTS_DB", "2")
REDIS_FILTER_STATE_CACHE_DB = get_env_variable("REDIS_RESULTS_DB", "3")
REDIS_EXPLORE_FORM_DATA_CACHE_DB = get_env_variable("REDIS_RESULTS_DB", "4")

RESULTS_BACKEND = FileSystemCache("/app/superset_home/sqllab")

CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_cache_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_RESULTS_DB,
}
DATA_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_data_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_DATA_CACHE_DB,
}
FILTER_STATE_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_filter_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_FILTER_STATE_CACHE_DB,
}
EXPLORE_FORM_DATA_CACHE_CONFIG = {
    "CACHE_TYPE": "RedisCache",
    "CACHE_DEFAULT_TIMEOUT": 86400,
    "CACHE_KEY_PREFIX": "superset_explore_",
    "CACHE_REDIS_HOST": REDIS_HOST,
    "CACHE_REDIS_PORT": REDIS_PORT,
    "CACHE_REDIS_DB": REDIS_EXPLORE_FORM_DATA_CACHE_DB,
}


class CeleryConfig(object):
    broker_url = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
    imports = ("superset.sql_lab",)
    result_backend = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_RESULTS_DB}"
    worker_prefetch_multiplier = 1
    task_acks_late = False
    beat_schedule = {
        "reports.scheduler": {
            "task": "reports.scheduler",
            "schedule": crontab(minute="*", hour="*"),
        },
        "reports.prune_log": {
            "task": "reports.prune_log",
            "schedule": crontab(minute=10, hour=0),
        },
    }


CELERY_CONFIG = CeleryConfig

FEATURE_FLAGS = {
    "ALERT_REPORTS": True,
    "CLIENT_CACHE": True,
    "ENABLE_EXPLORE_JSON_CSRF_PROTECTION": False,
    "PRESTO_EXPAND_DATA": True,
}
ALERT_REPORTS_NOTIFICATION_DRY_RUN = True
WEBDRIVER_BASEURL = "http://superset:8088/"
# The base URL for the email report hyperlinks.
WEBDRIVER_BASEURL_USER_FRIENDLY = WEBDRIVER_BASEURL

# SQL LAB
SQLLAB_CTAS_NO_LIMIT = True
SQLLAB_TIMEOUT = int(timedelta(seconds=60).total_seconds())

# Logging
ENABLE_TIME_ROTATE = True

SECRET_KEY = "YOUR_OWN_RANDOM_GENERATED_SECRET_KEY"

# Set the authentication type to OAuth
AUTH_TYPE = AUTH_DB
# Will allow user self registration, allowing to create Flask users from Authorized User
AUTH_USER_REGISTRATION = True
# The default user self registration role
# Can change it to Gamma if want user to have dashboard view
AUTH_USER_REGISTRATION_ROLE = "Gamma"
SAML_PATH = "/app/superset_home/saml"
LOGOUT_REDIRECT_URL = "https://{DASHBOARD_DOMAIN}/saml/acs"

# Add endpoints that need to be exempt from CSRF protection
WTF_CSRF_EXEMPT_LIST = [
    "superset.views.core.log",
    "superset.views.core.explore_json",
    "superset.charts.data.api.data",

    "superset.views.saml.assertion_consumer_service",
    "superset.views.saml.single_sign_on",
    "superset.views.saml.single_logout",
    "superset.views.saml.single_logout_service",
    "superset.views.saml.metadata"
]
ENABLE_PROXY_FIX = True

class RecoSupersetSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
        super(RecoSupersetSecurityManager, self).__init__(appbuilder)

    def create_login_manager(self, app) -> LoginManager:
        lm = super().create_login_manager(app)
        lm.login_view = "https://{DASHBOARD_DOMAIN}/saml/acs"
        lm.refresh_view = "https://{DASHBOARD_DOMAIN}/saml/acs"
        return lm


CUSTOM_SECURITY_MANAGER = RecoSupersetSecurityManager

#
# Optionally import superset_config_docker.py (which will have been included on
# the PYTHONPATH) in order to allow for local settings to be overridden
#
try:
    import superset_config_docker
    from superset_config_docker import *  # noqa

    logger.info(
        f"Loaded your Docker configuration at " f"[{superset_config_docker.__file__}]"
    )
except ImportError:
    logger.info("Using default Docker config...")
