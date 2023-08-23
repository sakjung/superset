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

import uuid
from typing import Union
import datetime

from flask import request, session, make_response, redirect, g
from flask_appbuilder import expose
from flask_appbuilder.api import safe
from flask_login import login_user
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from werkzeug import Response

from .base import BaseSupersetView
from superset import conf
from superset.extensions import event_logger

REMEMBER_COOKIE_DURATION = datetime.timedelta(days=1)


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=conf["SAML_PATH"])
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    request.scheme = "https"
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        "post_data": request.form.copy(),
    }


class SAMLView(BaseSupersetView):
    """
    Superset (SP) - Gsuite (IDP) SAML2.0 연동을 위한 Custom View API
    Reference: https://github.com/SAML-Toolkits/python3-saml > demo-flask 예제 참고
    """

    route_base = "/saml"
    allow_browser_login = True
    default_view = "assertion_consumer_service"

    @expose("/acs", methods=["GET", "POST"])
    @event_logger.log_this
    @safe
    def assertion_consumer_service(self) -> Union[Response, str]:
        """
        [IDP -> SP]
        - Single Sign-On 최초 진입점 (= SAML index page) API [GET]
        - Single Sign-On Response API [POST]
            - 아래 Single Sign-On (= /sso API) 에서 보낸 request에 대한 IDP 측 response 를 이 API에서 받아서 처리한다
        """
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        errors = []
        error_reason = None
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False

        request_id = None

        if (request.method == "GET" and g.user is not None and g.user.is_authenticated
            and "samlUserdata" in session):
            return redirect(self.appbuilder.get_url_for_index)
        elif request.method == "POST":
            if "AuthNRequestID" in session:
                request_id = session["AuthNRequestID"]

            auth.process_response(request_id=request_id)
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if len(errors) == 0:
                if "AuthNRequestID" in session:
                    del session["AuthNRequestID"]
                session["samlUserdata"] = auth.get_attributes()
                session["samlNameId"] = auth.get_nameid()
                session["samlNameIdFormat"] = auth.get_nameid_format()
                session["samlNameIdNameQualifier"] = auth.get_nameid_nq()
                session["samlNameIdSPNameQualifier"] = auth.get_nameid_spnq()
                session["samlSessionIndex"] = auth.get_session_index()

                user = self.appbuilder.sm.find_user(email=session["samlNameId"])
                if not user:
                    password = str(uuid.uuid4())
                    user = self.appbuilder.sm.add_user(
                        username=session["samlNameId"],
                        first_name=session["samlNameId"],
                        last_name=session["samlNameId"],
                        email=session["samlNameId"],
                        password=password,
                        # Custom Role for only dashboard view
                        role=self.appbuilder.sm.find_role("Viewer"),
                    )
                login_user(user, remember=True, duration=REMEMBER_COOKIE_DURATION)
                return_to = f"{request.host_url}superset/welcome/"
                return redirect(auth.redirect_to(return_to))
            elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()

        return self.render_template(
            "saml/saml.html",
            errors=errors,
            error_reason=error_reason,
            not_auth_warn=not_auth_warn,
            success_slo=success_slo,
            attributes=attributes,
            paint_logout=paint_logout,
        )

    @expose("/sso", methods=["GET", "POST"])
    @event_logger.log_this
    @safe
    def single_sign_on(self):
        """
        [SP -> IDP] Single Sign-On Request API
        """
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        return_to = f"{request.host_url}superset/welcome/"
        return redirect(auth.login(return_to))

    @expose("/slo", methods=["GET", "POST"])
    @event_logger.log_this
    @safe
    def single_logout(self):
        """
        [SP -> IDP] Single Logout Request API
        """
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        return_to = f"{request.host_url}saml/acs"

        name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
        if "samlNameId" in session:
            name_id = session["samlNameId"]
        if "samlSessionIndex" in session:
            session_index = session["samlSessionIndex"]
        if "samlNameIdFormat" in session:
            name_id_format = session["samlNameIdFormat"]
        if "samlNameIdNameQualifier" in session:
            name_id_nq = session["samlNameIdNameQualifier"]
        if "samlNameIdSPNameQualifier" in session:
            name_id_spnq = session["samlNameIdSPNameQualifier"]

        return redirect(
            auth.logout(
                name_id=name_id,
                session_index=session_index,
                nq=name_id_nq,
                name_id_format=name_id_format,
                spnq=name_id_spnq,
                return_to=return_to,
            )
        )

    @expose("/sls", methods=["GET", "POST"])
    @event_logger.log_this
    @safe
    def single_logout_service(self):
        """
        [IDP -> SP] Single Logout Response 처리 API
        위 single_logout (= /slo API) 에서 보낸 request에 대한 IDP 측 response 를 이 API에서 받아서 처리한다
        """
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        errors = []
        error_reason = None
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False

        request_id = None
        if "LogoutRequestID" in session:
            request_id = session["LogoutRequestID"]
        dscb = lambda: session.clear()
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the url is a trusted URL.
                return redirect(url)
            else:
                success_slo = True
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

        return self.render_template(
            "saml/saml.html",
            errors=errors,
            error_reason=error_reason,
            not_auth_warn=not_auth_warn,
            success_slo=success_slo,
            attributes=attributes,
            paint_logout=paint_logout,
        )

    @expose("/metadata", methods=["GET"])
    @event_logger.log_this
    @safe
    def metadata(self):
        """
        [IDP -> SP] SP (Superset) 측 metadata 조회 API
        """
        req = prepare_flask_request(request)
        auth = init_saml_auth(req)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers["Content-Type"] = "text/xml"
        else:
            resp = make_response(", ".join(errors), 500)
        return resp
