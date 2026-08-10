"""
Legacy CheckMK API Client for CheckMK 1.6.x using webapi.py

Translates REST API calls (used by all handlers) into webapi.py actions
so handlers require zero changes.
"""

import http.cookiejar
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from api.client import CheckMKClient
from api.exceptions import (
    CheckMKAPIError,
    CheckMKAuthenticationError,
    CheckMKConnectionError,
    CheckMKPermissionError,
)
from config import CheckMKConfig


class LegacyCheckMKClient(CheckMKClient):
    """CheckMK 1.6.x client — translates REST calls to webapi.py actions"""

    is_legacy = True

    def __init__(self, config: CheckMKConfig, webapi_url: str):
        super().__init__(config, skip_url_detection=True)
        self.is_legacy = True  # re-assert after parent __init__ resets it
        self._webapi_url = webapi_url
        self.api_base_url = webapi_url  # shown in debug output
        self._session_cj: Optional[http.cookiejar.CookieJar] = None

    # ------------------------------------------------------------------
    # Override request() — dispatch to webapi instead of REST
    # ------------------------------------------------------------------

    def request(
        self,
        endpoint: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        retry_count: int = 0,
        use_api_prefix: bool = True,
    ) -> Dict[str, Any]:
        return self._dispatch(endpoint.strip("/"), method.upper(), data, params)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def _dispatch(
        self,
        e: str,
        m: str,
        data: Optional[Dict[str, Any]],
        params: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        # version
        if e == "version":
            return self._handle_version()

        # host_config collection
        if e == "domain-types/host_config/collections/all":
            if m == "GET":
                return self._handle_get_all_hosts(params)
            if m == "POST":
                return self._handle_add_host(data)

        # host_config single
        if e.startswith("objects/host_config/"):
            hostname = e[len("objects/host_config/"):]
            if m == "GET":
                return self._handle_get_host(hostname)
            if m in ("PUT", "PATCH"):
                return self._handle_edit_host(hostname, data)
            if m == "DELETE":
                return self._handle_delete_host(hostname)

        # folder_config collection
        if e == "domain-types/folder_config/collections/all":
            if m == "GET":
                return self._handle_get_all_folders()
            if m == "POST":
                return self._handle_add_folder(data)

        # folder_config single
        if e.startswith("objects/folder_config/"):
            path = e[len("objects/folder_config/"):]
            if m == "GET":
                return self._handle_get_folder(path)
            if m in ("PUT", "PATCH"):
                return self._handle_edit_folder(path, data)
            if m == "DELETE":
                return self._handle_del_folder(path)

        # host_group_config
        if e == "domain-types/host_group_config/collections/all":
            return self._handle_get_all_groups("host")

        # service_group_config
        if e == "domain-types/service_group_config/collections/all":
            return self._handle_get_all_groups("service")

        # user_config
        if e == "domain-types/user_config/collections/all":
            return self._handle_get_all_users()

        # activation_run
        if "activation_run/actions/activate-changes" in e:
            return self._handle_activate_changes(data)
        if "activation_run/collections/pending_changes" in e:
            return self._handle_get_pending_changes()

        # acknowledge
        if e == "domain-types/acknowledge/collections/host":
            return self._handle_acknowledge(data, "host")
        if e == "domain-types/acknowledge/collections/service":
            return self._handle_acknowledge(data, "service")

        # downtime
        if e == "domain-types/downtime/collections/all":
            if m == "GET":
                return self._handle_get_all_downtimes(params)
            if m == "POST":
                return self._handle_add_downtime(data)
        if e == "domain-types/downtime/collections/host":
            return self._handle_add_downtime(data)
        if e == "domain-types/downtime/collections/service":
            return self._handle_add_downtime(data)
        if "downtime/actions/delete" in e:
            return self._handle_delete_downtime(data)

        # service discovery
        if "service_discovery/actions/start" in e:
            return self._handle_discover_services(data)

        # host tags
        if e == "domain-types/host_tag_group/collections/all":
            return self._handle_get_hosttags()

        return self._unsupported_response(f"Endpoint not available in CheckMK 1.6.x: {m} {e}")

    # ------------------------------------------------------------------
    # view.py HTTP helpers
    # ------------------------------------------------------------------

    def _view_base_url(self) -> str:
        return self._webapi_url.replace("webapi.py", "view.py")

    def _view_request(self, view_name: str, extra_params: Optional[Dict[str, str]] = None) -> Any:
        """Call view.py with output_format=json and return parsed rows (read-only)."""
        url_params: Dict[str, str] = {
            "view_name": view_name,
            "output_format": "json",
            "_username": self.config.username,
            "_secret": self.config.password,
        }
        if extra_params:
            url_params.update(extra_params)
        url = self._view_base_url() + "?" + urllib.parse.urlencode(url_params)
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, context=self._ssl_context, timeout=self.config.timeout) as response:
            raw = response.read().decode()
        return json.loads(raw)  # [[col1,col2,...],[row1val1,...],...]

    def _view_login(self, force: bool = False) -> http.cookiejar.CookieJar:
        """Login to view.py using automation secret as password; cache session cookie jar."""
        if self._session_cj is not None and not force:
            return self._session_cj
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context),
            urllib.request.HTTPCookieProcessor(cj),
        )
        login_url = self._view_base_url().replace("view.py", "login.py")
        login_data = urllib.parse.urlencode({
            "filled_in": "login",
            "_login": "1",
            "_origtarget": "index.py",
            "_username": self.config.username,
            "_password": self.config.password,
        }).encode()
        req = urllib.request.Request(
            login_url, data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with opener.open(req, timeout=self.config.timeout):
            pass
        self._session_cj = cj
        return cj

    def _view_command(self, cj: http.cookiejar.CookieJar, view_name: str,
                      filter_params: Dict[str, str], command_fields: Dict[str, str]) -> None:
        """Execute a view.py command using the 2-step submit→confirm flow."""
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context),
            urllib.request.HTTPCookieProcessor(cj),
        )
        view_url = self._view_base_url()

        def _get(url: str) -> str:
            with opener.open(urllib.request.Request(url), timeout=self.config.timeout) as r:
                return r.read().decode()

        def _post(data: Dict) -> str:
            encoded = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(
                view_url, data=encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with opener.open(req, timeout=self.config.timeout) as r:
                return r.read().decode()

        def _extract_hidden(html: str) -> Dict[str, str]:
            fields: Dict[str, str] = {}
            for inp in re.findall(r'<input[^>]+type="hidden"[^>]+>', html, re.I):
                n = re.search(r'name="([^"]+)"', inp)
                v = re.search(r'value="([^"]*)"', inp)
                if n:
                    fields[n.group(1)] = v.group(1) if v else ""
            return fields

        # Step 1: GET the view to obtain transid + selection_id
        qs = urllib.parse.urlencode({"view_name": view_name, **filter_params})
        page = _get(f"{view_url}?{qs}")
        forms = re.findall(r"<form[^>]*>(.*?)</form>", page, re.DOTALL)
        if len(forms) < 2:
            raise CheckMKAPIError("view.py: no command form found", 500, {})
        action_form = forms[1]
        transid_m = re.search(r'name="_transid" value="([^"]+)"', action_form)
        sel_m = re.search(r'name="selection" value="([^"]+)"', action_form)
        if not transid_m or not sel_m:
            raise CheckMKAPIError("view.py: missing transid or selection", 500, {})

        # Step 2: POST command → receive confirmation dialog
        submit_data = {
            "filled_in": "actions",
            "_transid": transid_m.group(1),
            "_do_actions": "yes",
            "actions": "yes",
            "selection": sel_m.group(1),
            "view_name": view_name,
            **filter_params,
            **command_fields,
        }
        confirm_page = _post(submit_data)

        # Step 3: If confirmation needed, extract hidden fields and GET confirm URL
        if "_do_confirm" in confirm_page:
            confirm_forms = re.findall(r"<form[^>]*>(.*?)</form>", confirm_page, re.DOTALL)
            if len(confirm_forms) < 2:
                raise CheckMKAPIError("view.py: no confirm form found", 500, {})
            hidden = _extract_hidden(confirm_forms[1])
            hidden["_do_confirm"] = "Yes!"
            _get(f"{view_url}?{urllib.parse.urlencode(hidden)}")

    def _view_get_downtimes(self, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Fetch downtimes from view.py and normalise to REST shape."""
        extra: Dict[str, str] = {}
        # Map REST params to view.py filter params
        if params:
            if params.get("host_name"):
                extra["host"] = params["host_name"]
            elif params.get("host"):
                extra["host"] = params["host"]
            if params.get("downtime_type") == "service":
                extra["is_service"] = "1"
        try:
            rows = self._view_request("downtimes", extra)
        except Exception as e:
            raise CheckMKAPIError(f"view.py downtimes failed: {e}", 500, {})
        if not rows:
            return self._success({"value": []})
        cols = rows[0]
        value = []
        for i, row in enumerate(rows[1:]):
            rd = dict(zip(cols, row))
            # Normalise to a shape the handlers can work with
            value.append({
                "id": str(i),
                "title": f"{rd.get('host', '')} downtime",
                "extensions": {
                    "host_name": rd.get("host", ""),
                    "service_description": rd.get("service_description", ""),
                    "comment": rd.get("downtime_comment", ""),
                    "author": rd.get("downtime_author", ""),
                    "start_time": rd.get("downtime_start_time", ""),
                    "end_time": rd.get("downtime_end_time", ""),
                    "is_service": 1 if rd.get("service_description") else 0,
                    **rd,
                },
            })
        return self._success({"value": value})

    # ------------------------------------------------------------------
    # webapi.py HTTP helper
    # ------------------------------------------------------------------

    def _legacy_request(
        self,
        action: str,
        extra_params: Optional[Dict[str, str]] = None,
        request_object: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Call webapi.py and return the parsed response dict."""
        url_params = {
            "action": action,
            "_username": self.config.username,
            "_secret": self.config.password,
            "output_format": "json",
        }
        if extra_params:
            url_params.update(extra_params)

        url = self._webapi_url + "?" + urllib.parse.urlencode(url_params)

        try:
            if request_object is not None:
                post_data = urllib.parse.urlencode(
                    {"request": json.dumps(request_object)}
                ).encode()
                req = urllib.request.Request(url, data=post_data, method="POST")
            else:
                req = urllib.request.Request(url, method="GET")

            with urllib.request.urlopen(
                req, context=self._ssl_context, timeout=self.config.timeout
            ) as response:
                raw = response.read().decode()

            parsed = json.loads(raw)

            if parsed.get("result_code") != 0:
                raise CheckMKAPIError(
                    f"webapi error: {parsed.get('result', 'unknown error')}", 400, parsed
                )

            return parsed

        except (CheckMKAPIError, CheckMKAuthenticationError,
                CheckMKPermissionError, CheckMKConnectionError):
            raise
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise CheckMKAuthenticationError(
                    f"Authentication failed: {e.reason}", e.code, {}
                )
            if e.code == 403:
                raise CheckMKPermissionError(
                    f"Permission denied: {e.reason}", e.code, {}
                )
            raise CheckMKAPIError(f"HTTP {e.code}: {e.reason}", e.code, {})
        except Exception as e:
            raise CheckMKConnectionError(f"Legacy request failed: {str(e)}")

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def _success(self, data: Any) -> Dict[str, Any]:
        return {"status": 200, "data": data, "success": True, "raw_content": "", "headers": {}}

    def _unsupported_response(self, msg: str) -> Dict[str, Any]:
        return self._success({"value": [], "_note": f"[vibeMK] {msg}"})

    # ------------------------------------------------------------------
    # Endpoint handlers
    # ------------------------------------------------------------------

    def _handle_version(self) -> Dict[str, Any]:
        # get_site_globals is not available in this CheckMK 1.6 build
        return self._success({"version": "1.6.x", "edition": "unknown"})

    def _handle_get_all_hosts(self, params: Optional[Dict]) -> Dict[str, Any]:
        extra = {}
        if params and params.get("folder"):
            extra["folder"] = params["folder"]
        r = self._legacy_request("get_all_hosts", extra)
        value = []
        for hostname, info in (r.get("result") or {}).items():
            value.append({
                "id": hostname,
                "title": hostname,
                "extensions": {
                    "attributes": info.get("attributes", {}),
                    "folder": info.get("path", "/"),
                },
            })
        return self._success({"value": value})

    def _handle_get_host(self, hostname: str) -> Dict[str, Any]:
        r = self._legacy_request("get_host", {"hostname": hostname})
        info = r.get("result") or {}
        return self._success({
            "id": hostname,
            "title": hostname,
            "extensions": {
                "attributes": info.get("attributes", {}),
                "folder": info.get("path", "/"),
            },
        })

    def _handle_add_host(self, data: Optional[Dict]) -> Dict[str, Any]:
        d = data or {}
        req_obj = {
            "hostname": d.get("host_name", d.get("hostname", "")),
            "folder": d.get("folder", "/"),
            "attributes": d.get("attributes", {}),
        }
        self._legacy_request("add_host", request_object=req_obj)
        return self._success({"id": req_obj["hostname"], "title": req_obj["hostname"]})

    def _handle_edit_host(self, hostname: str, data: Optional[Dict]) -> Dict[str, Any]:
        req_obj = {"hostname": hostname, "attributes": (data or {}).get("attributes", {})}
        self._legacy_request("edit_host", request_object=req_obj)
        return self._success({"id": hostname, "title": hostname})

    def _handle_delete_host(self, hostname: str) -> Dict[str, Any]:
        self._legacy_request("delete_host", request_object={"hostname": hostname})
        return self._success({})

    def _handle_get_all_folders(self) -> Dict[str, Any]:
        r = self._legacy_request("get_all_folders")
        value = []
        for path, info in (r.get("result") or {}).items():
            value.append({
                "id": path,
                "title": info.get("title", path),
                "extensions": {"path": path, "attributes": info.get("attributes", {})},
            })
        return self._success({"value": value})

    def _handle_get_folder(self, path: str) -> Dict[str, Any]:
        r = self._legacy_request("get_folder", {"foldername": path})
        info = r.get("result") or {}
        return self._success({
            "id": path,
            "title": info.get("title", path),
            "extensions": {"path": path, "attributes": info.get("attributes", {})},
        })

    def _handle_add_folder(self, data: Optional[Dict]) -> Dict[str, Any]:
        d = data or {}
        # Accept the handler-supplied "name", or callers passing "folder"/"foldername".
        name = d.get("name") or d.get("folder") or d.get("foldername") or ""
        title = d.get("title") or name
        parent = d.get("parent", "/") or "/"

        # 1.6's add_folder takes a single `folder` key with the FULL path
        # (parents joined by "/"). There is no separate `parent` field, and
        # the request key is `folder` — not `foldername` (which earlier
        # versions of this adapter used and which 1.6 rejects with
        # "Missing required key(s): folder"). The handler may pass the
        # parent in 2.x style ("~" / "/" for root); normalize both.
        parent_clean = parent.replace("~", "/").strip("/").strip()
        folder_path = f"{parent_clean}/{name}" if parent_clean else name

        # 1.6's `attributes` dict is strictly validated against the
        # inheritable-attribute list (site, ipaddress, tag_*, parents,
        # contactgroups, network_scan, …). It does NOT accept `title` —
        # passing it returns "Unknown attribute: title". The folder's
        # display title in 1.6 GUI is derived from the path itself; if a
        # different display title is needed later, set it via the
        # `set_folder` / `edit_folder` action (separate field, not an
        # attribute).
        attributes = dict(d.get("attributes", {}) or {})
        attributes.pop("title", None)  # defensive: drop if caller injected it

        req_obj = {
            "folder": folder_path,
            "attributes": attributes,
        }
        self._legacy_request("add_folder", request_object=req_obj)
        return self._success({"id": folder_path, "title": title})

    def _handle_edit_folder(self, path: str, data: Optional[Dict]) -> Dict[str, Any]:
        # The REST-style handler URL-encodes paths with "~" as separator
        # (e.g. "~parent~child"). 1.6 webapi expects "/" separators and a
        # leading-slash-free path. The request key is `folder` (was wrongly
        # `foldername` — 1.6 rejects that with "Missing required key(s):
        # folder").
        folder = path.replace("~", "/").lstrip("/")
        req_obj = {"folder": folder, "attributes": (data or {}).get("attributes", {})}
        self._legacy_request("edit_folder", request_object=req_obj)
        return self._success({"id": folder})

    def _handle_del_folder(self, path: str) -> Dict[str, Any]:
        self._legacy_request("delete_folder", request_object={"folder": path})
        return self._success({})

    def _handle_get_all_groups(self, group_type: str) -> Dict[str, Any]:
        action = {"host": "get_all_hostgroups", "service": "get_all_servicegroups"}.get(
            group_type, f"get_all_{group_type}groups"
        )
        r = self._legacy_request(action)
        value = []
        for name, info in (r.get("result") or {}).items():
            value.append({
                "id": name,
                "title": info.get("alias", name),
                "extensions": {"alias": info.get("alias", name)},
            })
        return self._success({"value": value})

    def _handle_get_all_users(self) -> Dict[str, Any]:
        r = self._legacy_request("get_all_users")
        value = []
        for userid, info in (r.get("result") or {}).items():
            value.append({
                "id": userid,
                "title": info.get("alias", userid),
                "extensions": info,
            })
        return self._success({"value": value})

    def _handle_activate_changes(self, data: Optional[Dict] = None) -> Dict[str, Any]:
        """1.6 webapi activate_changes — honors sites + foreign-change override.

        Accepts the same `data` shape the 2.x REST endpoint takes
        (handler default: {"sites": [...] or None, "force_foreign_changes": bool}).
        For 1.6 we translate to:
          - mode: "specific" + sites=[...]  if sites given
          - mode: "dirty"                    otherwise
          - allow_foreign_changes: true      when force_foreign_changes is truthy
        Without `allow_foreign_changes` the master rejects with
        "Authorization Error … foreign changes are not allowed" whenever
        any pending change was authored by a different user than the
        automation account this client uses.
        """
        d = data or {}
        req_obj: Dict[str, Any] = {"mode": "dirty"}
        sites = d.get("sites")
        if sites:
            req_obj["mode"] = "specific"
            req_obj["sites"] = sites
        if d.get("force_foreign_changes"):
            # 1.6 webapi parses this with `bool(int(value))` — must be a
            # numeric literal (1/0), NOT a JSON boolean. Sending True
            # serialises to `true`, and `int("true")` raises ValueError.
            req_obj["allow_foreign_changes"] = 1
        self._legacy_request("activate_changes", req_obj)
        return self._success({"id": "legacy-activation", "extensions": {"status": "completed"}})

    def _handle_get_pending_changes(self) -> Dict[str, Any]:
        # webapi has no direct equivalent; return empty list
        return self._success({"value": []})

    def _handle_acknowledge(self, data: Optional[Dict], obj_type: str) -> Dict[str, Any]:
        return self._unsupported_response("Acknowledge API not available in this CheckMK 1.6 build")

    def _handle_get_all_downtimes(self, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Read downtimes via view.py (webapi has no downtime actions in 1.6)."""
        return self._view_get_downtimes(params)

    def _view_command_with_session(self, view_name: str, filter_params: Dict[str, str],
                                    command_fields: Dict[str, str]) -> None:
        """Call _view_command using the cached session; re-login once on session expiry."""
        cj = self._view_login()
        try:
            self._view_command(cj, view_name, filter_params, command_fields)
        except CheckMKAPIError as e:
            # If the command form was not found it likely means session expired → re-login once
            if "no command form" in str(e).lower() or "missing transid" in str(e).lower():
                cj = self._view_login(force=True)
                self._view_command(cj, view_name, filter_params, command_fields)
            else:
                raise

    def _handle_add_downtime(self, data: Optional[Dict]) -> Dict[str, Any]:
        """Schedule downtime via view.py (login → submit → confirm flow)."""
        import datetime as _dt
        d = data or {}
        host = d.get("host_name", "")
        if not host:
            raise CheckMKAPIError("host_name is required for downtime scheduling", 400, {})

        comment = d.get("comment", "Scheduled via vibeMK")

        # Compute duration in minutes from start_time/end_time or duration field
        start_str = d.get("start_time", "")
        end_str = d.get("end_time", "")
        if start_str and end_str:
            # Parse ISO / "YYYY-MM-DD HH:MM:SS" strings
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    t_start = _dt.datetime.strptime(start_str[:19], fmt)
                    t_end = _dt.datetime.strptime(end_str[:19], fmt)
                    duration_minutes = max(1, int((t_end - t_start).total_seconds() / 60))
                    break
                except ValueError:
                    pass
            else:
                duration_minutes = 60
        else:
            raw = d.get("duration", 3600)
            duration_minutes = max(1, int(raw / 60) if isinstance(raw, (int, float)) else 60)

        # Determine view + filter by whether this is a host or service downtime
        svc = d.get("service_description", "")
        if svc:
            view_name = "allservices"
            filter_params = {"host": host, "service_regex": f"^{re.escape(svc)}$"}
        else:
            view_name = "allhosts"
            filter_params = {"host": host}

        try:
            self._view_command_with_session(view_name, filter_params, {
                "_down_comment": comment,
                "_down_from_now": "From now for",
                "_down_minutes": str(duration_minutes),
            })
        except (CheckMKAPIError, CheckMKAuthenticationError,
                CheckMKPermissionError, CheckMKConnectionError):
            raise
        except Exception as e:
            raise CheckMKAPIError(f"Downtime scheduling failed: {e}", 500, {})

        return self._success({"id": "legacy-downtime", "extensions": {"status": "scheduled"}})

    def _handle_delete_downtime(self, data: Optional[Dict]) -> Dict[str, Any]:
        """Remove downtimes via view.py _remove_downtimes command."""
        d = data or {}
        host = d.get("host_name", "")
        comment = d.get("comment", "")
        svc = d.get("service_description", "")

        if not host:
            # Query-based delete: extract host from query string if present
            query = str(d.get("query", ""))
            m = re.search(r'"host_name"[^"]*"([^"]+)"', query)
            if not m:
                m = re.search(r'host_name.*?"right"\s*:\s*"([^"]+)"', query)
            if m:
                host = m.group(1)
            if not host:
                return self._unsupported_response("host_name required for downtime deletion in 1.6")

        filter_params: Dict[str, str] = {"host": host}
        if svc:
            filter_params["service_regex"] = f"^{re.escape(svc)}$"
        if comment:
            filter_params["downtime_comment"] = comment

        view_name = "allservices" if svc else "downtimes"

        try:
            self._view_command_with_session(view_name, filter_params, {"_remove_downtimes": "Remove"})
        except (CheckMKAPIError, CheckMKAuthenticationError,
                CheckMKPermissionError, CheckMKConnectionError):
            raise
        except Exception as e:
            raise CheckMKAPIError(f"Downtime deletion failed: {e}", 500, {})

        return self._success({})

    def _handle_discover_services(self, data: Optional[Dict]) -> Dict[str, Any]:
        d = data or {}
        req_obj = {
            "hostname": d.get("host_name", ""),
            "mode": d.get("mode", "new"),
        }
        self._legacy_request("discover_services", request_object=req_obj)
        return self._success({"id": "legacy-discovery", "extensions": {"status": "started"}})

    def _handle_get_hosttags(self) -> Dict[str, Any]:
        r = self._legacy_request("get_hosttags")
        tag_groups = (r.get("result") or {}).get("tag_groups", [])
        value = [
            {"id": tg.get("id", ""), "title": tg.get("title", ""), "extensions": tg}
            for tg in tag_groups
        ]
        return self._success({"value": value})
