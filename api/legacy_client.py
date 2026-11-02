"""
Legacy CheckMK API Client for CheckMK 1.6.x using webapi.py

Translates REST API calls (used by all handlers) into webapi.py actions
so handlers require zero changes.
"""

import http.cookiejar
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from api.client import CheckMKClient
from api.exceptions import (
    CheckMKAPIError,
    CheckMKAuthenticationError,
    CheckMKConnectionError,
    CheckMKNotFoundError,
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
        self._version: Optional[str] = None
        # 1.6 discovery is synchronous, so there is never a job to poll. Keep
        # the outcome of each run so the 2.x "status"/"wait" calls that follow
        # a start can answer with what actually happened.
        self._discovery_runs: Dict[str, Dict[str, Any]] = {}
        self._bulk_jobs: Dict[str, Dict[str, Any]] = {}

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

        # comments (acknowledgements are listed and removed through these)
        if e.startswith("domain-types/comment/collections/") and m == "GET":
            return self._handle_get_comments(params, e.rsplit("/", 1)[1])
        if e.startswith("objects/comment/") and m == "DELETE":
            return self._handle_delete_comment(urllib.parse.unquote(e[len("objects/comment/"):]))

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

        # services (monitoring state) via view.py - CheckMK 1.6 webapi has no
        # service state API at all, which is why every service lookup used to
        # come back empty on this build.
        if e == "domain-types/service/collections/all":
            return self._handle_get_services(params)
        if e.startswith("objects/host/") and "/actions/show_service/invoke" in e:
            hostname = e[len("objects/host/"):].split("/", 1)[0]
            merged = dict(params or {})
            merged.update(data or {})
            merged["host_name"] = hostname
            # With a service named, the REST original returns ONE service object,
            # and the status handler reads data["extensions"] straight off it.
            if merged.get("service_description"):
                return self._handle_get_service(hostname, merged["service_description"])
            return self._handle_get_services(merged)
        if e.startswith("objects/service/") and m == "GET":
            rest = e[len("objects/service/"):]
            hostname, _, svc = rest.partition("/")
            return self._handle_get_service(
                urllib.parse.unquote(hostname), urllib.parse.unquote(svc)
            )

        # live host state
        if e.startswith("objects/host/") and "/" not in e[len("objects/host/"):] and m == "GET":
            return self._handle_get_host_status(urllib.parse.unquote(e[len("objects/host/"):]))

        # service discovery. The handlers use both "service_discovery" and
        # "service_discovery_run" spellings; matching only the first sent every
        # vibemk_start_service_discovery call to the not-supported fallback,
        # which used to report success without contacting CheckMK.
        if "bulk-discovery-start" in e:
            return self._handle_bulk_discovery(data)
        if re.fullmatch(r"domain-types/service_discovery(_run)?/actions/start/invoke", e):
            return self._handle_discover_services(data)
        if e.startswith("objects/service_discovery_run/"):
            return self._handle_discovery_run_status(
                urllib.parse.unquote(e[len("objects/service_discovery_run/"):].split("/", 1)[0])
            )
        if e.startswith("objects/discovery_run/"):
            return self._handle_bulk_discovery_status(urllib.parse.unquote(e[len("objects/discovery_run/"):]))
        if e.startswith("objects/service_discovery/"):
            host = urllib.parse.unquote(e[len("objects/service_discovery/"):])
            last = self._discovery_runs.get(host)
            hint = f" Last run in this session ({last['mode']}): {last['result']}" if last else ""
            self._unsupported(
                "CheckMK 1.6 webapi cannot preview a discovery (no check table without changing it)." + hint
            )

        # host tags
        if e == "domain-types/host_tag_group/collections/all":
            return self._handle_get_hosttags()

        self._unsupported(f"Endpoint not available in CheckMK 1.6.x: {m} {e}")

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
                      filter_params: Dict[str, str], command_fields: Dict[str, str]) -> str:
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
        final_page = confirm_page
        if "_do_confirm" in confirm_page:
            confirm_forms = re.findall(r"<form[^>]*>(.*?)</form>", confirm_page, re.DOTALL)
            if len(confirm_forms) < 2:
                raise CheckMKAPIError("view.py: no confirm form found", 500, {})
            hidden = _extract_hidden(confirm_forms[1])
            hidden["_do_confirm"] = "Yes!"
            final_page = _get(f"{view_url}?{urllib.parse.urlencode(hidden)}")

        # CheckMK 1.6 answers a rejected command with HTTP 200 and an error div,
        # so a silent "success" here means nothing unless the page is inspected.
        problem = self._view_page_error(final_page)
        if problem:
            raise CheckMKAPIError(f"view.py {view_name}: {problem}", 500, {})
        return final_page

    @staticmethod
    def _view_page_error(html: str) -> str:
        """Extract an error/warning message CheckMK rendered into a view page."""
        for pattern in (
            r'<div class="error[^"]*">(.*?)</div>',
            r'<div class=error>(.*?)</div>',
        ):
            m = re.search(pattern, html, re.DOTALL | re.I)
            if m:
                text = re.sub(r"<[^>]+>", " ", m.group(1))
                text = " ".join(text.split())
                if text:
                    return text[:300]
        return ''

    def _view_get_downtimes(self, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Fetch downtimes from view.py and normalise to REST shape.

        Honours the REST-style ``query`` expression the handlers send. Without
        it every caller that asked "is there a SERVICE downtime for host X with
        comment Y" got back "yes" for any downtime on X at all, which is how a
        host-wide downtime passed verification as a service downtime.
        """
        extra: Dict[str, str] = {}
        query = None
        if params:
            if params.get("host_name"):
                extra["host"] = params["host_name"]
            elif params.get("host"):
                extra["host"] = params["host"]
            if params.get("downtime_type") == "service":
                extra["is_service"] = "1"
            query = params.get("query")
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
            svc = rd.get("service_description", "")
            # Explicit keys must come AFTER **rd - the raw view columns used to
            # overwrite is_service and hide every service downtime as a host one.
            ext = {
                **rd,
                "host_name": rd.get("host", ""),
                "service_description": svc,
                "comment": rd.get("downtime_comment", ""),
                "author": rd.get("downtime_author", ""),
                "start_time": rd.get("downtime_start_time", ""),
                "end_time": rd.get("downtime_end_time", ""),
                "is_service": 1 if svc else 0,
                "type": 3 if svc else 2,
            }
            if not self._query_matches(query, ext):
                continue
            value.append(
                {
                    # Prefer CheckMK's own downtime id; the row index it used to
                    # return is a position in the site-wide list, not an id.
                    "id": str(rd.get("downtime_id") or i),
                    "title": f"{ext['host_name']} downtime",
                    "extensions": ext,
                }
            )
        return self._success({"value": value})

    def _query_matches(self, query: Any, ext: Dict[str, Any]) -> bool:
        """Evaluate a CheckMK REST-style query expression against a downtime row.

        Supports the subset the handlers emit: and/or/not plus the leaf ops
        =, !=, ~. Anything unrecognised matches, so an unknown filter can never
        silently hide rows from a caller.
        """
        if not query:
            return True
        if isinstance(query, str):
            try:
                query = json.loads(query)
            except (TypeError, ValueError):
                return True
        if not isinstance(query, dict):
            return True

        op = query.get("op")
        if op in ("and", "or"):
            results = [self._query_matches(x, ext) for x in (query.get("expr") or [])]
            if not results:
                return True
            return all(results) if op == "and" else any(results)
        if op == "not":
            return not self._query_matches(query.get("expr"), ext)

        left, right = query.get("left"), query.get("right")
        if left is None:
            return True
        actual = str(ext.get(left, ""))
        right = str(right)
        if op == "=":
            return actual == right
        if op == "!=":
            return actual != right
        if op == "~":
            # Callers pass comments verbatim as the pattern, and a comment like
            # "CRIT (PagerDuty #123)" is a regex that does NOT match itself.
            # Fall back to substring containment so that cannot cause a miss.
            try:
                if re.search(right, actual):
                    return True
            except re.error:
                pass
            return right in actual
        return True

    def _extract_query_fields(self, query: Any) -> Dict[str, str]:
        """Pull host_name / service_description / comment out of a query tree."""
        found: Dict[str, str] = {}

        def walk(node: Any) -> None:
            if isinstance(node, str):
                try:
                    node = json.loads(node)
                except (TypeError, ValueError):
                    return
            if isinstance(node, list):
                for item in node:
                    walk(item)
                return
            if not isinstance(node, dict):
                return
            if node.get("op") in ("and", "or", "not"):
                walk(node.get("expr"))
                return
            left, right = node.get("left"), node.get("right")
            if isinstance(left, str) and right is not None and left not in found:
                found[left] = str(right)

        walk(query)
        return found

    def _assert_view_scoped(
        self,
        view_name: str,
        filter_params: Dict[str, str],
        host: str,
        services: Optional[List[str]] = None,
        require_no_service_rows: bool = False,
    ) -> int:
        """Verify a view's filters really narrowed the rows before commanding it.

        A view.py command applies to every row the view displays, so a filter
        the GUI quietly ignored would turn "downtime one service" into
        "downtime the whole site". Returns the number of matching rows.
        """
        try:
            rows = self._view_request(view_name, filter_params)
        except Exception as e:
            raise CheckMKAPIError(f"view.py {view_name} pre-check failed: {e}", 500, {})
        if not rows or len(rows) < 2:
            return 0

        cols = rows[0]
        for row in rows[1:]:
            rd = dict(zip(cols, row))
            row_host = rd.get("host", "") or rd.get("host_name", "")
            if row_host and row_host != host:
                raise CheckMKAPIError(
                    f"view.py {view_name}: host filter was not applied - row for "
                    f"'{row_host}' present while filtering for '{host}'. Refusing to run the command.",
                    500,
                    {},
                )
            row_svc = rd.get("service_description", "") or rd.get("service", "")
            if services and row_svc and row_svc not in services:
                raise CheckMKAPIError(
                    f"view.py {view_name}: service filter was not applied - row for "
                    f"'{row_svc}' present. Refusing to run the command.",
                    500,
                    {},
                )
            if require_no_service_rows and row_svc:
                # A host-scoped removal must not sweep up this host's service
                # downtimes as collateral.
                raise CheckMKAPIError(
                    f"view.py {view_name}: service downtime for '{row_svc}' is in scope of a "
                    f"host-level removal. Refusing to run the command.",
                    500,
                    {},
                )
        return len(rows) - 1

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

    def _unsupported(self, msg: str) -> None:
        """Fail an endpoint 1.6 cannot serve.

        This used to return success with an empty value list, so every write
        the adapter did not translate - discovery, acknowledgements, comments -
        was reported to the caller as done without CheckMK ever being called.
        """
        raise CheckMKAPIError(
            f"[vibeMK] {msg}", 501, {"title": "Not supported on CheckMK 1.6", "detail": msg}
        )

    # ------------------------------------------------------------------
    # Endpoint handlers
    # ------------------------------------------------------------------

    def _handle_version(self) -> Dict[str, Any]:
        # 1.6 webapi has no version action (get_site_globals is absent too), but
        # the unauthenticated login page footer carries it: "Version: 1.6.0p11".
        if self._version is None:
            version = "1.6.x"
            try:
                login_url = self._view_base_url().replace("view.py", "login.py")
                with urllib.request.urlopen(
                    urllib.request.Request(login_url), context=self._ssl_context, timeout=self.config.timeout
                ) as r:
                    m = re.search(r"Version:\s*([0-9][0-9A-Za-z.\-]*)", r.read().decode(errors="replace"))
                if m:
                    version = m.group(1)
            except Exception:
                pass
            self._version = version
        return self._success(
            {"version": self._version, "edition": "unknown", "versions": {"checkmk": self._version}}
        )

    def _handle_get_host_status(self, hostname: str) -> Dict[str, Any]:
        """Live host state from the hoststatus view (1.6 webapi has none)."""
        try:
            rows = self._view_request("hoststatus", {"host": hostname})
        except Exception as e:
            raise CheckMKAPIError(f"view.py hoststatus failed: {e}", 500, {})
        hosts = [dict(zip(rows[0], r)) for r in rows[1:]] if rows else []
        row = next((h for h in hosts if h.get("host") == hostname), None)
        if row is None:
            raise CheckMKNotFoundError(f"Host '{hostname}' is not monitored")

        state_text = str(row.get("host_state", "")).strip().upper()
        state = {"UP": 0, "DOWN": 1, "UNREACH": 2, "UNREACHABLE": 2}.get(state_text)
        # host_attempt is "current/max"; a problem state is hard once it hits max.
        attempt, _, max_attempts = str(row.get("host_attempt", "")).partition("/")
        state_type = 1 if state == 0 or (attempt and attempt == max_attempts) else 0
        return self._success(
            {
                "id": hostname,
                "title": hostname,
                "extensions": {
                    **row,
                    "name": hostname,
                    "state": state,
                    "hard_state": state if state_type == 1 else None,
                    "state_type": state_type,
                    "has_been_checked": 0 if state_text == "PEND" else 1,
                    "plugin_output": row.get("host_plugin_output", ""),
                    "state_text": state_text,
                },
            }
        )

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
        """Map the 2.x host_config PUT shape onto 1.6 webapi edit_host.

        The 2.x handler sends exactly one of:
          {"attributes": {...}}         -> replace the attribute set
          {"update_attributes": {...}}  -> merge into the existing set
          {"remove_attributes": [...]}  -> drop those keys
        1.6's edit_host only understands `attributes` and `unset_attributes`,
        so for a merge we read the current set and compute the result here.
        Without this, an `update_attributes` payload fell through to an empty
        `attributes` dict: webapi returned result_code 0 and the caller
        reported "Host Updated Successfully" while nothing was written.
        """
        d = data or {}
        req_obj: Dict[str, Any] = {"hostname": hostname}

        if "update_attributes" in d:
            current = (
                (self._legacy_request("get_host", {"hostname": hostname}).get("result") or {})
                .get("attributes")
                or {}
            )
            merged = {k: v for k, v in current.items() if k != "meta_data"}
            merged.update(d.get("update_attributes") or {})
            req_obj["attributes"] = merged
        elif "remove_attributes" in d:
            req_obj["unset_attributes"] = list(d.get("remove_attributes") or [])
        else:
            req_obj["attributes"] = d.get("attributes", {})

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

    def _wato_page(self, mode: str) -> str:
        """GET a WATO page with the GUI session; re-login once if it expired."""
        url = self._view_base_url().replace("view.py", "wato.py") + "?" + urllib.parse.urlencode({"mode": mode})
        for force in (False, True):
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self._ssl_context),
                urllib.request.HTTPCookieProcessor(self._view_login(force=force)),
            )
            with opener.open(urllib.request.Request(url), timeout=self.config.timeout) as r:
                html = r.read().decode(errors="replace")
            if 'name="_login"' not in html:
                return html
        raise CheckMKAuthenticationError(f"wato.py?mode={mode}: GUI login was not accepted", 401, {})

    @staticmethod
    def _html_text(fragment: str) -> str:
        return " ".join(re.sub(r"<[^>]+>", " ", fragment).replace("&nbsp;", " ").split())

    def _html_tables(self, html: str) -> List[Tuple[str, List[Dict[str, str]]]]:
        """Return (css class, rows keyed by header text) for each data table."""
        tables = []
        for m in re.finditer(r'<table class="(data[^"]*)"[^>]*>(.*?)</table>', html, re.S):
            body = m.group(2)
            headers = [self._html_text(h) for h in re.findall(r"<th[^>]*>(.*?)</th>", body, re.S)]
            rows = []
            for tr in re.findall(r'<tr class="data[^"]*">(.*?)</tr>', body, re.S):
                cells = [self._html_text(td) for td in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
                rows.append(dict(zip(headers, cells)))
            tables.append((m.group(1), rows))
        return tables

    _CHANGE_VERBS = (
        ("create", ("created", "added", "new ")),
        ("delete", ("deleted", "removed")),
        ("move", ("moved", "renamed")),
        ("edit", ("modified", "changed", "edited", "saved", "updated", "did service discovery")),
    )

    def _handle_get_pending_changes(self) -> Dict[str, Any]:
        """Read pending changes from the activation page (wato.py?mode=changelog).

        1.6 webapi has no pending-changes action. This used to return an empty
        list unconditionally, so "no pending changes" was reported even with
        changes waiting. The page has a per-site table whose Changes column is
        authoritative, and a change list table; the two are cross-checked so a
        layout this parser does not understand fails loudly instead of reading
        as "nothing pending".
        """
        html = self._wato_page("changelog")
        tables = self._html_tables(html)

        site_rows = next((rows for css, rows in tables if "activation" in css), None)
        if site_rows is None or (site_rows and "Changes" not in site_rows[0]):
            raise CheckMKAPIError("Pending changes: activation table not found on wato.py?mode=changelog", 500, {})
        dirty_sites = [r.get("Site", "?") for r in site_rows if r.get("Changes", "0") not in ("", "0")]

        change_rows = next((rows for css, rows in tables if "changes" in css.split()), [])
        if dirty_sites and not change_rows:
            raise CheckMKAPIError(
                f"Pending changes exist on {len(dirty_sites)} site(s) ({', '.join(dirty_sites[:5])}) "
                "but the change list could not be parsed from wato.py?mode=changelog",
                500,
                {},
            )

        value = []
        for i, row in enumerate(change_rows):
            text = row.get("Change", "")
            lowered = text.lower()
            verb = next((v for v, words in self._CHANGE_VERBS if any(w in lowered for w in words)), "change")
            obj = row.get("Object", "")
            obj_type, _, obj_name = obj.partition(" ")
            value.append(
                {
                    "id": str(i),
                    "title": text,
                    "extensions": {
                        # The handler prints "<action_name>: <object_type> '<object_name>'"
                        # and buckets by verb, so carry both the verb and the text.
                        "action_name": f"{verb} - {text}" if text else verb,
                        "object_type": obj_type or "change",
                        "object_name": obj_name or obj or "-",
                        "user_id": row.get("User", "unknown"),
                        "time": row.get("Time", ""),
                        "affected_sites": row.get("Affected sites", ""),
                        "text": text,
                    },
                }
            )
        return self._success({"value": value})

    # ------------------------------------------------------------------
    # Acknowledgements and comments (view.py)
    # ------------------------------------------------------------------

    _COMMENT_ENTRY_TYPES = {"Comment": 1, "User": 1, "Downtime": 2, "Flapping": 3, "Acknowledgement": 4}

    def _view_get_comments(self, host: str = "") -> List[Dict[str, Any]]:
        """Read the comments view and normalise to the REST comment shape."""
        try:
            rows = self._view_request("comments", {"host": host} if host else None)
        except Exception as e:
            raise CheckMKAPIError(f"view.py comments failed: {e}", 500, {})
        out: List[Dict[str, Any]] = []
        for row in (rows or [])[1:]:
            rd = dict(zip(rows[0], row))
            if host and rd.get("host") != host:
                continue
            svc = rd.get("service_description", "")
            entry_text = rd.get("comment_entry_type", "")
            out.append(
                {
                    "id": str(rd.get("comment_id", "")),
                    "title": rd.get("comment_comment", ""),
                    "extensions": {
                        **rd,
                        "host_name": rd.get("host", ""),
                        "service_description": svc,
                        "is_service": bool(svc),
                        "comment": rd.get("comment_comment", ""),
                        "author": rd.get("comment_author", ""),
                        "entry_time": rd.get("comment_time", ""),
                        "entry_type": self._COMMENT_ENTRY_TYPES.get(entry_text, 0),
                        "entry_type_text": entry_text,
                        "persistent": None,  # not exposed by the 1.6 comments view
                    },
                }
            )
        return out

    def _handle_get_comments(self, params: Optional[Dict], collection: str) -> Dict[str, Any]:
        p = params or {}
        comments = self._view_get_comments(p.get("host_name", ""))
        if collection in ("host", "service"):
            comments = [c for c in comments if c["extensions"]["is_service"] == (collection == "service")]
        if p.get("service_description"):
            comments = [c for c in comments if c["extensions"]["service_description"] == p["service_description"]]
        return self._success({"value": comments})

    def _acks_present(self, host: str, service: str = "") -> List[Dict[str, Any]]:
        """Acknowledgement comments currently on a host (service="") or one service."""
        return [
            c
            for c in self._view_get_comments(host)
            if c["extensions"]["entry_type"] == 4 and c["extensions"]["service_description"] == service
        ]

    def _ack_target(self, host: str, service: str) -> Tuple[str, Dict[str, str]]:
        if service:
            return "allservices", {"host": host, "service_regex": f"^{re.escape(service)}$"}
        return "allhosts", {"host": host}

    def _handle_acknowledge(self, data: Optional[Dict], obj_type: str) -> Dict[str, Any]:
        """Acknowledge a host or service problem via the view.py command.

        Pre-checked (the row must exist and be in a problem state - CheckMK
        silently ignores an acknowledgement of an OK object) and verified
        afterwards against the comments view, because view.py reports nothing
        about what a command actually did.
        """
        d = data or {}
        host = d.get("host_name", "")
        service = d.get("service_description", "") if obj_type == "service" else ""
        comment = d.get("comment", "")
        if not host or (obj_type == "service" and not service):
            raise CheckMKAPIError("host_name (and service_description for services) is required", 400, {})
        if not comment:
            raise CheckMKAPIError("CheckMK 1.6 requires a comment for an acknowledgement", 400, {})
        if ";" in comment:
            raise CheckMKAPIError("CheckMK 1.6 rejects acknowledgement comments containing ';'", 400, {})

        target = f"{host}/{service}" if service else host
        view_name, filter_params = self._ack_target(host, service)
        if not self._assert_view_scoped(view_name, filter_params, host, [service] if service else None):
            raise CheckMKNotFoundError(f"'{target}' is not monitored - nothing to acknowledge")

        if service:
            state = (self._view_get_services(host, service, exact=True) or [{}])[0].get("extensions", {}).get("state")
            ok = state == 0
        else:
            ok = self._handle_get_host_status(host)["data"]["extensions"]["state"] == 0
        if ok:
            raise CheckMKAPIError(f"'{target}' is OK - CheckMK only acknowledges problems", 409, {})

        before = {c["id"] for c in self._acks_present(host, service)}
        fields = {"_acknowledge": "Acknowledge", "_ack_comment": comment}
        for key in ("sticky", "notify", "persistent"):
            if d.get(key):
                fields[f"_ack_{key}"] = "on"
        self._view_command_with_session(view_name, filter_params, fields)

        new = [c for c in self._acks_present(host, service) if c["id"] not in before]
        if not new:
            raise CheckMKAPIError(
                f"Acknowledge command for '{target}' was accepted but no acknowledgement appeared", 500, {}
            )
        return self._success({"id": new[0]["id"], "extensions": new[0]["extensions"]})

    def _remove_acknowledgement(self, host: str, service: str = "") -> Dict[str, Any]:
        target = f"{host}/{service}" if service else host
        if not self._acks_present(host, service):
            raise CheckMKNotFoundError(f"No acknowledgement on '{target}'")
        view_name, filter_params = self._ack_target(host, service)
        if not self._assert_view_scoped(view_name, filter_params, host, [service] if service else None):
            raise CheckMKNotFoundError(f"'{target}' is not monitored")
        self._view_command_with_session(view_name, filter_params, {"_remove_ack": "Remove Acknowledgement"})
        if self._acks_present(host, service):
            raise CheckMKAPIError(
                f"Remove-acknowledgement command for '{target}' was accepted but it is still acknowledged", 500, {}
            )
        return self._success({})

    def _handle_delete_comment(self, comment_id: str) -> Dict[str, Any]:
        """Delete by comment id. Only acknowledgement comments are supported:
        removing one means removing the acknowledgement it belongs to."""
        match = next((c for c in self._view_get_comments() if c["id"] == comment_id), None)
        if match is None:
            raise CheckMKNotFoundError(f"Comment #{comment_id} not found")
        ext = match["extensions"]
        if ext["entry_type"] != 4:
            self._unsupported(
                f"Deleting a {ext['entry_type_text'] or 'non-acknowledgement'} comment is not implemented for 1.6"
            )
        return self._remove_acknowledgement(ext["host_name"], ext["service_description"])

    def _handle_get_all_downtimes(self, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Read downtimes via view.py (webapi has no downtime actions in 1.6)."""
        return self._view_get_downtimes(params)

    def _view_command_with_session(self, view_name: str, filter_params: Dict[str, str],
                                    command_fields: Dict[str, str]) -> str:
        """Call _view_command using the cached session; re-login once on session expiry."""
        cj = self._view_login()
        try:
            return self._view_command(cj, view_name, filter_params, command_fields)
        except CheckMKAPIError as e:
            # If the command form was not found it likely means session expired → re-login once
            if "no command form" in str(e).lower() or "missing transid" in str(e).lower():
                cj = self._view_login(force=True)
                return self._view_command(cj, view_name, filter_params, command_fields)
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

        # Determine view + filter by whether this is a host or service downtime.
        # The handlers send service_descriptions (plural, a list); reading only
        # the singular key made every service downtime fall through to the
        # allhosts view and silently mute the entire host instead.
        svcs = self._service_list(d)

        if svcs:
            view_name = "allservices"
            alternation = "|".join(re.escape(x) for x in svcs)
            filter_params = {"host": host, "service_regex": f"^({alternation})$"}
        else:
            view_name = "allhosts"
            filter_params = {"host": host}

        matched = self._assert_view_scoped(view_name, filter_params, host, svcs)
        if not matched:
            target = f"{host}/[{', '.join(svcs)}]" if svcs else host
            raise CheckMKAPIError(
                f"No monitored rows matched '{target}' - nothing to schedule downtime for", 404, {}
            )

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

        return self._success(
            {
                "id": "legacy-downtime",
                "extensions": {
                    "status": "scheduled",
                    "downtime_type": "service" if svcs else "host",
                    "host_name": host,
                    "service_descriptions": svcs,
                },
            }
        )

    def _handle_delete_downtime(self, data: Optional[Dict]) -> Dict[str, Any]:
        """Remove downtimes via view.py _remove_downtimes command."""
        d = data or {}
        host = d.get("host_name", "")
        comment = d.get("comment", "")
        svcs = self._service_list(d)

        # Query-based delete: the handler sends only {"delete_type": "query",
        # "query": "..."}. Parse the expression tree - the old regex captured
        # the literal string "right" as the host name, so the filtered view
        # matched no rows and the delete silently did nothing while the handler
        # still reported success.
        if not host or not svcs or not comment:
            parsed = self._extract_query_fields(d.get("query"))
            host = host or parsed.get("host_name", "")
            comment = comment or parsed.get("comment", "")
            if not svcs and parsed.get("service_description"):
                svcs = [parsed["service_description"]]

        if not host:
            raise CheckMKAPIError("host_name is required for downtime deletion in 1.6", 400, {})

        # Try the Downtimes view first - removing a downtime is what that view is
        # for - then fall back to the host/service views. Each attempt is scope-
        # checked before it runs and verified after, because 1.6 accepts a command
        # without ever reporting what it did.
        if svcs:
            alternation = "|".join(re.escape(x) for x in svcs)
            candidates = [
                ("downtimes", {"host": host, "service_regex": f"^({alternation})$"}, svcs, False),
                ("allservices", {"host": host, "service_regex": f"^({alternation})$"}, svcs, False),
            ]
        else:
            candidates = [
                ("downtimes", {"host": host}, None, True),
                ("allhosts", {"host": host}, None, False),
            ]

        attempts: List[str] = []
        for view_name, filter_params, scope_svcs, no_svc_rows in candidates:
            try:
                matched = self._assert_view_scoped(
                    view_name, filter_params, host, scope_svcs, require_no_service_rows=no_svc_rows
                )
            except CheckMKAPIError as e:
                attempts.append(f"{view_name}: {e}")
                continue
            if not matched:
                attempts.append(f"{view_name}: no matching rows")
                continue

            try:
                self._view_command_with_session(view_name, filter_params, {"_remove_downtimes": "Remove"})
            except (CheckMKAuthenticationError, CheckMKPermissionError, CheckMKConnectionError):
                raise
            except CheckMKAPIError as e:
                attempts.append(f"{view_name}: {e}")
                continue
            except Exception as e:
                attempts.append(f"{view_name}: {e}")
                continue

            if not self._downtimes_still_present(host, svcs):
                return self._success(
                    {
                        "removed_via": view_name,
                        "removed_scope": (
                            f"all downtimes on {host}/[{', '.join(svcs)}]"
                            if svcs
                            else f"all host-level downtimes on {host}"
                        ),
                        "note": (
                            "CheckMK 1.6 removes downtimes per host/service row, not per downtime id - "
                            "every downtime on the matched row(s) was removed."
                        ),
                    }
                )
            attempts.append(f"{view_name}: command accepted but downtimes still present")

        leftover = self._downtimes_still_present(host, svcs)
        raise CheckMKAPIError(
            f"Downtime removal did not take effect: {leftover} matching downtime(s) still active "
            f"on '{host}'. Attempts: " + " | ".join(attempts),
            500,
            {},
        )

    def _downtimes_still_present(self, host: str, services: Optional[List[str]] = None) -> int:
        """Count downtimes remaining on a host (or on the given services)."""
        try:
            rows = self._view_get_downtimes({"host_name": host})["data"].get("value", [])
        except Exception:
            return 0
        remaining = 0
        for dt in rows:
            ext = dt.get("extensions", {})
            if ext.get("host_name") and ext.get("host_name") != host:
                continue
            svc = ext.get("service_description", "")
            if services:
                if svc in services:
                    remaining += 1
            elif not svc:
                remaining += 1
        return remaining

    @staticmethod
    def _service_list(d: Dict[str, Any]) -> List[str]:
        """Normalise the singular/plural service keys the handlers use."""
        svcs = d.get("service_descriptions") or []
        if isinstance(svcs, str):
            svcs = [svcs]
        if not svcs and d.get("service_description"):
            svcs = [d["service_description"]]
        return [x for x in svcs if x]

    # ------------------------------------------------------------------
    # Service state (view.py "allservices")
    # ------------------------------------------------------------------

    _SERVICE_STATES = {
        "OK": 0,
        "WARN": 1,
        "WARNING": 1,
        "CRIT": 2,
        "CRITICAL": 2,
        "UNKN": 3,
        "UNKNOWN": 3,
    }

    @staticmethod
    def _first_of(row: Dict[str, Any], *keys: str) -> str:
        """Return the first non-empty value among candidate column names."""
        for k in keys:
            v = row.get(k)
            if v not in (None, ""):
                return v
        return ""

    def _view_get_services(self, host: str = "", service: str = "", exact: bool = False) -> List[Dict[str, Any]]:
        """Read service rows from the allservices view and normalise to REST shape."""
        extra: Dict[str, str] = {}
        if host:
            extra["host"] = host
        if service:
            extra["service_regex"] = f"^{re.escape(service)}$" if exact else service
        try:
            rows = self._view_request("allservices", extra)
        except Exception as e:
            raise CheckMKAPIError(f"view.py allservices failed: {e}", 500, {})
        if not rows or len(rows) < 2:
            return []

        cols = rows[0]
        out: List[Dict[str, Any]] = []
        for row in rows[1:]:
            rd = dict(zip(cols, row))
            host_name = self._first_of(rd, "host", "host_name")
            description = self._first_of(rd, "service_description", "service", "svc_description", "description")
            state_raw = self._first_of(rd, "service_state", "svc_state", "state")
            state = self._SERVICE_STATES.get(str(state_raw).strip().upper())
            if state is None:
                try:
                    state = int(state_raw)
                except (TypeError, ValueError):
                    state = None
            out.append(
                {
                    "id": f"{host_name}-{description}",
                    "title": description,
                    "extensions": {
                        **rd,
                        "host_name": host_name,
                        "description": description,
                        "state": state,
                        "state_text": str(state_raw),
                        "plugin_output": self._first_of(
                            rd, "svc_plugin_output", "service_plugin_output", "plugin_output", "output"
                        ),
                    },
                }
            )
        return out

    def _handle_get_services(self, params: Optional[Dict] = None) -> Dict[str, Any]:
        p = params or {}
        host = p.get("host_name") or p.get("host") or ""
        service = p.get("service_description") or p.get("description") or ""
        services = self._view_get_services(host, service, exact=bool(service))
        query = p.get("query")
        if query:
            services = [s for s in services if self._query_matches(query, s["extensions"])]
        return self._success({"value": services})

    def _handle_get_service(self, host: str, service: str) -> Dict[str, Any]:
        matches = self._view_get_services(host, service, exact=True)
        if not matches:
            raise CheckMKNotFoundError(f"Service '{service}' not found on host '{host}'")
        return self._success(matches[0])

    # 2.x REST discovery mode -> 1.6 webapi mode. "refresh" is deliberately
    # absent: in 2.x it only rescans, but 1.6's "refresh" is tabula rasa (drop
    # every service on the host and rediscover), and vibemk_start_service_discovery
    # defaults to "refresh". Passing it through would wipe services; the 1.6
    # tabula rasa is reachable only by asking for "tabula_rasa" explicitly.
    _DISCOVERY_MODES = {
        "new": "new",
        "remove": "remove",
        "fix_all": "fixall",
        "fixall": "fixall",
        "only_host_labels": "only-host-labels",
        "tabula_rasa": "refresh",
    }

    def _legacy_discovery_mode(self, mode: str) -> str:
        legacy_mode = self._DISCOVERY_MODES.get(mode)
        if legacy_mode is None:
            if mode == "refresh":
                raise CheckMKAPIError(
                    "Discovery mode 'refresh' is refused on CheckMK 1.6: there it means tabula rasa "
                    "(remove all services and rediscover), not the 2.x rescan. Use 'new', 'remove' or "
                    "'fix_all', or 'tabula_rasa' if a full rediscovery is really intended.",
                    400,
                    {},
                )
            raise CheckMKAPIError(
                f"Discovery mode '{mode}' is not available on CheckMK 1.6 "
                f"(supported: {', '.join(sorted(self._DISCOVERY_MODES))})",
                400,
                {},
            )
        return legacy_mode

    def _discover_host(self, host: str, mode: str) -> Dict[str, Any]:
        """Run one synchronous 1.6 discovery and remember its outcome."""
        if not host:
            raise CheckMKAPIError("host_name is required for service discovery", 400, {})
        legacy_mode = self._legacy_discovery_mode(mode)
        started = time.time()
        # webapi.py reads the mode from the URL variable, not the request
        # object; send it in both places so either implementation sees it.
        r = self._legacy_request(
            "discover_services", {"mode": legacy_mode}, request_object={"hostname": host, "mode": legacy_mode}
        )
        run = {
            "state": "finished",
            "host_name": host,
            "mode": mode,
            "result": r.get("result") or "",
            "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
            "duration": f"{time.time() - started:.1f}s",
        }
        self._discovery_runs[host] = run
        return run

    def _handle_discover_services(self, data: Optional[Dict]) -> Dict[str, Any]:
        d = data or {}
        run = self._discover_host(d.get("host_name", ""), d.get("mode", "new"))
        return self._success({"id": f"legacy-discovery-{run['host_name']}", "extensions": run})

    def _handle_bulk_discovery(self, data: Optional[Dict]) -> Dict[str, Any]:
        """Bulk discovery = one synchronous discovery per host on 1.6."""
        d = data or {}
        hosts = d.get("hostnames") or []
        if not hosts:
            raise CheckMKAPIError("hostnames is required for bulk discovery", 400, {})
        mode = d.get("mode")
        if not mode:
            opts = d.get("options") or {}
            add, remove = opts.get("monitor_undecided_services"), opts.get("remove_vanished_services")
            if add and remove:
                mode = "fix_all"
            elif add:
                mode = "new"
            elif remove:
                mode = "remove"
            elif opts.get("update_host_labels"):
                mode = "only_host_labels"
            else:
                raise CheckMKAPIError("Bulk discovery options select nothing to do", 400, {})
        self._legacy_discovery_mode(mode)  # refuse a bad mode before touching any host

        results: Dict[str, str] = {}
        failed: Dict[str, str] = {}
        for host in hosts:
            try:
                results[host] = self._discover_host(host, mode)["result"]
            except (CheckMKAuthenticationError, CheckMKPermissionError, CheckMKConnectionError):
                raise
            except CheckMKAPIError as e:
                failed[host] = str(e)
        if not results:
            raise CheckMKAPIError(
                "Bulk discovery failed on every host: " + "; ".join(f"{h}: {m}" for h, m in failed.items()),
                500,
                {},
            )

        job_id = f"legacy-bulk-{len(self._bulk_jobs) + 1}"
        self._bulk_jobs[job_id] = {
            "state": "finished",
            "mode": mode,
            "progress": {"total": len(hosts), "completed": len(results), "failed": len(failed)},
            "results": results,
            "failed_hosts": failed,
        }
        return self._success({"id": job_id, "job_id": job_id, "extensions": self._bulk_jobs[job_id]})

    def _handle_discovery_run_status(self, host: str) -> Dict[str, Any]:
        run = self._discovery_runs.get(host)
        if run is None:
            self._unsupported(
                f"No discovery of '{host}' was run in this session. CheckMK 1.6 discovery is synchronous, "
                "so there is no background job to query; the start call returns the result."
            )
        return self._success({"id": f"legacy-discovery-{host}", "extensions": {**run, "active": False}})

    def _handle_bulk_discovery_status(self, job_id: str) -> Dict[str, Any]:
        job = self._bulk_jobs.get(job_id)
        if job is None:
            raise CheckMKNotFoundError(f"Bulk discovery job '{job_id}' is unknown to this session")
        return self._success({"id": job_id, "extensions": job})

    def _handle_get_hosttags(self) -> Dict[str, Any]:
        r = self._legacy_request("get_hosttags")
        tag_groups = (r.get("result") or {}).get("tag_groups", [])
        value = [
            {"id": tg.get("id", ""), "title": tg.get("title", ""), "extensions": tg}
            for tg in tag_groups
        ]
        return self._success({"value": value})
