"""FortiADC REST <-> CLI field renames, MEASURED per build on lab boxes (data).

FortiADC's REST names many CLI attributes outright differently (REST ``pool``
= CLI ``load-balance-pool``, ``recurision_status`` = ``recursion-status``),
which no spelling rule derives (``fortiadc.field_twins`` only joins ``_`` for
``-`` and ``mkey``). Without this map a CLI field REST does not name on an
object REST read stays ``unknown`` ("unverified on this build" under Not in
GUI) even though REST serves it under its own name.

How each pair was measured (2026-10-14, read-only: one REST ``GET`` per object
and one ``show full-configuration`` over SSH per box; only field names and
salted value hashes left the run, never a value):

* candidates: on one object REST read with its fields, a CLI field the
  channel join left ``unknown`` x a REST field it left ``rest_only``;
* REST row and CLI block paired by ``mkey`` = ``edit`` name (a singleton: its
  one row); a pair is kept only if the two values are EQUAL on every row
  where both are printed (lists compared as sorted tokens) and on >= 1 row;
* and the evidence carries it: an informative equal value (not empty,
  ``enable``/``disable``, ``0``/``1``) with related names (similarity >= 0.5
  or a shared word), or names similar >= 0.8; a table seen on ONE row needs
  names similar >= 0.8, and with only uninformative values >= 2 rows;
* and it is unique: neither name has another candidate that passes, nor
  another informative value-equal partner. Where several fields share one
  value (``security_waf_http_protocol_constraint``'s ``*-action`` /
  ``*-severity``, ``global_load_balance_setting``'s mask lengths) nothing is
  joined: those stay ``unknown`` until rows with distinct values exist.

Calibration of the value test on the same runs: fields the join already
reads ``both`` compared equal on 3 141 of 3 144 row pairs on 7.6.7 (the 3:
two encrypted secrets and one escaped message buffer).

A build not listed has no map: nothing is carried over from another build
(both boxes agree on every pair they share, but a build is measured or it is
not). ``{build: {REST channel key: {REST field: CLI field}}}``.
"""
from __future__ import annotations

#: Where each build's map was measured.
MEASURED_ON = {
    "7.6.7": {"device": "fortiadc10 (lab)", "build": "7.6.7 build0676", "date": "2026-10-14",
              "objects": 116, "row_pairs": 809},
    "8.0.4": {"device": "fortiadc11 (lab)", "build": "8.0.4 build0136", "date": "2026-10-14",
              "objects": 96, "row_pairs": 671},
}

FIELD_RENAMES: dict = {
    "7.6.7": {
        "global_dns_server_general": {
            "recurision_status": "recursion-status",
            "response_ratelimit": "response-rate-limit",
        },
        "global_dns_server_zone": {"responible_mail": "responsible-mail"},
        "global_load_balance_servers": {"user-defined-cert": "user-defined-certificate"},
        "global_load_balance_setting": {
            "listen-on-interface-all": "listen-on-all-interface",
            "user-defined-cert": "user-defined-certificate",
        },
        "load_balance_captcha_profile": {
            "max_retry_times": "max-attempts",
            "pic_difficulty": "picture-difficulty",
        },
        "load_balance_client_ssl_profile": {
            "client_certificate_verify_mode": "client-certificate-verify-option",
            "customized_ssl_ciphers_flag": "ssl-customize-ciphers-flag",
            "ssl_renegotiation": "renegotiation",
        },
        "load_balance_content_routing": {
            "method": "load-balance-method",
            "persistence": "load-balance-persistence",
            "pool": "load-balance-pool",
        },
        "load_balance_geoip_list": {"action": "default-action"},
        "load_balance_http2_profile": {
            "backend_concurrent_stream": "backend-http2-max-concurrent-stream",
            "backend_max_receive_window": "backend-http2-max-receive-window",
            "backend_multiplex_mode": "backend-multiplexing-mode",
            "backend_proto_mode_http": "backend-http2-protocol-mode-http",
            "backend_proto_mode_https": "backend-http2-protocol-mode-https",
        },
        "load_balance_http3_profile": {"backend_multiplex_mode": "backend-multiplexing-mode"},
        "load_balance_pool": {
            "health_check": "health-check-ctrl",
            "health_check_action": "health-check-down-action",
            "health_check_relationship": "health-check-relation",
            "pool_type": "addr-type",
            "rs_profile": "real-server-ssl-profile",
        },
        "load_balance_profile": {
            "dns_cache_response_type": "cache-response-type",
            "media_address": "media-addr",
            "sip_max_size": "max-size",
            "smtp_disable_command": "disable-command",
            "smtp_domain_name": "domain-name",
        },
        "load_balance_real_server_ssl_profile": {
            "ciphers_tlsv13": "ssl-ciphers-tlsv13",
            "customized_ssl_ciphers": "ssl-customized-ciphers",
            "customized_ssl_ciphers_flag": "ssl-customize-ciphers-flag",
            "new_ssl_ciphers_long": "ssl-ciphers",
        },
        "load_balance_schedule_pool": {"pool": "load-balance-pool"},
        "load_balance_virtual_server": {
            "method": "load-balance-method",
            "one-click-gslb-server": "one-click-gslb-server-option",
            "packet-fwd-method": "packet-forwarding-method",
            "persistence": "load-balance-persistence",
            "pool": "load-balance-pool",
            "profile": "load-balance-profile",
            "source-pool-list": "ippool-list",
            "warmrate": "warm-rate",
            "warmup": "warm-up",
        },
        "log_setting_global_remote": {
            "addr_type": "address_type",
            "attack_category": "attack-log-category",
            "event_category": "event-log-category",
        },
        "log_setting_local": {"event_category": "event-log-category"},
        "router_static": {"dest": "destination"},
        "security_dos_ip_fragmentation_protection": {
            "memory_max_size": "max-memory-size",
            "memory_min_size": "min-memory-size",
            "timeout": "time",
        },
        "security_dos_tcp_synflood_protection": {"halfopen_num": "max-half-open"},
        "security_waf_action": {"action_type": "type", "comments": "comment"},
        "security_waf_adaptive_learning": {"least_time": "least-learning-time"},
        "security_waf_heuristic_sql_xss_injection_detection": {
            "refer_sql_injection_detection": "referer-sql-injection-detection",
        },
        "security_waf_http_protocol_constraint": {
            "illegal_host_name": "illegal-host-name-check",
            "illegal_http_version": "illegal-http-version-check",
            "max_body_length": "max-request-body-length",
            "max_cookie_number": "max-cookie-number-in-request",
            "max_header_length": "max-request-header-length",
            "max_header_number": "max-header-number-in-request",
        },
        "security_waf_json_validation_detection": {
            "exception_id": "exception",
            "json_format_checks": "format-checks",
            "json_limit_checks": "limit-checks",
            "json_schema_checks": "schema-checks",
            "json_sql_injection_checks": "sql-injection-checks",
            "json_xss_checks": "xss-checks",
            "limit_max_array_value": "limit-max-array-value-num",
            "limit_max_depth": "limit-max-depth-num",
        },
        "security_waf_profile": {
            "bot_detection_name": "bot-detection",
            "brute_force_login_name": "brute-force-login",
            "data_leak_prevention_name": "data-leak-prevention",
            "desc": "description",
            "heuristic_sql_xss_injection_detection": "heuristic-sql-xss-injection-detect",
            "http_header_security_name": "http-header-security",
            "input_validation_policy_name": "input-validation-policy",
            "json_validation_name": "json-validation",
            "openapi_validation_name": "openapi-validation",
            "xml_validation_name": "xml-validation",
        },
        "security_waf_sensitive_data_type": {"desc": "description"},
        "security_waf_xml_validation_detection": {
            "exception_id": "exception",
            "limit_max_elem_child": "limit-max-elem-child-num",
            "limit_max_namespace": "limit-max-namespace-num",
            "xml_format_checks": "format-checks",
            "xml_limit_checks": "limit-checks",
            "xml_schema_checks": "schema-checks",
            "xml_sql_injection_checks": "sql-injection-checks",
            "xml_xss_checks": "xss-checks",
        },
        "system_admin": {"trusted-host": "trusted-hosts"},
        "system_alert": {"event_gid": "event", "source_type": "alert-source-type"},
        "system_alert_policy": {"use_rolling_win": "use-rolling-window"},
        "system_csf": {"mgmt_port": "management-port"},
        "system_dns": {"ip_primary": "primary", "ip_second": "secondary"},
        "system_global": {
            "adv_bot_status": "advanced-bot-status",
            "gui-device-longtitude": "gui-device-longitude",
            "http-port": "port-http",
            "https-port": "port-https",
            "ssh-port": "port-ssh",
            "sys-global-language": "language",
            "telnet-port": "port-telnet",
        },
        "system_ha": {
            "arp_interval": "arps-interval",
            "groupid": "group-id",
            "hbtype": "hb-type",
            "interval": "hb-interval",
        },
        "system_health_check": {"allow-ssl-version": "allow-ssl-versions", "down_retry": "retry"},
        "system_interface": {"dedicate-to-management": "dedicate-to-mgmt"},
        "system_one_click_glb_server": {"auto-update-interval": "interval"},
        "user_ldap": {"cn_id": "cnid"},
        "user_local": {"two_fa_support": "2fa-support"},
    },
    "8.0.4": {
        "global_dns_server_general": {"recurision_status": "recursion-status"},
        "global_dns_server_security": {"response_ratelimit": "response-rate-limit"},
        "global_load_balance_setting": {
            "listen-on-interface-all": "listen-on-all-interface",
            "user-defined-cert": "user-defined-certificate",
        },
        "load_balance_captcha_profile": {"pic_difficulty": "picture-difficulty"},
        "load_balance_client_ssl_profile": {
            "customized_ssl_ciphers_flag": "ssl-customize-ciphers-flag",
            "ssl_renegotiation": "renegotiation",
        },
        "load_balance_http2_profile": {
            "backend_concurrent_stream": "backend-http2-max-concurrent-stream",
            "backend_max_receive_window": "backend-http2-max-receive-window",
            "backend_multiplex_mode": "backend-multiplexing-mode",
            "backend_proto_mode_http": "backend-http2-protocol-mode-http",
            "backend_proto_mode_https": "backend-http2-protocol-mode-https",
        },
        "load_balance_http3_profile": {"backend_multiplex_mode": "backend-multiplexing-mode"},
        "load_balance_profile": {
            "dns_cache_response_type": "cache-response-type",
            "media_address": "media-addr",
            "sip_max_size": "max-size",
            "smtp_disable_command": "disable-command",
            "smtp_domain_name": "domain-name",
        },
        "load_balance_real_server_ssl_profile": {
            "customized_ssl_ciphers_flag": "ssl-customize-ciphers-flag",
            "new_ssl_ciphers_long": "ssl-ciphers",
        },
        "log_setting_local": {"event_category": "event-log-category"},
        "security_dos_ip_fragmentation_protection": {
            "memory_max_size": "max-memory-size",
            "memory_min_size": "min-memory-size",
            "timeout": "time",
        },
        "security_dos_tcp_synflood_protection": {"halfopen_num": "max-half-open"},
        "security_waf_action": {"action_type": "type", "comments": "comment"},
        "security_waf_adaptive_learning": {"least_time": "least-learning-time"},
        "security_waf_heuristic_sql_xss_injection_detection": {
            "refer_sql_injection_detection": "referer-sql-injection-detection",
        },
        "security_waf_http_protocol_constraint": {
            "illegal_host_name": "illegal-host-name-check",
            "illegal_http_version": "illegal-http-version-check",
            "max_body_length": "max-request-body-length",
            "max_cookie_number": "max-cookie-number-in-request",
            "max_header_length": "max-request-header-length",
            "max_header_number": "max-header-number-in-request",
        },
        "security_waf_json_validation_detection": {
            "exception_id": "exception",
            "json_format_checks": "format-checks",
            "json_limit_checks": "limit-checks",
            "json_schema_checks": "schema-checks",
            "json_sql_injection_checks": "sql-injection-checks",
            "json_xss_checks": "xss-checks",
            "limit_max_array_value": "limit-max-array-value-num",
            "limit_max_depth": "limit-max-depth-num",
        },
        "security_waf_profile": {
            "bot_detection_name": "bot-detection",
            "brute_force_login_name": "brute-force-login",
            "data_leak_prevention_name": "data-leak-prevention",
            "heuristic_sql_xss_injection_detection": "heuristic-sql-xss-injection-detect",
            "http_header_security_name": "http-header-security",
            "input_validation_policy_name": "input-validation-policy",
            "json_validation_name": "json-validation",
            "openapi_validation_name": "openapi-validation",
            "xml_validation_name": "xml-validation",
        },
        "security_waf_sensitive_data_type": {"desc": "description"},
        "security_waf_xml_validation_detection": {
            "exception_id": "exception",
            "limit_max_elem_child": "limit-max-elem-child-num",
            "limit_max_namespace": "limit-max-namespace-num",
            "xml_format_checks": "format-checks",
            "xml_limit_checks": "limit-checks",
            "xml_schema_checks": "schema-checks",
            "xml_sql_injection_checks": "sql-injection-checks",
            "xml_xss_checks": "xss-checks",
        },
        "system_admin": {"trusted-host": "trusted-hosts"},
        "system_alert": {"event_gid": "event", "source_type": "alert-source-type"},
        "system_alert_policy": {"use_rolling_win": "use-rolling-window"},
        "system_csf": {"mgmt_port": "management-port", "sync_mode": "configuration-sync"},
        "system_dns": {"ip_primary": "primary", "ip_second": "secondary"},
        "system_global": {
            "adv_bot_status": "advanced-bot-status",
            "gui-device-longtitude": "gui-device-longitude",
            "http-port": "port-http",
            "https-port": "port-https",
            "ssh-port": "port-ssh",
            "sys-global-language": "language",
            "telnet-port": "port-telnet",
        },
        "system_ha": {
            "arp_interval": "arps-interval",
            "groupid": "group-id",
            "hbtype": "hb-type",
            "interval": "hb-interval",
        },
        "system_health_check": {"allow-ssl-version": "allow-ssl-versions", "down_retry": "retry"},
        "system_one_click_glb_server": {"auto-update-interval": "interval"},
        "system_saml": {
            "idp_logout_url": "idp-single-logout-url",
            "server_addr": "server-address",
        },
    },
}


def renames_for(version: str, key: str) -> dict:
    """``{REST field: CLI field}`` measured for one object on one build, or ``{}``."""
    return dict((FIELD_RENAMES.get(str(version or "")) or {}).get(key or "") or {})


__all__ = ["MEASURED_ON", "FIELD_RENAMES", "renames_for"]
