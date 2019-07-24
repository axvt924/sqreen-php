/* sqreen extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/url.h"
#include "php_sqreen.h"
#include "libinjection/libinjection.h"

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

/* {{{ void sqreen_sqli(data)
 */
static ZEND_RESULT_CODE sqreen_sqli(zval *data)
{
    char fingerprint[8];
    if (data && Z_TYPE_P(data) == IS_STRING) {
        Z_STRLEN_P(data) = php_url_decode(Z_STRVAL_P(data), Z_STRLEN_P(data));
        // If res = 1 we found a SQLi
        if (libinjection_sqli(Z_STRVAL_P(data), Z_STRLEN_P(data), fingerprint) == 1) {
            return FAILURE;
        }
    }

    return SUCCESS;
}

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(sqreen)
{

#if defined(ZTS) && defined(COMPILE_DL_SQREEN)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	zval *data = NULL;
	zval *value = NULL;

    // Retrieve SERVER infos
	if (zend_is_auto_global_str("_SERVER", sizeof("_SERVER") - 1) == 1) {
        // Retrieve REQUEST_URI
        if ((data = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]),
                        "REQUEST_URI", sizeof("REQUEST_URI") - 1))) {
            if (sqreen_sqli(data) < 0) {
                return FAILURE;
            }
        }

        // Retrieve METHOD
        if ((data = zend_hash_str_find(Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]),
                        "REQUEST_METHOD", sizeof("REQUEST_METHOD") - 1))) {
            if (Z_TYPE_P(data) == IS_STRING) {
                if (strncasecmp(Z_STRVAL_P(data), "GET", sizeof("GET") -1) == 0) {
                    // Retrieve GET infos
                    if (zend_is_auto_global_str("_GET", sizeof("_GET") - 1) == 1) {
                        ZEND_HASH_FOREACH_VAL(Z_ARRVAL(PG(http_globals)[TRACK_VARS_GET]), value) {
                            if (sqreen_sqli(value) < 0) {
                                return FAILURE;
                            }
                        } ZEND_HASH_FOREACH_END();
                    }

                } else if (strncasecmp(Z_STRVAL_P(data), "POST", sizeof("POST") -1) == 0) {
                    // Retrieve POST infos
                    if (zend_is_auto_global_str("_POST", sizeof("_POST") - 1) == 1) {
                        ZEND_HASH_FOREACH_VAL(Z_ARRVAL(PG(http_globals)[TRACK_VARS_POST]), value) {
                            if (sqreen_sqli(value) < 0) {
                                return FAILURE;
                            }
                        } ZEND_HASH_FOREACH_END();
                    }
                }
            }
        }
    }

    // Retrieve COOKIE infos
    if (zend_is_auto_global_str("_COOKIE", sizeof("_COOKIE") - 1) == 1) {
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL(PG(http_globals)[TRACK_VARS_COOKIE]), value) {
            if (sqreen_sqli(value) < 0) {
                return FAILURE;
            }
        } ZEND_HASH_FOREACH_END();
    }

	return SUCCESS;
}

/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(sqreen)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "sqreen support", "enabled");
	php_info_print_table_end();
}
/* }}} */

/* {{{ arginfo
 */

/* }}} */

/* {{{ sqreen_functions[]
 */
/* }}} */

/* {{{ sqreen_module_entry
 */
zend_module_entry sqreen_module_entry = {
	STANDARD_MODULE_HEADER,
	"sqreen",					/* Extension name */
	NULL,           			/* zend_function_entry */
	NULL,						/* PHP_MINIT - Module initialization */
	NULL,						/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(sqreen),			/* PHP_RINIT - Request initialization */
	NULL,						/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(sqreen),			/* PHP_MINFO - Module info */
	PHP_SQREEN_VERSION,		    /* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SQREEN
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(sqreen)
#endif
