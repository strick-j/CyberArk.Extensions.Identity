namespace CyberArk.Extensions.Identity
{

    /*
     * Plug-in Errors class should contain common error numbers and messages for all operations.
     * Specific action error messages should implemented in the action class itself 
     */
    public static class PluginErrors
    {
        // STANDARD_DEFUALT_ERROR_CODE_IDX --> index for standard error code.
        public static readonly int STANDARD_DEFUALT_ERROR_CODE_IDX = 9999;

        public static readonly int NO_SUCH_ENTITY_ERROR_NUMBER = 8800;
        public static readonly int MANDATORY_PARAMETER_MISSING = 8801;
        public static readonly int REGEX_TOKEN_ERROR = 8802;
        public static readonly int REGEX_UUID_ERROR = 8803;
        public static readonly int RESPONSE_CONTENT_NULL = 8804;
        public static readonly int RESPONSE_GENERIC_EXCEPTION = 8505;
        public static readonly int RESPONSE_TIMEOUT_EXCEPTION = 8506;

        // SUCCESS_ERROR --> Errors when 200 Success is returned but the action failed.
        public static readonly int SUCCESS_DEFAULT_ERROR = 8810;
        public static readonly int SUCCESS_USER_NOT_FOUND = 8811;
        public static readonly int SUCCESS_USER_ID_NOT_FOUND = 8812;
        public static readonly int SUCCESS_USER_NOT_AUTHORIZED = 8813;
        public static readonly int SUCCESS_SERVICE_NOT_AUTHORIZED = 8814;
        public static readonly int SUCCESS_INVALID_PASSWORD_COMPLEXITY = 8815;
        public static readonly int SUCCESS_PASSWORD_SAME_AS_OLD = 8816;
        public static readonly int SUCCESS_PASSWORD_LAST_N = 8817;
        public static readonly int SUCCESS_JSON_EXCEPTION = 8818;

        // BAD_REQUEST_ERRORS --> Errors returned with 400 Bad Request Response.
        public static readonly int BAD_REQUEST_NULL_RESPONSE = 8820;
        public static readonly int BAD_REQUEST_UNHANDLED = 8821;
        public static readonly int BAD_REQUEST_CLIENT_OR_CREDS = 8822;
        public static readonly int BAD_REQUEST_SCOPE = 8823;
        public static readonly int BAD_REQUEST_APP = 8824;
        public static readonly int BAD_REQUEST_AUTH_MODE = 8825;
        public static readonly int BAD_REQUEST_GRANT_TYPE = 8826;
        public static readonly int BAD_REQUEST_USER_ACCESS = 8827;

        // STATUS_CODE_ERROS --> Errors related to non success status code.
        public static readonly int STATUS_CODE_UNAUTHORIZED = 8830;
        public static readonly int STATUS_CODE_NOT_FOUND = 8831;
        public static readonly int STATUS_CODE_REQ_TIMEOUT = 8832;
        public static readonly int STATUS_CODE_GW_TIMEOUT = 8833;
        public static readonly int STATUS_CODE_PROXY_AUTH = 8834;
        public static readonly int STATUS_CODE_FORBIDDEN = 8835;
        public static readonly int STATUS_CODE_UNHANDLED = 8836;

        // HTTP_ERRORS --> Errors received with HTTP Transport, no response recieved.
        public static readonly int HTTP_GENERIC_EXCEPTION = 8840;
        public static readonly int HTTP_NAME_RESOLUTION_FAILURE = 8841;
        public static readonly int HTTP_CONNECT_FAILURE = 8842;
        public static readonly int HTTP_INNER_WEB_UNHANDLED = 8843;
        public static readonly int HTTP_INNER_UNHANDLED = 8844;
        public static readonly int HTTP_SSL_TLS_EXCEPTION = 8845;

        

        public static readonly int DEFAULT_ERROR_NUMBER = -1;
    }
}
