using CyberArk.Extensions.Utilties.Logger;
using System.Net;

namespace CyberArk.Extensions.Identity
{
    public class IdentityServiceManager
    {
        public void ValidateRegexExtraction(string regexData, string regexValue)
        {
            Logger.MethodStart();
            if (string.IsNullOrEmpty(regexData))
            {
                switch (regexValue)
                {
                    case "access_token":
                        throw new IdentityServiceException(string.Format(Resources.TokenError), PluginErrors.REGEX_TOKEN_ERROR);
                    case "uuid":
                        throw new IdentityServiceException(string.Format(Resources.UuidError), PluginErrors.REGEX_UUID_ERROR);
                }
            }
            Logger.MethodEnd();
        }

        public void HandleHttpErrorResult(HttpErrorResult<ApiResponse> httpErrorResult)
        {
            // Check 400 Bad Request Status Code
            if (httpErrorResult.StatusCode == HttpStatusCode.BadRequest)
            {
                // Check for various reasons 400 Bad Request may be returned
                Logger.WriteLine(Resources.BadRequestRecieved, LogLevel.ERROR);
                if (httpErrorResult.Message.Contains("invalid client creds or client not allowed"))
                    throw new IdentityServiceException(string.Format(Resources.InvalidClientOrCreds), PluginErrors.BAD_REQUEST_CLIENT_OR_CREDS);
                else if (httpErrorResult.Message.Contains("unknown app"))
                    throw new IdentityServiceException(string.Format(Resources.InvalidApp), PluginErrors.BAD_REQUEST_APP);
                else if (httpErrorResult.Message.Contains("unknown scope requested"))
                    throw new IdentityServiceException(string.Format(Resources.InvalidScope), PluginErrors.BAD_REQUEST_SCOPE);
                else if (httpErrorResult.Message.Contains("invalid grant type"))
                    throw new IdentityServiceException(string.Format(Resources.InvalidGrantType), PluginErrors.BAD_REQUEST_GRANT_TYPE);
                else if (httpErrorResult.Message.Contains("user not allowed access to app"))
                    throw new IdentityServiceException(string.Format(Resources.InvalidUserAccess), PluginErrors.BAD_REQUEST_USER_ACCESS);
                else if (httpErrorResult.Message.Contains("auth mode not allowed"))
                    throw new IdentityServiceException(string.Format(Resources.InvalidAuthMode), PluginErrors.BAD_REQUEST_AUTH_MODE);
                else
                    throw new IdentityServiceException(string.Format("Bad Request: {0}", httpErrorResult.Message), PluginErrors.BAD_REQUEST_UNHANDLED);
            };

            // Check other common Status Codes
            throw httpErrorResult.StatusCode switch
            {
                HttpStatusCode.Unauthorized => new IdentityServiceException("Status Code 401 - Unauthorized", PluginErrors.STATUS_CODE_UNAUTHORIZED),
                HttpStatusCode.Forbidden => new IdentityServiceException("Status Code 403 - Forbidden", PluginErrors.STATUS_CODE_FORBIDDEN),
                HttpStatusCode.NotFound => new IdentityServiceException("Status Code 404 - Not Found", PluginErrors.STATUS_CODE_NOT_FOUND),
                HttpStatusCode.ProxyAuthenticationRequired => new IdentityServiceException("Status Code 407 - Proxy Authentication Required", PluginErrors.STATUS_CODE_PROXY_AUTH),
                HttpStatusCode.RequestTimeout => new IdentityServiceException("Status Code 408 - Request Timeout", PluginErrors.STATUS_CODE_REQ_TIMEOUT),
                HttpStatusCode.GatewayTimeout => new IdentityServiceException("Status Code 504 - Gateway Timeout", PluginErrors.STATUS_CODE_GW_TIMEOUT),
                _ => new IdentityServiceException(Resources.GenericError, PluginErrors.STANDARD_DEFUALT_ERROR_CODE_IDX),
            };
        }

        public void HandleHttpRequestExceptionResult(HttpRequestException ex)
        {
            if (ex.GetBaseException() is WebException webException)
            {
                throw webException.Status switch
                {
                    WebExceptionStatus.NameResolutionFailure => new IdentityServiceException(string.Format(Resources.HttpNameResolutionFailure), PluginErrors.HTTP_NAME_RESOLUTION_FAILURE),
                    WebExceptionStatus.ConnectFailure => new IdentityServiceException(string.Format(Resources.HttpConnectFailure), PluginErrors.HTTP_CONNECT_FAILURE),
                    WebExceptionStatus.SecureChannelFailure => new IdentityServiceException(string.Format(Resources.HttpSecureChannelError), PluginErrors.HTTP_SSL_TLS_EXCEPTION),
                    _ => new IdentityServiceException(string.Format(Resources.HttpUnhandledInnerWebException + "{0}", webException.Message), PluginErrors.HTTP_INNER_WEB_UNHANDLED),
                };
            }
            else
            {
                throw new IdentityServiceException(string.Format(Resources.HttpUnhandledInnerException + "{0}", ex.InnerException.Message), PluginErrors.HTTP_INNER_UNHANDLED);
            }

            throw new IdentityServiceException(string.Format(Resources.HttpGeneralRequestError + "{0}", ex.InnerException.Message), PluginErrors.HTTP_GENERIC_EXCEPTION);
        }

        public void HandleErrorResult(ErrorResult<ApiResponse> errorResult)
        {
            throw new IdentityServiceException(string.Format(Resources.GenericError + "{0}", errorResult.Data.Details), PluginErrors.DEFAULT_ERROR_NUMBER);
        }

        public void HandleSuccessResult(SuccessResult<ApiResponse> successResult)
        {
            Logger.MethodStart();
            if (successResult.Data.Details.Contains("\"success\":false"))
            {
                Logger.WriteLine("Identity server returned status code 200 but action was not successful. Checking error...", LogLevel.ERROR);
                if (successResult.Data.Details.Contains("_I18N_UserNotFound"))
                    throw new IdentityServiceException(string.Format(Resources.UserNotFound), PluginErrors.SUCCESS_USER_NOT_FOUND);
                else if (successResult.Data.Details.Contains("_I18N_UserIDNotFound"))
                    throw new IdentityServiceException(string.Format(Resources.UserIdNotFound), PluginErrors.SUCCESS_USER_ID_NOT_FOUND);
                else if (successResult.Data.Details.Contains("_I18N_System.UnauthorizedAccessException"))
                    throw new IdentityServiceException(string.Format(Resources.UserNotAuthorized), PluginErrors.SUCCESS_USER_NOT_AUTHORIZED);
                else if (successResult.Data.Details.Contains("_I18N_ServiceUnauthorizedAccess"))
                    throw new IdentityServiceException(string.Format(Resources.ServiceNotAuthorized), PluginErrors.SUCCESS_SERVICE_NOT_AUTHORIZED);
                else if (successResult.Data.Details.Contains("_I18N_SetPasswordFailedNotComplex"))
                    throw new IdentityServiceException(string.Format(Resources.PasswordComplexity), PluginErrors.SUCCESS_INVALID_PASSWORD_COMPLEXITY);
                else if (successResult.Data.Details.Contains("_I18N_SetPasswordFailedNewSameAsOld"))
                    throw new IdentityServiceException(string.Format(Resources.PasswordSameAsOld), PluginErrors.SUCCESS_PASSWORD_SAME_AS_OLD);
                else if (successResult.Data.Details.Contains("_I18N_SetPasswordFailedSameAsLastN"))
                    throw new IdentityServiceException(string.Format(Resources.PasswordLastN), PluginErrors.SUCCESS_PASSWORD_LAST_N);
                else if (successResult.Data.Details.Contains("_I18N_Newtonsoft.Json.JsonReaderException"))
                    throw new IdentityServiceException(string.Format(Resources.PasswordJsonRead), PluginErrors.SUCCESS_JSON_EXCEPTION);
                else
                    throw new IdentityServiceException(string.Format("Unhandled Error: {0}", successResult.Data.Details), PluginErrors.SUCCESS_DEFAULT_ERROR);
            }
            Logger.MethodEnd();
        }
    }
}
