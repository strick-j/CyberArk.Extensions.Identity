using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.Reader;
using System.Text.RegularExpressions;
using System.Net.Http.Headers;
using System.Security;
using System.Text;

namespace CyberArk.Extensions.Identity
{
    public class Change : BaseAction
    {
        #region Consts
        public static readonly string USERNAME = "Username";
        public static readonly string ADDRESS = "Address";
        public static readonly string IDENAPPID = "IdentityAppId";
        public static readonly string IDENSCOPE = "IdentityScope";
        #endregion

        #region constructor
        /// <summary>
        /// Logon Ctor. Do not change anything unless you would like to initialize local class members
        /// The Ctor passes the logger module and the plug-in account's parameters to base.
        /// Do not change Ctor's definition not create another.
        /// <param name="accountList"></param>
        /// <param name="logger"></param>
        public Change(List<IAccount> accountList, ILogger logger)
            : base(accountList, logger)
        {
        }
        #endregion

        #region Setter
        /// <summary>
        /// Defines the Action name that the class is implementing - Change
        /// </summary>
        override public CPMAction ActionName
        {
            get { return CPMAction.changepass; }
        }
        #endregion

        /// <summary>
        /// Plug-in Starting point function.
        /// </summary>
        /// <param name="platformOutput"></param>
        override public int run(ref PlatformOutput platformOutput)
        {
            Logger.MethodStart();
            #region Init
            ErrorCodeStandards errCodeStandards = new ErrorCodeStandards();
            int RC = 9999;
            string action = "Password Change";
            string empty = string.Empty;
            #endregion 

            try
            {
                SetDefaultValues(errCodeStandards, ref empty);
                #region Fetch Account Properties (FileCategories)
                string username = ParametersAPI.GetMandatoryParameter(USERNAME, TargetAccount.AccountProp);
                ParametersAPI.ValidateParameterLength(username, "Username", 64);

                string address = ParametersAPI.GetMandatoryParameter(ADDRESS, TargetAccount.AccountProp);
                ParametersAPI.ValidateURI(address, "Address", UriKind.RelativeOrAbsolute);

                string identityScope = ParametersAPI.GetMandatoryParameter(IDENSCOPE, TargetAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityScope, "Identity Scope");

                string identityAppId = ParametersAPI.GetMandatoryParameter(IDENAPPID, TargetAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityAppId, "Identity Application Id");
                #endregion

                #region Fetch Account's Passwords
                SecureString secureCurrPass = TargetAccount.CurrentPassword;
                ParametersAPI.ValidatePasswordIsNotEmpty(secureCurrPass, "Password", 8201);
                SecureString secureNewPass = TargetAccount.NewPassword;
                ParametersAPI.ValidatePasswordIsNotEmpty(secureCurrPass, "Password", 8201);
                #endregion

                #region Logic
                // Logon and obatain Bearer Token
                // Create URL encoded content for POST
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("scope",$"{identityScope}"),
                });

                // Generate auth token for basic auth header
                var authToken = Encoding.ASCII.GetBytes($"{username}:{secureCurrPass.convertSecureStringToString()}");

                // Check URI for Scheme, add if not present
                UriBuilder adddressBuilder = new(address)
                {
                    Scheme = "https",
                    Port = -1
                };
                Uri validatedAddress = adddressBuilder.Uri;

                // Create HTTP client and set initial headers
                var client = new HttpClient
                {
                    BaseAddress = validatedAddress
                };
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(authToken));

                // Obtain Bearer Auth Token from Identity Server API
                var _client = new IdentityHttpClient(client);

                Logger.WriteLine(string.Format(Resources.SendActionRequest + "Bearer Token to {0}/Oauth2/Token/{1}", address, identityAppId), LogLevel.INFO);
                var tokenResponse = _client.GetAccessToken(identityAppId, content);
                if (tokenResponse.Failure)
                {
                    if (tokenResponse is HttpErrorResult<ApiResponse> httpErrorResult)
                        IdentityAPI.HandleHttpErrorResult(httpErrorResult);
                    else if (tokenResponse is HttpRequestExceptionResult<ApiResponse> httpRequestExcpetionResult)
                        IdentityAPI.HandleHttpRequestExceptionResult(httpRequestExcpetionResult.RequestException);
                    else if (tokenResponse is ErrorResult<ApiResponse> errorResult)
                        IdentityAPI.HandleErrorResult(errorResult);
                    else
                        tokenResponse.MissingPatternMatch();
                }
                else if (tokenResponse.Success)
                {
                    Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseSuccess), LogLevel.INFO);
                }
                _client.Dispose();

                // Use Regular Expression to extract Access Token from response
                Logger.WriteLine(string.Format("Extracting Bearer Token from {0}/Oauth2/Token/{1} response.", address, identityAppId), LogLevel.INFO);
                var accessToken = Regex.Match(tokenResponse.Data.Details, "(?<=access_token\":\")(.+?)(?=\")").Groups[1].Value;
                IdentityAPI.ValidateRegexExtraction(accessToken, "access_Token");
                Logger.WriteLine(Resources.TokenSuccess, LogLevel.INFO);

                // Establish new Client to use Bearer Token Authorization Header
                var changeClient = new HttpClient
                {
                    BaseAddress = validatedAddress
                };
                Logger.WriteLine(Resources.UpdateAuthenticationHeader, LogLevel.INFO);
                changeClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var _updatedClient = new IdentityHttpClient(changeClient);
                Logger.WriteLine(string.Format(Resources.SendActionRequest + action), LogLevel.INFO);

                // Create Request Content for changing user password
                string userChangeData = @"{'oldPassword':'" + Utils.CleanForJSON(secureCurrPass.convertSecureStringToString()) + "','newPassword':'" + Utils.CleanForJSON(secureNewPass.convertSecureStringToString()) + "'}";
                var userChangeContent = new StringContent(userChangeData, Encoding.UTF8, "application/json");

                var apiResponse = _updatedClient.ChangePassword(userChangeContent);
                if (apiResponse.Failure)
                {
                    if (apiResponse is HttpErrorResult<ApiResponse> httpErrorResult)
                        IdentityAPI.HandleHttpErrorResult(httpErrorResult);
                    else if (apiResponse is HttpRequestExceptionResult<ApiResponse> httpRequestExcpetionResult)
                        IdentityAPI.HandleHttpRequestExceptionResult(httpRequestExcpetionResult.RequestException);
                    else if (apiResponse is ErrorResult<ApiResponse> errorResult)
                        IdentityAPI.HandleErrorResult(errorResult);
                    else
                        apiResponse.MissingPatternMatch();
                }
                else if (apiResponse is SuccessResult<ApiResponse> successResult)
                {
                    Logger.WriteLine(string.Format(action + Resources.RecieveActionResponse), LogLevel.INFO);
                    IdentityAPI.HandleSuccessResult(successResult);
                    Logger.WriteLine(string.Format(action + Resources.ActionResponseSuccess), LogLevel.INFO);
                }
                _updatedClient.Dispose();

                // Change Password action complete set outputs and dispose client
                Logger.WriteLine(Resources.ChangeSuccess, LogLevel.INFO);
                platformOutput.Message = Resources.ChangeSuccess;
                RC = 0;
                #endregion Logic

            }
            catch (ParametersConfigurationException ex)
            {
                Logger.WriteLine(string.Format("Recieved exception: {0}", ex.ToString()));
                platformOutput.Message = ex.Message;
                RC = ex.ErrorCode;
            }
            catch (IdentityServiceException ex)
            {
                Logger.WriteLine(string.Format("Recieved exception: {0}", ex.Message), LogLevel.ERROR);
                platformOutput.Message = ex.Message;
                RC = ex.ErrorCode;
            }
            catch (HttpRequestException ex)
            {
                Logger.WriteLine(string.Format(Resources.HttpRequestException), LogLevel.ERROR);
                Logger.WriteLine(string.Format("Recieved exception: {0}", ex.ToString()), LogLevel.ERROR);
                platformOutput.Message = Resources.HttpRequestException;
                RC = PluginErrors.HTTP_GENERIC_EXCEPTION;
            }
            catch (Exception ex)
            {
                RC = HandleGeneralError(ex, ref platformOutput);
            }
            finally
            {
                Logger.MethodEnd();
            }

            return RC;

        }
    }
}