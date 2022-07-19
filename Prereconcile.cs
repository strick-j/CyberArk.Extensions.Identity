using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.Reader;
using System.Net.Http.Headers;
using System.Security;
using System.Text;

namespace CyberArk.Extensions.Identity
{
    public class Prereconcile : BaseAction
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
        public Prereconcile(List<IAccount> accountList, ILogger logger)
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
            get { return CPMAction.prereconcilepass; }
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
            string empty = string.Empty;
            #endregion 

            try
            {
                SetDefaultValues(errCodeStandards, ref empty);
                #region Fetch Account Properties (FileCategories)
                string username = ParametersAPI.GetMandatoryParameter(USERNAME, TargetAccount.AccountProp);
                ParametersAPI.ValidateParameterLength(username, "Username", 64);

                string reconcileUsername = ParametersAPI.GetMandatoryParameter(USERNAME, ReconcileAccount.AccountProp);
                ParametersAPI.ValidateParameterLength(reconcileUsername, "Username", 64);

                string address = ParametersAPI.GetMandatoryParameter(ADDRESS, TargetAccount.AccountProp);
                ParametersAPI.ValidateURI(address, "Address", UriKind.RelativeOrAbsolute);

                string identityScope = ParametersAPI.GetMandatoryParameter(IDENSCOPE, ReconcileAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityScope, "Identity Scope");

                string identityAppId = ParametersAPI.GetMandatoryParameter(IDENAPPID, ReconcileAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityAppId, "Identity Application Id");
                #endregion

                #region Fetch Account's Passwords
                SecureString secureRecPass = TargetAccount.CurrentPassword;
                ParametersAPI.ValidatePasswordIsNotEmpty(secureRecPass, "Reconcile Password", 8201);
                SecureString secureNewPass = TargetAccount.CurrentPassword;
                ParametersAPI.ValidatePasswordIsNotEmpty(secureNewPass, "Password", 8201);
                string reconcilePassword = ReconcileAccount.CurrentPassword.convertSecureStringToString();
                string newPassword = TargetAccount.NewPassword.convertSecureStringToString();
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
                var authToken = Encoding.ASCII.GetBytes($"{reconcileUsername}:{reconcilePassword}");

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

                Logger.WriteLine(Resources.PrereconcileSuccess, LogLevel.INFO);
                RC = 0;
                #endregion Logic

            }
            catch (ParametersConfigurationException ex)
            {
                Logger.WriteLine(string.Format("Recieved exception: {0}", ex.Message), LogLevel.ERROR);
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
                Logger.WriteLine(string.Format("Recieved exception: {0}", ex.Message), LogLevel.ERROR);
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
