using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.Reader;
using CyberArk.Extensions.Plugin.RestAPI;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace CyberArk.Extensions.Identity
{
    public class Reconcile : BaseAction
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
        public Reconcile(List<IAccount> accountList, ILogger logger)
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
            get { return CPMAction.reconcilepass; }
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
            string action = "Password Reconcile";
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
                SecureString secureRecPass = ReconcileAccount.CurrentPassword;
                ParametersAPI.ValidatePasswordIsNotEmpty(secureRecPass, "Reconcile Password", 8201);
                SecureString secureNewPass = TargetAccount.NewPassword;
                #endregion

                #region Logic
                // Check Identity Address URI for Scheme, add scheme if not present and convert to string
                UriBuilder addressBuilder = new(address)
                {
                    Scheme = "https",
                    Port = -1
                };
                Uri validatedAddress = addressBuilder.Uri;
                string identityAddress = validatedAddress.ToString();
                Logger.WriteLine(string.Format("Generated Identity URL: {0}", identityAddress), LogLevel.INFO);

                // Generate auth token for basic auth header and create auth header string
                var authToken = Encoding.ASCII.GetBytes($"{reconcileUsername}:{secureRecPass.convertSecureStringToString()}");
                string clientCredAuthToken = string.Format("Basic {0}", Convert.ToBase64String(authToken));
                Logger.WriteLine("Generated Basic Authorization Header", LogLevel.INFO);

                // Create body for logon including grant_type and scope
                string logonBody = string.Format("&grant_type=client_credentials&scope={0}", identityScope);
                Logger.WriteLine(string.Format("Generated Authorization Body: {0}", logonBody), LogLevel.INFO);

                // Initialize Client 
                JsonSerializer _jsonWriter = new()
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
                var _client = new IdentityClient(_jsonWriter);

                // Send request for Bearer Token
                Logger.WriteLine(string.Format(Resources.SendActionRequest + "Bearer Token to {0}/Oauth2/Token/{1}", address, identityAppId), LogLevel.INFO);
                var tokenResponse = _client.GetBearerToken(identityAddress, identityAppId, logonBody, clientCredAuthToken);
                if (tokenResponse.Failure)
                {
                    if (tokenResponse is HttpErrorResult<Response> httpErrorResult)
                        IdentityAPI.HandleHttpErrorResult(httpErrorResult);
                    else if (tokenResponse is WebExceptionResult<Response> WebExceptionResult)
                        IdentityAPI.HandleWebExceptionResult(WebExceptionResult.RequestException);
                    else if (tokenResponse is ErrorResult<Response> errorResult)
                        IdentityAPI.HandleErrorResult(errorResult);
                    else
                        tokenResponse.MissingPatternMatch();
                }
                else if (tokenResponse.Success)
                {
                    Logger.WriteLine(string.Format("Bearer Token " + Resources.ActionResponseSuccess), LogLevel.INFO);
                }

                // Extract Access Token From JSON
                Logger.WriteLine(string.Format("Extracting Bearer Token from {0}/Oauth2/Token/{1} response.", address, identityAppId), LogLevel.INFO);
                var jsonToken = JsonConvert.DeserializeObject<TokenResponse>(tokenResponse.Data.MessageContent);
                if (jsonToken.AccessToken == null)
                    throw new IdentityServiceException(string.Format(Resources.TokenError), PluginErrors.JSON_TOKEN_ERROR);
                string bearerAuthtoken = string.Format("Bearer {0}", jsonToken.AccessToken.ToString());
                Logger.WriteLine(Resources.TokenSuccess, LogLevel.INFO);

                // Create request body to retrieve user attributes
                UserObject userObject = new()
                {
                    ID = username
                };
                var userAttributeBody = JsonConvert.SerializeObject(userObject);

                // Send Request for User Attributes
                Logger.WriteLine(string.Format(Resources.SendActionRequest + "User Attributes to {0}UserMgmt/GetUserAttributes.", identityAddress), LogLevel.INFO);
                var attributeResponse = _client.PostJsonBody(string.Format("{0}UserMgmt/GetUserAttributes", identityAddress), userAttributeBody, bearerAuthtoken);
                if (attributeResponse.Failure)
                {
                    if (attributeResponse is HttpErrorResult<Response> httpErrorResult)
                        IdentityAPI.HandleHttpErrorResult(httpErrorResult);
                    else if (attributeResponse is WebExceptionResult<Response> WebExceptionResult)
                        IdentityAPI.HandleWebExceptionResult(WebExceptionResult.RequestException);
                    else if (attributeResponse is ErrorResult<Response> errorResult)
                        IdentityAPI.HandleErrorResult(errorResult);
                    else
                        attributeResponse.MissingPatternMatch();
                }
                else if (attributeResponse.Success)
                {
                    Logger.WriteLine(string.Format(action + Resources.RecieveActionResponse), LogLevel.INFO);
                    IdentityAPI.HandleSuccessResult(attributeResponse.Data.MessageContent.ToString());
                    Logger.WriteLine(string.Format(action + Resources.ActionResponseSuccess), LogLevel.INFO);
                }

                // Deserialize JSON and extract UUID for user from GetUserAttributes response
                Logger.WriteLine(string.Format("Extracting UUID from {0}UserMgmt/GetUserAttributes response.", identityAddress), LogLevel.INFO);
                var jsonUserAttributes = JsonConvert.DeserializeObject<IdentityResponseRoot>(attributeResponse.Data.MessageContent);
                if (!jsonUserAttributes.Success || jsonUserAttributes.Result == null)
                    throw new IdentityServiceException(string.Format(Resources.UuidError), PluginErrors.JSON_UUID_ERROR);
                string? uuid = jsonUserAttributes.Result.Uuid;
                Logger.WriteLine(string.Format("User {0} UUID Extracted: {1}", username, uuid), LogLevel.INFO);
                Logger.WriteLine(Resources.UuidSuccess, LogLevel.INFO);

                // Create reset password request body
                ResetPasswordObject resetPasswordObject = new()
                {
                    ID = uuid,
                    NewPassword = secureNewPass.convertSecureStringToString()
                };
                var resetPasswordBody = JsonConvert.SerializeObject(resetPasswordObject);

                // Attempt credential change using extracted UUID
                Logger.WriteLine(string.Format(Resources.SendActionRequest + action), LogLevel.INFO);
                var reconcileResponse = _client.PostJsonBody(string.Format("{0}UserMgmt/ResetUserPassword", identityAddress), resetPasswordBody, bearerAuthtoken);
                if (reconcileResponse.Failure)
                {
                    if (reconcileResponse is HttpErrorResult<Response> httpErrorResult)
                        IdentityAPI.HandleHttpErrorResult(httpErrorResult);
                    else if (reconcileResponse is WebExceptionResult<Response> WebExceptionResult)
                        IdentityAPI.HandleWebExceptionResult(WebExceptionResult.RequestException);
                    else if (reconcileResponse is ErrorResult<Response> errorResult)
                        IdentityAPI.HandleErrorResult(errorResult);
                    else
                        reconcileResponse.MissingPatternMatch();
                }
                else if (reconcileResponse.Success)
                {
                    Logger.WriteLine(string.Format(action + Resources.RecieveActionResponse), LogLevel.INFO);
                    IdentityAPI.HandleSuccessResult(reconcileResponse.Data.MessageContent.ToString());
                    Logger.WriteLine(string.Format(action + Resources.ActionResponseSuccess), LogLevel.INFO);
                }

                Logger.WriteLine(Resources.ReconcileSuccess, LogLevel.INFO);
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
            finally
            {
                Logger.MethodEnd();
            }

            return RC;

        }
    }
}