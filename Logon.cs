using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.Reader;
using Newtonsoft.Json;
using CyberArk.Extensions.Plugin.RestAPI;
using System.Net;
using System.Net.Http.Headers;
using System.Security;
using System.Text;

// Change the Template name space
namespace CyberArk.Extensions.Identity
{
    public class Logon : BaseAction
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
        public Logon(List<IAccount> accountList, ILogger logger)
            : base(accountList, logger)
        {
        }
        #endregion

        #region Setter
        /// <summary>
        /// Defines the Action name that the class is implementing - Logon
        /// </summary>
        override public CPMAction ActionName
        {
            get { return CPMAction.logon; }
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
                Logger.WriteLine("Attempting to fetch account properties", LogLevel.INFO);

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
                var authToken = Encoding.ASCII.GetBytes($"{username}:{secureCurrPass.convertSecureStringToString()}");
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
                Logger.WriteLine(string.Format(Resources.SendActionRequest + "Bearer Token to {0}/Oauth2/Token/{1}", identityAddress, identityAppId), LogLevel.INFO);
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

                Logger.WriteLine(Resources.LogonSuccess, LogLevel.INFO);
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