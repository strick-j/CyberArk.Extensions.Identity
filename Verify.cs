using System.Collections.Generic;
using System.Threading.Tasks;
using CyberArk.Extensions.Identity.Properties;
using CyberArk.Extensions.Identity.Client;
using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.Reader;
using System;
using CyberArk.Extensions.Identity.Model;

namespace CyberArk.Extensions.Identity
{
    public class Verify : BaseAction
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
        public Verify(List<IAccount> accountList, ILogger logger)
            : base(accountList, logger)
        {
        }
        #endregion

        #region Setter
        /// <summary>
        /// Defines the Action name that the class is implementing - Verify
        /// </summary>
        override public CPMAction ActionName
        {
            get { return CPMAction.verifypass; }
        }
        #endregion

        /// <summary>
        /// Plug-in Starting point function.
        /// </summary>
        /// <param name="platformOutput"></param>
        /// 
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
                Logger.WriteLine("Attempting to fetch account properties for Verify", LogLevel.INFO);
                string username = ParametersAPI.GetMandatoryParameter(USERNAME, TargetAccount.AccountProp);
                ParametersAPI.ValidateParameterLength(username, "Username", 64);

                string address = ParametersAPI.GetMandatoryParameter(ADDRESS, TargetAccount.AccountProp);
                ParametersAPI.ValidateURI(address, "Address", UriKind.Absolute);

                string identityScope = ParametersAPI.GetMandatoryParameter(IDENSCOPE, TargetAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityScope, "Identity Scope");

                string identityAppId = ParametersAPI.GetMandatoryParameter(IDENAPPID, TargetAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityAppId, "Identity Application Id");
                #endregion

                #region Fetch Account's Passwords
                Logger.WriteLine("Attempting to fetch account password for Verify", LogLevel.INFO);
                string verifyPassword = TargetAccount.CurrentPassword.convertSecureStringToString();
                Logger.WriteLine(string.Format("{0}", verifyPassword), LogLevel.INFO);
                #endregion

                #region Logic
                Logger.WriteLine("Creating Verify Client", LogLevel.INFO);
                var verifyClient = new IdentityClient(address, username, verifyPassword, identityScope, identityAppId);
                Logger.WriteLine("Retrieving Verify Response", LogLevel.INFO);
                var verifyResponse = verifyClient.GetUserAttributes(username);
                Logger.WriteLine(string.Format("Task Status: {0}", verifyResponse.Result), LogLevel.INFO);
                Logger.WriteLine("Validating Verify Response", LogLevel.INFO);
                ResponseAPI.ValidateLookupResponse(verifyResponse);

                if (verifyResponse.Success)
                {
                    Logger.WriteLine("Verify action ended successfully", LogLevel.INFO);
                    RC = 0;
                }
                #endregion Logic

            }
            catch (ParametersConfigurationException ex)
            {
                Logger.WriteLine("Parameter Configuration Exception", LogLevel.INFO);
                Logger.WriteLine(string.Format("Recieved exception: {0}", ex.ToString()));
                platformOutput.Message = ex.Message;
                RC = ex.ErrorCode;
            }
            catch (UserNotAuthorizedException ex)
            {
                Logger.WriteLine("User Not Authorized Exeception", LogLevel.INFO);
                HandleException(ex, Resources.UserNotAuthorizedMessage, ref empty);
                platformOutput.Message = ex.Message;
                RC = PluginErrors.ACCESS_DENIED;
            }
            catch (Exception ex)
            {
                Logger.WriteLine("Generic Exception", LogLevel.INFO);
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