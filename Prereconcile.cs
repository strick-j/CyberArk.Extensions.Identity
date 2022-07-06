using System.Collections.Generic;
using CyberArk.Extensions.Identity.Properties;
using CyberArk.Extensions.Identity.Model;
using CyberArk.Extensions.Identity.Client;
using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.Reader;
using System;


// Change the Template name space
namespace CyberArk.Extensions.Identity
{
    public class Prereconcile : BaseAction
    {
        #region Consts
        public static readonly string USERNAME = "Username";
        public static readonly string ADDRESS = "address";
        public static readonly string IDENAPPID = "identityAppId";
        public static readonly string IDENSCOPE = "identityScope";

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
        /// Defines the Action name that the class is implementing - PreReconcile
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
            ErrorCodeStandards errCodeStandards = new();
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
                ParametersAPI.ValidateParameterLength(reconcileUsername, "Reconcile Username", 64);

                string address = ParametersAPI.GetMandatoryParameter(ADDRESS, TargetAccount.AccountProp);
                ParametersAPI.ValidateURI(address, "Address", UriKind.Absolute);

                string identityScope = ParametersAPI.GetMandatoryParameter(IDENSCOPE, TargetAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityScope, "Scope");

                string identityAppId = ParametersAPI.GetMandatoryParameter(IDENAPPID, TargetAccount.AccountProp);
                ParametersAPI.ValidateAlphanumeric(identityAppId, "AppId");

                #endregion

                #region Fetch Account's Passwords
                // TODO: Add tests for password validation
                string currPassword = TargetAccount.CurrentPassword.convertSecureStringToString();
                string newPassword = TargetAccount.NewPassword.convertSecureStringToString();
                string reconcilePassword = ReconcileAccount.CurrentPassword.convertSecureStringToString();
                #endregion

                #region Logic
                //  Perform Uuid lookup for Target User as Reconcile User
                var reconcileClient = new IdentityClient(address, reconcileUsername, reconcilePassword, identityScope, identityAppId);
                var reconcileResponse = reconcileClient.GetUserAttributes(username);
                ResponseAPI.ValidateLookupResponse(reconcileResponse.Result);
                if (reconcileResponse.Result.Success)
                {
                    Logger.WriteLine(string.Format("obtained Uuid ({0}) for {1}", reconcileResponse.Result.Result.Uuid, username), LogLevel.INFO);
                }

                // TODO: Add additional check for permissions to reset user passwords
                #endregion Logic
            }
            catch (ParametersConfigurationException ex)
            {
                Logger.WriteLine(string.Format("Recieved exception: {0}", ex.ToString()));
                platformOutput.Message = ex.Message;
                RC = ex.ErrorCode;
            }
            catch (UserNotAuthorizedException ex)
            {
                HandleException(ex, Resources.UserNotAuthorizedMessage, ref empty);
                platformOutput.Message = ex.Message;
                RC = PluginErrors.ACCESS_DENIED;
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