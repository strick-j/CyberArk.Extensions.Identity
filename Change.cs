using System.Collections.Generic;
using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.Logger;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.Reader;
using System;

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
            string empty = string.Empty;
            #endregion 

            try
            {
                SetDefaultValues(errCodeStandards, ref empty);
                #region Fetch Account Properties (FileCategories)
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
                string currPassword = TargetAccount.CurrentPassword.convertSecureStringToString();
                string newPassword = TargetAccount.NewPassword.convertSecureStringToString();

                #endregion

                #region Logic
                //  Perform Uuid lookup for Current User as Current User
                var changeClient = new IdentityClient(address, username, currPassword, identityScope, identityAppId);
                var changeResponse = changeClient.GetUserAttributes(username);
                ResponseAPI.ValidateLookupResponse(changeResponse);
                if (changeResponse.Result.Success)
                {
                    Logger.WriteLine(string.Format("obtained Uuid ({0}) for {1}", changeResponse.Result.Result.Uuid, username), LogLevel.INFO);
                }

                // Execute Change Password Process
                var executeChangeResponse = changeClient.ChangeUserPassword(currPassword, newPassword);
                ResponseAPI.ValidateActionResponse(executeChangeResponse);
                if (executeChangeResponse.Result.Success)
                {
                    Logger.WriteLine("Verify action ended successfully", LogLevel.INFO);
                    RC = 0;
                }
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
