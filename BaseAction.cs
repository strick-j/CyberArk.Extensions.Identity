using CyberArk.Extensions.Plugins.Models;
using CyberArk.Extensions.Utilties.CPMParametersValidation;
using CyberArk.Extensions.Utilties.CPMPluginErrorCodeStandarts;
using CyberArk.Extensions.Utilties.Logger;

namespace CyberArk.Extensions.Identity
{
    /*
     * Base Action class should contain common plug-in functionality and parameters.
     * For specific action functionality and parameters use the action classes.
     */
    abstract public class BaseAction : AbsAction
    {
        #region Properties
        private readonly string CLASS_NAME = nameof(BaseAction);
        internal ParametersManager ParametersAPI { get; private set; }
        internal IdentityServiceManager IdentityAPI { get; private set; }
        #endregion

        #region constructor
        /// <summary>
        /// BaseAction Ctor. Do not change anything unless you would like to initialize local class members
        /// The Ctor passes the logger module and the plug-in account's parameters to base.
        /// Do not change Ctor's definition not create another.
        /// <param name="accountList"></param>
        /// <param name="logger"></param>
        public BaseAction(List<IAccount> accountList, ILogger logger)
            : base(accountList, logger)
        {
            ParametersAPI = new ParametersManager();
            IdentityAPI = new IdentityServiceManager();
        }
        #endregion

        internal int SetDefaultValues(ErrorCodeStandards errCodeStandards, ref string messegeToPVWA)
        {
            messegeToPVWA = errCodeStandards.ErrorStandardsDict[this.DEFAULT_ERROR_ID].ErrorMsg;
            return errCodeStandards.ErrorStandardsDict[this.DEFAULT_ERROR_ID].ErrorRC;
        }

        internal void HandleException(Exception exception, string errorMsg, ref string messegeToPVWA)
        {
            this.LogGeneralException(exception, errorMsg);
            messegeToPVWA = errorMsg;
        }

        internal void LogGeneralException(Exception exception, string errorMsg)
        {
            this.log.WriteLine(this.CLASS_NAME, "handleException()", "Got " + (object)exception.GetType() + " message = " + exception.Message, (LogLevel)2);
            this.log.WriteLine(this.CLASS_NAME, "handleException()", errorMsg, (LogLevel)2);
        }

        /// <summary>
        /// Handle the general RC and error message.
        /// <summary>
        /// <param name="ex"></param>
        /// <param name="platformOutput"></param>
        internal int HandleGeneralError(Exception ex, ref PlatformOutput platformOutput)
        {
            ErrorCodeStandards errCodeStandards = new ErrorCodeStandards();
            Logger.WriteLine(string.Format("Received exception: {0}.", ex), LogLevel.ERROR);
            platformOutput.Message = errCodeStandards.ErrorStandardsDict[PluginErrors.STANDARD_DEFUALT_ERROR_CODE_IDX].ErrorMsg;
            return errCodeStandards.ErrorStandardsDict[PluginErrors.STANDARD_DEFUALT_ERROR_CODE_IDX].ErrorRC;
        }
    }
}