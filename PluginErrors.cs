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
        public static readonly int GENERAL_ERROR_NUMBER = 8807;
        public static readonly int NO_SUCH_ENTITY_ERROR_NUMBER = 8800;
        public static readonly int MANDATORY_PARAMETER_MISSING = 8808;
        public static readonly int ACCESS_DENIED = 8802;
        public static readonly int DEFAULT_ERROR_NUMBER = -1;
    }
}

