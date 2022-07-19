namespace CyberArk.Extensions.Identity
{
    public class IdentityServiceException : Exception
    {
        public int ErrorCode { get; set; }

        public IdentityServiceException(string message, int errorCode)
            : base(message)
        {
            ErrorCode = errorCode;
        }

        public IdentityServiceException(string message, int errorCode, Exception ex)
            : base(message, ex)
        {

            ErrorCode = errorCode;
        }
    }
}

