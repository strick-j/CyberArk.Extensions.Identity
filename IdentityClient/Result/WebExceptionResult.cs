using System.Net;

namespace CyberArk.Extensions.Identity
{
    public class WebExceptionResult<T> : ErrorResult<T>
    {
        public WebException RequestException { get; }

        public WebExceptionResult(string message, WebException requestException) : base(message)
        {
            RequestException = requestException;
        }

        public WebExceptionResult(string message, IReadOnlyCollection<Error> errors, WebException requestException) : base(message, errors)
        {
            RequestException = requestException;
        }
    }
}
