using Homo.Core.Constants;

namespace Homo.Auth.Constants
{
    public class AppSettings : Homo.Core.Constants.IAppSettings
    {
        public Common Common { get; set; }
        public Secrets Secrets { get; set; }
    }

    public class Secrets
    {
        public string JwtKey { get; set; }
    }
}
