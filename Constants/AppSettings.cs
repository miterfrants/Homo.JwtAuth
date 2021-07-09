namespace Homo.Auth.Constants
{
    public class AppSettings : Homo.Core.Constants.AppSettings
    {
        public Secrets Secrets { get; set; }
    }

    public class Secrets
    {
        public string JwtKey { get; set; }
    }
}
