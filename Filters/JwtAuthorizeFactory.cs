using System;
using System.Net;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Homo.Core.Constants;
using Homo.Auth.Constants;


namespace Homo.Auth.Filters
{
    public class JwtAuthorizeFactory : ActionFilterAttribute, IFilterFactory
    {
        public bool IsReusable => true;
        public PERMISSIONS[] _permissions;
        public JwtAuthorizeFactory(PERMISSIONS[] permissions = null)
        {
            this._permissions = permissions;
        }

        public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
        {
            IOptions<Homo.Auth.Constants.AppSettings> config = serviceProvider.GetService<IOptions<Homo.Auth.Constants.AppSettings>>();
            if (config.Value.Secrets == null || config.Value.Secrets.JwtKey == null)
            {
                throw new CustomException(Homo.Auth.Constants.ERROR_CODE.SECRETS_NOT_IN_APPSETTING, HttpStatusCode.InternalServerError);
            }
            JwtAuthorizeAttribute attribute = new JwtAuthorizeAttribute(_permissions, config.Value.Secrets.JwtKey);
            return attribute;
        }
    }
}