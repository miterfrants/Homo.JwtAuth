using System;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Homo.Auth.Constants;
using Microsoft.Extensions.Options;

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
            JwtAuthorizeAttribute attribute = new JwtAuthorizeAttribute(_permissions, config.Value.Secrets.JwtKey);
            return attribute;
        }
    }
}