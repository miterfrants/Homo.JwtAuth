using System;
using System.Net;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Homo.Core.Constants;
using Homo.Core.Middlewares;

namespace Homo.Auth.Middlewares
{
    public class JwtAuthErrorHandlingMiddleware : ErrorHandlingMiddleware
    {
        private readonly RequestDelegate next;
        public JwtAuthErrorHandlingMiddleware(RequestDelegate next) : base(next)
        {
            this.next = next;
        }

        protected override ActionResult<dynamic> HandleExceptionAsync(HttpContext context, Exception ex, IOptions<IAppSettings> config)
        {
            IOptions<Homo.Auth.Constants.AppSettings> _config = _serviceProvider.GetService<IOptions<Homo.Auth.Constants.AppSettings>>();
            return base.HandleExceptionAsync(context, ex, _config);

        }
    }
}
