using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Linq;
using System.Security.Claims;
using System.Net;
using Homo.Core.Helpers;
using Homo.Core.Constants;
using Homo.Auth.Constants;

namespace Homo.Auth.Filters
{
    public class JwtAuthorizeAttribute : ActionFilterAttribute
    {
        string _jwtKey { get; set; }
        PERMISSIONS[] _permissions { get; set; }
        public bool isSignUp { get; set; }

        public JwtAuthorizeAttribute(PERMISSIONS[] permissions, string jwtKey)
        {
            _jwtKey = jwtKey;
            _permissions = permissions;
        }

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            if (_permissions == null)
            {
                throw new CustomException(Homo.Auth.Constants.ERROR_CODE.PERMISSION_IS_UNDEFINED, HttpStatusCode.Forbidden);
            }

            string authorization = context.HttpContext.Request.Headers["Authorization"];
            string token = authorization != null ? authorization.Substring("Bearer ".Length).Trim() : null;
            if (token == null || token == "")
            {
                throw new CustomException(Homo.Auth.Constants.ERROR_CODE.UNAUTH_ACCESS_API, HttpStatusCode.Forbidden);
            }
            ClaimsPrincipal payload = JWTHelper.GetPayload(_jwtKey, token);
            bool isAllow = (_permissions != null && _permissions.Any(x => payload.IsInRole(x.ToString())))
                    || _permissions.Contains(PERMISSIONS.NO)
                    || payload.IsInRole(PERMISSIONS.ADMIN.ToString());
            // permission block
            if (payload == null || !isAllow)
            {
                throw new CustomException(Homo.Auth.Constants.ERROR_CODE.UNAUTH_ACCESS_API, HttpStatusCode.Unauthorized);
            }

            int unixTimestamp = 0;
            Int32.TryParse(payload.FindFirstValue("exp"), out unixTimestamp);
            DateTime expiration = new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime();
            if (DateTime.Now > expiration.AddSeconds(unixTimestamp))
            {
                throw new CustomException(Homo.Auth.Constants.ERROR_CODE.TOKEN_EXPIRED, HttpStatusCode.Unauthorized);
            }

            long? userId = JWTHelper.GetUserIdFromRequest(_jwtKey, context.HttpContext.Request);

            if (userId == null)
            {
                throw new CustomException(Homo.Auth.Constants.ERROR_CODE.USER_ID_NOT_IN_TOKEN, HttpStatusCode.NotFound);
            }
            context.ActionArguments["jwtExtraPayload"] = Newtonsoft.Json.JsonConvert.DeserializeObject(payload.FindFirstValue("extra"));
        }
    }
}