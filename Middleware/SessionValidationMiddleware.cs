using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using WebApplication1.Model;

namespace WebApplication1.Middleware
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, UserManager<ApplicationUser> userManager)
        {
            // Only validate for authenticated users
            if (context.User?.Identity?.IsAuthenticated ?? false)
            {
                var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (!string.IsNullOrEmpty(userId))
                {
                    var user = await userManager.FindByIdAsync(userId);
                    if (user != null)
                    {
                        var serverSessionId = user.SessionId;
                        var clientSessionId = context.Session.GetString("SessionId");

                        // If server has a session id and it doesn't match client session, sign out
                        if (!string.IsNullOrEmpty(serverSessionId) && serverSessionId != clientSessionId)
                        {
                            // Invalidate
                            await context.SignOutAsync(IdentityConstants.ApplicationScheme);
                            context.Session.Clear();
                            context.Response.Redirect("/Identity/Account/Login");
                            return;
                        }
                    }
                }
            }

            await _next(context);
        }
    }
}
