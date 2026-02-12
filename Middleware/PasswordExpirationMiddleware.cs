using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;
using System.Security.Claims;

namespace WebApplication1.Middleware
{
    public class PasswordExpirationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _config;

        public PasswordExpirationMiddleware(RequestDelegate next, IConfiguration config)
        {
            _next = next;
            _config = config;
        }

        public async Task InvokeAsync(HttpContext context, UserManager<ApplicationUser> userManager)
        {
            var path = context.Request.Path.Value?.ToLowerInvariant() ?? "";

            // ALWAYS allow these paths - NO REDIRECTS for these
            if (path.Contains("/account/login") ||
                path.Contains("/account/changepassword") ||
                path.Contains("/account/forgotpassword") ||
                path.Contains("/account/resetpassword") ||
                path.Contains("/account/register") ||
                path.Contains("/css") ||
                path.Contains("/js") ||
                path.Contains("/lib") ||
                path.Contains("/images") ||
                path.Contains("/uploads") ||
                path.Contains("/error") ||
                path.Contains("/status"))
            {
                await _next(context);
                return;
            }

            // Only check for authenticated users
            if (context.User?.Identity?.IsAuthenticated ?? false)
            {
                var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (!string.IsNullOrEmpty(userId))
                {
                    var user = await userManager.FindByIdAsync(userId);
                    if (user?.LastPasswordChangedAt.HasValue == true)
                    {
                        var maxAgeMinutes = _config.GetValue<int?>("PasswordPolicy:MaxPasswordAgeMinutes") ?? 2;
                        var timeSinceChange = DateTime.UtcNow - user.LastPasswordChangedAt.Value;

                        // If password is expired, redirect to ChangePassword page
                        if (timeSinceChange.TotalMinutes >= maxAgeMinutes)
                        {
                            context.Response.Redirect("/Account/ChangePassword?expired=true");
                            return;
                        }
                    }
                }
            }

            await _next(context);
        }
    }
}