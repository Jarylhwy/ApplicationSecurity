using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;
using Microsoft.Extensions.Configuration;

namespace WebApplication1.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            IConfiguration config)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _config = config;
        }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string Password { get; set; }

        public string? LockoutMessage { get; set; }

        public IActionResult OnGet()
        {
            // If already logged in, redirect to home
            if (User.Identity?.IsAuthenticated ?? false)
            {
                return RedirectToPage("/Index");
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                _db.AuditLogs.Add(new AuditLog
                {
                    UserId = "Unknown",
                    Action = "LoginFailed",
                    Timestamp = DateTime.UtcNow,
                    Details = "Failed login attempt from unknown email"
                });
                await _db.SaveChangesAsync();
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            // Set LastPasswordChangedAt if it's null (for existing users)
            if (!user.LastPasswordChangedAt.HasValue)
            {
                user.LastPasswordChangedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
            }

            var result = await _signInManager.PasswordSignInAsync(user.UserName, Password,
                isPersistent: false, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                // Check if password is expired
                var maxAgeMinutes = _config.GetValue<int?>("PasswordPolicy:MaxPasswordAgeMinutes") ?? 2;
                var timeSinceChange = DateTime.UtcNow - user.LastPasswordChangedAt.Value;

                if (timeSinceChange.TotalMinutes >= maxAgeMinutes)
                {
                    // Password expired - sign in temporarily, then redirect to change password
                    // This allows them to access the ChangePassword page
                    var sessionId = Guid.NewGuid().ToString();
                    user.SessionId = sessionId;
                    await _userManager.UpdateAsync(user);
                    HttpContext.Session.SetString("SessionId", sessionId);
                    HttpContext.Session.SetString("PasswordExpired", "true");

                    return RedirectToPage("/Account/ChangePassword", new { expired = true });
                }

                // Normal login - create session
                var newSessionId = Guid.NewGuid().ToString();
                user.SessionId = newSessionId;
                await _userManager.UpdateAsync(user);
                HttpContext.Session.SetString("SessionId", newSessionId);

                _db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "LoginSucceeded",
                    Timestamp = DateTime.UtcNow,
                    Details = null
                });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Index");
            }

            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("/Account/TwoFactor");
            }

            if (result.IsLockedOut)
            {
                _db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "AccountLocked",
                    Timestamp = DateTime.UtcNow,
                    Details = null
                });
                await _db.SaveChangesAsync();

                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                if (lockoutEnd.HasValue)
                {
                    var remaining = lockoutEnd.Value.UtcDateTime - DateTime.UtcNow;
                    if (remaining.TotalSeconds > 0)
                    {
                        LockoutMessage = $"Account locked. Please try again in {remaining.Minutes} minutes and {remaining.Seconds} seconds.";
                    }
                }
                ModelState.AddModelError("", LockoutMessage ?? "Account locked.");
                return Page();
            }

            // Failed login
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Action = "LoginFailed",
                Timestamp = DateTime.UtcNow,
                Details = null
            });
            await _db.SaveChangesAsync();

            ModelState.AddModelError("", "Invalid login attempt.");
            return Page();
        }
    }
}