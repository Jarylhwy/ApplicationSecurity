using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;

namespace WebApplication1.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
        }

        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string Password { get; set; }

        public string? LockoutMessage { get; set; }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                // log failed attempt — database requires a non-null UserId, use a placeholder
                _db.AuditLogs.Add(new AuditLog { UserId = "Unknown", Action = "LoginFailed", Timestamp = DateTime.UtcNow, Details = $"Unknown email {Email}" });
                await _db.SaveChangesAsync();
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            var result = await _signInManager.PasswordSignInAsync(user, Password, isPersistent: false, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                // create session id and store
                var sessionId = Guid.NewGuid().ToString();
                user.SessionId = sessionId;
                await _userManager.UpdateAsync(user);
                HttpContext.Session.SetString("SessionId", sessionId);

                _db.AuditLogs.Add(new AuditLog { UserId = user.Id, Action = "LoginSucceeded", Timestamp = DateTime.UtcNow, Details = null });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Index");
            }

            if (result.IsLockedOut)
            {
                _db.AuditLogs.Add(new AuditLog { UserId = user.Id, Action = "AccountLocked", Timestamp = DateTime.UtcNow, Details = null });
                await _db.SaveChangesAsync();

                // Compute remaining lockout time
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                if (lockoutEnd.HasValue)
                {
                    var remaining = lockoutEnd.Value.UtcDateTime - DateTime.UtcNow;
                    if (remaining.TotalSeconds > 0)
                    {
                        LockoutMessage = $"Account locked. It will automatically recover in {remaining.Minutes} minutes and {remaining.Seconds} seconds.";
                    }
                    else
                    {
                        LockoutMessage = "Account locked. Please try again later.";
                    }
                }
                else
                {
                    LockoutMessage = "Account locked. Please try again later.";
                }

                ModelState.AddModelError("", LockoutMessage);
                return Page();
            }

            // failed attempt
            _db.AuditLogs.Add(new AuditLog { UserId = user.Id, Action = "LoginFailed", Timestamp = DateTime.UtcNow, Details = null });
            await _db.SaveChangesAsync();
            ModelState.AddModelError("", "Invalid login attempt.");
            return Page();
        }
    }
}
