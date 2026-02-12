using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;

namespace WebApplication1.Pages.Account
{
    public class TwoFactorModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;

        public TwoFactorModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
        }

        [BindProperty]
        public string Code { get; set; }

        public string? StatusMessage { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToPage("/Account/Login");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (string.IsNullOrWhiteSpace(Code))
            {
                ModelState.AddModelError("", "Code is required.");
                return Page();
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToPage("/Account/Login");
            }

            // Only support authenticator app (TOTP) codes
            var code = Code.Replace(" ", "");
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent: false, rememberClient: false);

            if (result.Succeeded)
            {
                // complete login: create session id and store
                var sessionId = Guid.NewGuid().ToString();
                user.SessionId = sessionId;
                await _userManager.UpdateAsync(user);
                HttpContext.Session.SetString("SessionId", sessionId);

                _db.AuditLogs.Add(new AuditLog { UserId = user.Id, Action = "LoginSucceeded_2FA", Timestamp = DateTime.UtcNow, Details = null });
                await _db.SaveChangesAsync();

                return RedirectToPage("/Index");
            }

            if (result.IsLockedOut)
            {
                _db.AuditLogs.Add(new AuditLog { UserId = user.Id, Action = "AccountLocked_2FA", Timestamp = DateTime.UtcNow, Details = null });
                await _db.SaveChangesAsync();
                ModelState.AddModelError("", "Account locked.");
                return Page();
            }

            // failed
            ModelState.AddModelError("", "Invalid authentication code.");
            return Page();
        }
    }
}