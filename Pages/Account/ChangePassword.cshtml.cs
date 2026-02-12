using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using WebApplication1.Model;

namespace WebApplication1.Pages.Account
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            AuthDbContext db,
            IConfiguration config)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _config = config;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string StatusMessage { get; set; }
        public bool IsPasswordExpired { get; set; }
        public string ExpiryMessage { get; set; }
        public double MinAgeMinutes { get; set; } = 1;
        public DateTime? LastPasswordChange { get; set; }
        public double MinutesSinceLastChange { get; set; }
        public bool CanChangePassword { get; set; } = true;

        public class InputModel
        {
            public string CurrentPassword { get; set; }
            public string NewPassword { get; set; }
            public string ConfirmPassword { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(bool expired = false)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Account/Login");
            }

            IsPasswordExpired = expired || HttpContext.Session.GetString("PasswordExpired") == "true";
            MinAgeMinutes = _config.GetValue<double?>("PasswordPolicy:MinPasswordAgeMinutes") ?? 1;
            LastPasswordChange = user.LastPasswordChangedAt;

            if (IsPasswordExpired)
            {
                ExpiryMessage = "Your password has expired. You must change it now to continue.";
                ViewData["Title"] = "Change Expired Password";
                CanChangePassword = true;
            }
            else
            {
                ViewData["Title"] = "Change Password";

                if (LastPasswordChange.HasValue)
                {
                    MinutesSinceLastChange = (DateTime.UtcNow - LastPasswordChange.Value).TotalMinutes;

                    if (MinutesSinceLastChange < MinAgeMinutes)
                    {
                        CanChangePassword = false;
                        var timeRemaining = MinAgeMinutes - MinutesSinceLastChange;
                        ViewData["MinAgeWarning"] = $"?? Please wait {timeRemaining:F1} more minutes before changing your password again.";
                    }
                    else
                    {
                        CanChangePassword = true;
                    }
                }
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Account/Login");
            }

            IsPasswordExpired = HttpContext.Session.GetString("PasswordExpired") == "true" ||
                                Request.Query["expired"] == "true";

            // Minimum password age check - only if not expired
            if (!IsPasswordExpired)
            {
                var minAgeMinutes = _config.GetValue<double?>("PasswordPolicy:MinPasswordAgeMinutes") ?? 1;
                if (user.LastPasswordChangedAt.HasValue)
                {
                    var since = DateTime.UtcNow - user.LastPasswordChangedAt.Value;
                    if (since.TotalMinutes < minAgeMinutes)
                    {
                        var timeRemaining = minAgeMinutes - since.TotalMinutes;
                        ModelState.AddModelError("", $"Please wait {timeRemaining:F1} more minutes before changing your password.");
                        return Page();
                    }
                }
            }

            // Verify current password
            var verify = await _userManager.CheckPasswordAsync(user, Input.CurrentPassword);
            if (!verify)
            {
                ModelState.AddModelError("", "Current password is incorrect.");
                return Page();
            }

            // Prevent reuse of last 2 passwords
            var lastTwo = await _db.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.Timestamp)
                .Take(2)
                .ToListAsync();

            foreach (var h in lastTwo)
            {
                var res = _userManager.PasswordHasher.VerifyHashedPassword(user, h.HashedPassword, Input.NewPassword);
                if (res != PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError("", "You may not reuse one of your last 2 passwords.");
                    return Page();
                }
            }

            // Change password
            var change = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!change.Succeeded)
            {
                foreach (var e in change.Errors)
                {
                    ModelState.AddModelError("", e.Description);
                }
                return Page();
            }

            // Add new password hash to history
            var newHash = _userManager.PasswordHasher.HashPassword(user, Input.NewPassword);
            _db.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                HashedPassword = newHash,
                Timestamp = DateTime.UtcNow
            });

            // Trim history to 2 entries
            var all = await _db.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.Timestamp)
                .ToListAsync();

            if (all.Count > 2)
            {
                var remove = all.Skip(2).ToList();
                _db.PasswordHistories.RemoveRange(remove);
            }
            await _db.SaveChangesAsync();

            // Update last password changed timestamp
            user.LastPasswordChangedAt = DateTime.UtcNow;

            // Generate new session ID but KEEP USER SIGNED IN
            var newSessionId = Guid.NewGuid().ToString();
            user.SessionId = newSessionId;
            await _userManager.UpdateAsync(user);
            HttpContext.Session.SetString("SessionId", newSessionId);

            // Clear password expiration flags
            HttpContext.Session.Remove("PasswordExpired");
            HttpContext.Session.Remove("PasswordExpiryMessage");
            HttpContext.Session.Remove("PasswordExpiryWarning");

            // Refresh sign-in - keeps user logged in
            await _signInManager.RefreshSignInAsync(user);

            if (IsPasswordExpired)
            {
                TempData["SuccessMessage"] = "Your expired password has been changed successfully!";
                return RedirectToPage("/Index");
            }
            else
            {
                StatusMessage = "Your password has been changed successfully.";
                return Page();
            }
        }
    }
}