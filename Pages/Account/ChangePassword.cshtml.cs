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

        public ChangePasswordModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, AuthDbContext db, IConfiguration config)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _config = config;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string StatusMessage { get; set; }

        public class InputModel
        {
            public string CurrentPassword { get; set; }
            public string NewPassword { get; set; }
            public string ConfirmPassword { get; set; }
        }

        public async Task OnGetAsync()
        {
            // nothing
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

            // Enforce minimum password age: cannot change within X minutes of last change
            var minAgeMinutes = _config.GetValue<int?>("PasswordPolicy:MinPasswordAgeMinutes") ?? 5;
            if (user.LastPasswordChangedAt.HasValue)
            {
                var since = DateTime.UtcNow - user.LastPasswordChangedAt.Value;
                if (since.TotalMinutes < minAgeMinutes)
                {
                    ModelState.AddModelError("", $"You cannot change your password within {minAgeMinutes} minutes of the last change.");
                    return Page();
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
            var lastTwo = await _db.PasswordHistories.Where(p => p.UserId == user.Id).OrderByDescending(p => p.Timestamp).Take(2).ToListAsync();
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

            // Add new password hash to history and trim to 2
            var newHash = _userManager.PasswordHasher.HashPassword(user, Input.NewPassword);
            _db.PasswordHistories.Add(new PasswordHistory { UserId = user.Id, HashedPassword = newHash, Timestamp = DateTime.UtcNow });
            var all = await _db.PasswordHistories.Where(p => p.UserId == user.Id).OrderByDescending(p => p.Timestamp).ToListAsync();
            if (all.Count > 2)
            {
                var remove = all.Skip(2).ToList();
                _db.PasswordHistories.RemoveRange(remove);
            }
            await _db.SaveChangesAsync();

            // Update last password changed timestamp
            user.LastPasswordChangedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            await _signInManager.RefreshSignInAsync(user);

            StatusMessage = "Your password has been changed.";
            return Page();
        }
    }
}
