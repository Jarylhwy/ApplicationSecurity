using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;

namespace WebApplication1.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string StatusMessage { get; set; }

        public class InputModel
        {
            public string UserId { get; set; }

            [Required]
            public string Token { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string NewPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Compare("NewPassword")]
            public string ConfirmPassword { get; set; }
        }

        public void OnGet(string userId, string token)
        {
            Input = new InputModel { UserId = userId, Token = token };
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByIdAsync(Input.UserId);
            if (user == null)
            {
                // don't reveal
                return RedirectToPage("/Account/ResetPasswordConfirmation");
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Token, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors)
                {
                    ModelState.AddModelError("", e.Description);
                }
                return Page();
            }

            // optionally clear sessions, set session id null
            user.SessionId = null;
            await _userManager.UpdateAsync(user);

            return RedirectToPage("/Account/ResetPasswordConfirmation");
        }
    }
}
