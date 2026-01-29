using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;

namespace WebApplication1.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult OnGet()
        {
            // Redirect GET requests to home
            return RedirectToPage("/Index");
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                user.SessionId = null;
                await _userManager.UpdateAsync(user);
            }

            await _signInManager.SignOutAsync();
            HttpContext.Session.Clear();

            return RedirectToPage("/Index");
        }
    }
}
