using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.ViewModels;
using WebApplication1.Services;

namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }
        private readonly IDataProtector _protector;
        private readonly RecaptchaService _recaptcha;

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IDataProtectionProvider dataProtectionProvider, RecaptchaService recaptcha)
        {
            this.userManager = userManager; this.signInManager = signInManager;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.UserData");
            _recaptcha = recaptcha;
        }

        public void OnGet()
        {
        }

        //Save data into the database
        public async Task<IActionResult> OnPostAsync()
        {
            var token = Request.Form["g-recaptcha-response"].ToString();
            var ok = await _recaptcha.ValidateAsync(token, "register", 0.5);
            if (!ok)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                var sessionId = Guid.NewGuid().ToString();

                var user = new ApplicationUser()
                {
                    UserName = RModel.Email,
                    Email = RModel.Email,
                    FirstName = RModel.FirstName,
                    LastName = RModel.LastName,
                    CreditCard = string.IsNullOrEmpty(RModel.CreditCard) ? string.Empty : _protector.Protect(RModel.CreditCard),
                    BillingAddress = string.IsNullOrEmpty(RModel.BillingAddress) ? string.Empty : _protector.Protect(RModel.BillingAddress),
                    ShippingAddress = string.IsNullOrEmpty(RModel.ShippingAddress) ? string.Empty : _protector.Protect(RModel.ShippingAddress),
                    PhoneNumber = RModel.PhoneNumber ?? string.Empty,
                    SessionId = sessionId
                };
                var result = await userManager.CreateAsync(user, RModel.Password); if (result.Succeeded)
                {
                    // Sign the user in and set a cookie/session
                    await signInManager.SignInAsync(user, false);

                    // Store session id in server-side session as well
                    HttpContext.Session.SetString("SessionId", sessionId);

                    return RedirectToPage("Index");
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

            }
            return Page();
        }

    }
}
