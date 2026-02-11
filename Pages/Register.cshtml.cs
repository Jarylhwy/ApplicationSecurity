using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.ViewModels;
using WebApplication1.Services;
using WebApplication1.Validations;
using System.IO;

namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }
        private readonly IDataProtector _protector;
        private readonly RecaptchaService _recaptcha;
        private readonly IWebHostEnvironment _environment;

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<ApplicationUser> userManager,
                           SignInManager<ApplicationUser> signInManager,
                           IDataProtectionProvider dataProtectionProvider,
                           RecaptchaService recaptcha,
                           IWebHostEnvironment environment)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.UserData");
            _recaptcha = recaptcha;
            _environment = environment;
        }

        public void OnGet()
        {
        }

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
                string photoFileName = null;

                // Handle photo upload
                if (RModel.Photo != null && RModel.Photo.Length > 0)
                {
                    // Validate file extension (server-side double-check)
                    var allowedExtensions = new[] { ".jpg", ".jpeg" };
                    var extension = Path.GetExtension(RModel.Photo.FileName).ToLowerInvariant();

                    if (!allowedExtensions.Contains(extension))
                    {
                        ModelState.AddModelError("RModel.Photo", "Only JPG/JPEG files are allowed.");
                        return Page();
                    }

                    // Validate file size (server-side double-check)
                    if (RModel.Photo.Length > 5 * 1024 * 1024) // 5MB
                    {
                        ModelState.AddModelError("RModel.Photo", "File size must be less than 5MB.");
                        return Page();
                    }

                    // Create unique filename to prevent overwriting and path traversal
                    var uniqueFileName = Guid.NewGuid().ToString() + extension;

                    // Create uploads directory if it doesn't exist
                    var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads");
                    if (!Directory.Exists(uploadsFolder))
                    {
                        Directory.CreateDirectory(uploadsFolder);
                    }

                    // Secure file path
                    var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                    // Save file
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await RModel.Photo.CopyToAsync(stream);
                    }

                    photoFileName = uniqueFileName;
                }
                else
                {
                    ModelState.AddModelError("RModel.Photo", "Please upload a profile photo.");
                    return Page();
                }

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
                    PhotoPath = photoFileName, // Store filename
                    SessionId = sessionId
                };

                var result = await userManager.CreateAsync(user, RModel.Password);

                if (result.Succeeded)
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