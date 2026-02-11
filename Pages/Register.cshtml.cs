using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using WebApplication1.ViewModels;
using WebApplication1.Services;
using WebApplication1.Validations;
using System.IO;
using System.Text.RegularExpressions;
using WebApplication1.Utilities;
using System.Text.Encodings.Web;
using Microsoft.EntityFrameworkCore;

namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private UserManager<ApplicationUser> userManager { get; }
        private SignInManager<ApplicationUser> signInManager { get; }
        private readonly IDataProtector _protector;
        private readonly RecaptchaService _recaptcha;
        private readonly IWebHostEnvironment _environment;
        private readonly AuthDbContext _db;

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(UserManager<ApplicationUser> userManager,
                           SignInManager<ApplicationUser> signInManager,
                           IDataProtectionProvider dataProtectionProvider,
                           RecaptchaService recaptcha,
                           IWebHostEnvironment environment,
                           AuthDbContext db)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.UserData");
            _recaptcha = recaptcha;
            _environment = environment;
            _db = db;
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

            // Basic server-side normalization
            if (RModel != null)
            {
                RModel.Email = RModel.Email?.Trim();

                // Sanitize inputs to remove HTML/script tags but keep readable text
                RModel.FirstName = InputSanitizer.Sanitize(RModel.FirstName?.Trim());
                RModel.LastName = InputSanitizer.Sanitize(RModel.LastName?.Trim());

                RModel.BillingAddress = InputSanitizer.Sanitize(RModel.BillingAddress?.Trim());
                RModel.ShippingAddress = InputSanitizer.Sanitize(RModel.ShippingAddress?.Trim());

                RModel.PhoneNumber = RModel.PhoneNumber?.Trim();
                RModel.CreditCard = RModel.CreditCard?.Replace(" ", "").Trim();
            }

            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Additional server-side validation
            if (!string.IsNullOrEmpty(RModel?.PhoneNumber) && !IsValidPhone(RModel.PhoneNumber))
            {
                ModelState.AddModelError("RModel.PhoneNumber", "Please enter a valid phone number (e.g. +6512345678).");
                return Page();
            }

            if (!string.IsNullOrEmpty(RModel?.CreditCard) && !Regex.IsMatch(RModel.CreditCard, "^\\d{16}$"))
            {
                ModelState.AddModelError("RModel.CreditCard", "Credit card must be exactly 16 digits.");
                return Page();
            }

            if (!string.IsNullOrEmpty(RModel?.CreditCard) && !IsValidLuhn(RModel.CreditCard))
            {
                ModelState.AddModelError("RModel.CreditCard", "Credit card number is invalid.");
                return Page();
            }

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

                // Validate content type
                var allowedContentTypes = new[] { "image/jpeg", "image/jpg" };
                if (!allowedContentTypes.Contains(RModel.Photo.ContentType?.ToLowerInvariant()))
                {
                    ModelState.AddModelError("RModel.Photo", "Uploaded file content type is not valid.");
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

            // HTML-encode sanitized values before storing to DB
            var encodedFirstName = HtmlEncoder.Default.Encode(RModel.FirstName ?? string.Empty);
            var encodedLastName = HtmlEncoder.Default.Encode(RModel.LastName ?? string.Empty);
            var encodedBilling = HtmlEncoder.Default.Encode(RModel.BillingAddress ?? string.Empty);
            var encodedShipping = HtmlEncoder.Default.Encode(RModel.ShippingAddress ?? string.Empty);

            var user = new ApplicationUser()
            {
                UserName = RModel.Email,
                Email = RModel.Email,
                FirstName = encodedFirstName,
                LastName = encodedLastName,
                CreditCard = string.IsNullOrEmpty(RModel.CreditCard) ? string.Empty : _protector.Protect(RModel.CreditCard),
                BillingAddress = string.IsNullOrEmpty(encodedBilling) ? string.Empty : _protector.Protect(encodedBilling),
                ShippingAddress = string.IsNullOrEmpty(encodedShipping) ? string.Empty : _protector.Protect(encodedShipping),
                PhoneNumber = RModel.PhoneNumber ?? string.Empty,
                PhotoPath = photoFileName, // Store filename
                SessionId = sessionId
            };

            var result = await userManager.CreateAsync(user, RModel.Password);

            if (result.Succeeded)
            {
                // Store password hash in history (keep max 2 recent entries)
                var hash = userManager.PasswordHasher.HashPassword(user, RModel.Password);
                _db.PasswordHistories.Add(new PasswordHistory { UserId = user.Id, HashedPassword = hash, Timestamp = DateTime.UtcNow });

                // trim older entries to keep only last 2
                var histories = await _db.PasswordHistories.Where(p => p.UserId == user.Id).OrderByDescending(p => p.Timestamp).ToListAsync();
                if (histories.Count > 2)
                {
                    var toRemove = histories.Skip(2).ToList();
                    _db.PasswordHistories.RemoveRange(toRemove);
                }

                await _db.SaveChangesAsync();

                // Set last password change timestamp
                user.LastPasswordChangedAt = DateTime.UtcNow;
                await userManager.UpdateAsync(user);

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

            return Page();
        }

        private bool IsValidPhone(string phone)
        {
            // Basic E.164-ish validation: optional + and 7-15 digits
            if (string.IsNullOrEmpty(phone)) return false;
            return Regex.IsMatch(phone, "^\\+?\\d{7,15}$");
        }

        private bool IsValidLuhn(string number)
        {
            if (string.IsNullOrEmpty(number)) return false;
            int sum = 0;
            bool alternate = false;
            for (int i = number.Length - 1; i >= 0; i--)
            {
                char c = number[i];
                if (c < '0' || c > '9') return false;
                int n = c - '0';
                if (alternate)
                {
                    n *= 2;
                    if (n > 9) n -= 9;
                }
                sum += n;
                alternate = !alternate;
            }
            return (sum % 10 == 0);
        }
    }
}