using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;
using System.Text;
using System.Text.Encodings.Web;

namespace WebApplication1.Pages.Account
{
    [Authorize]
    public class Manage2FAModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IWebHostEnvironment _environment;

        public Manage2FAModel(UserManager<ApplicationUser> userManager,
                            SignInManager<ApplicationUser> signInManager,
                            IWebHostEnvironment environment)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _environment = environment;
        }

        public bool Is2faEnabled { get; set; }
        public bool HasAuthenticator { get; set; }
        public string? SharedKey { get; set; }
        public string? QrCodeImage { get; set; }
        [BindProperty]
        public string? Code { get; set; }
        public string? StatusMessage { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Account/Login");

            Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            HasAuthenticator = !string.IsNullOrEmpty(key);

            if (!HasAuthenticator)
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
                HasAuthenticator = !string.IsNullOrEmpty(key);
            }

            SharedKey = FormatKey(key);

            if (!string.IsNullOrEmpty(key))
            {
                var authenticatorUri = GenerateQrCodeUri(user.Email, key);
                QrCodeImage = GenerateQrCodeBase64(authenticatorUri);
            }

            return Page();
        }

        public async Task<IActionResult> OnPostResetAuthenticatorAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Account/Login");

            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);

            StatusMessage = "Authenticator key has been reset. Configure your authenticator app with the new key.";
            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostVerifyAuthenticatorAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Account/Login");

            if (string.IsNullOrEmpty(Code))
            {
                ModelState.AddModelError("", "Code is required.");
                return await OnGetAsync();
            }

            var valid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, Code.Replace(" ", ""));
            if (!valid)
            {
                ModelState.AddModelError("", "Invalid code.");
                return await OnGetAsync();
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);

            // Generate recovery codes but don't display them
            await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

            StatusMessage = "Authenticator app verified. Two-factor authentication is now enabled.";

            await _signInManager.SignInAsync(user, isPersistent: false);

            return RedirectToPage();
        }

        public async Task<IActionResult> OnPostDisable2faAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return RedirectToPage("/Account/Login");

            await _userManager.SetTwoFactorEnabledAsync(user, false);

            StatusMessage = "Two-factor authentication has been disabled.";
            return RedirectToPage();
        }

        private static string FormatKey(string? unformattedKey)
        {
            if (string.IsNullOrEmpty(unformattedKey)) return string.Empty;
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(' ');
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }
            return result.ToString().ToLowerInvariant();
        }

        private static string GenerateQrCodeUri(string email, string? unformattedKey)
        {
            var issuer = "WebApplication1";
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={unformattedKey}&issuer={Uri.EscapeDataString(issuer)}&digits=6";
        }

        private string GenerateQrCodeBase64(string authenticatorUri)
        {
            try
            {
                using (var qrGenerator = new QRCoder.QRCodeGenerator())
                {
                    var qrCodeData = qrGenerator.CreateQrCode(authenticatorUri, QRCoder.QRCodeGenerator.ECCLevel.Q);
                    using (var qrCode = new QRCoder.PngByteQRCode(qrCodeData))
                    {
                        var qrCodeBytes = qrCode.GetGraphic(20);
                        return $"data:image/png;base64,{Convert.ToBase64String(qrCodeBytes)}";
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}