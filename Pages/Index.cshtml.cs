using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtector _protector;
        private readonly IConfiguration _config;

        public IndexModel(
            ILogger<IndexModel> logger,
            UserManager<ApplicationUser> userManager,
            IDataProtectionProvider dataProtectionProvider,
            IConfiguration config)
        {
            _logger = logger;
            _userManager = userManager;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.UserData");
            _config = config;
        }

        public bool IsAuthenticated { get; private set; }
        public string Email { get; private set; } = string.Empty;
        public string FirstName { get; private set; } = string.Empty;
        public string LastName { get; private set; } = string.Empty;
        public string BillingAddress { get; private set; } = string.Empty;
        public string ShippingAddress { get; private set; } = string.Empty;
        public string CreditCard { get; private set; } = string.Empty;
        public string PhoneNumber { get; private set; } = string.Empty;
        public string? PhotoPath { get; private set; }

        // Password expiry properties
        public bool IsPasswordExpiringSoon { get; private set; }
        public double MinutesRemaining { get; private set; }
        public double ExpiryPercentage { get; private set; }
        public string ExpiryMessage { get; private set; } = string.Empty;
        public string ExpiryColor { get; private set; } = string.Empty;

        public async Task OnGetAsync()
        {
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false;
            if (!IsAuthenticated) return;

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return;

            Email = user.Email ?? string.Empty;
            PhoneNumber = user.PhoneNumber ?? string.Empty;
            PhotoPath = user.PhotoPath;

            // Decrypt protected fields - SHOW FULL CREDIT CARD
            try
            {
                FirstName = TryUnprotect(user.FirstName);
                LastName = TryUnprotect(user.LastName);
                BillingAddress = TryUnprotect(user.BillingAddress);
                ShippingAddress = TryUnprotect(user.ShippingAddress);
                CreditCard = TryUnprotect(user.CreditCard); // FULL credit card number
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to unprotect some user data for user {UserId}", user.Id);
                FirstName = user.FirstName ?? string.Empty;
                LastName = user.LastName ?? string.Empty;
                BillingAddress = user.BillingAddress ?? string.Empty;
                ShippingAddress = user.ShippingAddress ?? string.Empty;
                CreditCard = user.CreditCard ?? string.Empty; // Fallback to encrypted if unprotect fails
            }

            // Check password expiry
            if (user.LastPasswordChangedAt.HasValue)
            {
                var maxAgeMinutes = _config.GetValue<int?>("PasswordPolicy:MaxPasswordAgeMinutes") ?? 2;
                var timeSinceChange = DateTime.UtcNow - user.LastPasswordChangedAt.Value;
                var minutesRemaining = maxAgeMinutes - timeSinceChange.TotalMinutes;

                MinutesRemaining = Math.Max(0, Math.Round(minutesRemaining, 1));
                ExpiryPercentage = (MinutesRemaining / maxAgeMinutes) * 100;

                // Set warning if less than 1 minute remaining
                if (timeSinceChange.TotalMinutes >= maxAgeMinutes)
                {
                    IsPasswordExpiringSoon = true;
                    ExpiryMessage = "?? PASSWORD EXPIRED - Please change your password now!";
                    ExpiryColor = "danger";
                }
                else if (minutesRemaining <= 1)
                {
                    IsPasswordExpiringSoon = true;
                    ExpiryMessage = $"?? Password expires in {MinutesRemaining} minutes - Change now!";
                    ExpiryColor = "warning";
                }
                else if (minutesRemaining <= 2)
                {
                    IsPasswordExpiringSoon = true;
                    ExpiryMessage = $"?? Password will expire in {MinutesRemaining} minutes";
                    ExpiryColor = "info";
                }
            }
        }

        private string TryUnprotect(string protectedOrPlain)
        {
            if (string.IsNullOrEmpty(protectedOrPlain)) return string.Empty;
            try
            {
                return _protector.Unprotect(protectedOrPlain);
            }
            catch
            {
                return protectedOrPlain;
            }
        }
    }
}