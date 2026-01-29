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

        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager, IDataProtectionProvider dataProtectionProvider)
        {
            _logger = logger;
            _userManager = userManager;
            _protector = dataProtectionProvider.CreateProtector("BookwormsOnline.UserData");
        }

        public bool IsAuthenticated { get; private set; }
        public string Email { get; private set; } = string.Empty;
        public string FirstName { get; private set; } = string.Empty;
        public string LastName { get; private set; } = string.Empty;
        public string BillingAddress { get; private set; } = string.Empty;
        public string ShippingAddress { get; private set; } = string.Empty;
        public string CreditCard { get; private set; } = string.Empty;
        public string PhoneNumber { get; private set; } = string.Empty;

        public async Task OnGetAsync()
        {
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false;
            if (!IsAuthenticated) return;

            var user = await _userManager.GetUserAsync(User);
            if (user == null) return;

            Email = user.Email ?? string.Empty;
            PhoneNumber = user.PhoneNumber ?? string.Empty;
            // Decrypt protected fields. If unprotect fails, fall back to raw value.
            try
            {
                FirstName = TryUnprotect(user.FirstName);
                LastName = TryUnprotect(user.LastName);
                BillingAddress = TryUnprotect(user.BillingAddress);
                ShippingAddress = TryUnprotect(user.ShippingAddress);
                CreditCard = TryUnprotect(user.CreditCard);
            }
            catch (Exception ex)
            {
                // Log and fallback to stored values
                _logger.LogWarning(ex, "Failed to unprotect some user data for user {UserId}", user.Id);
                FirstName = user.FirstName ?? string.Empty;
                LastName = user.LastName ?? string.Empty;
                BillingAddress = user.BillingAddress ?? string.Empty;
                ShippingAddress = user.ShippingAddress ?? string.Empty;
                CreditCard = user.CreditCard ?? string.Empty;
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
                // If it isn't protected or unprotect fails, return the original
                return protectedOrPlain;
            }
        }
    }
}
