using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace WebApplication1.Model
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [DataType(DataType.Text)]
        public string FirstName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string LastName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string BillingAddress { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string ShippingAddress { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        public string CreditCard { get; set; }

        [Required]
        [DataType(DataType.PhoneNumber)]
        public string PhoneNumber { get; set; }

        // Session tracking: store current active session id (GUID). Updated on login.
        public string? SessionId { get; set; }
    }
}
