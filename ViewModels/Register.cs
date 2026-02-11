using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using WebApplication1.Validations;

namespace WebApplication1.ViewModels
{
    public class Register
    {
        [Required]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [RegularExpression("^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).*$",
            ErrorMessage = "Password must be at least 12 characters and include upper-case, lower-case, number and special character.")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
        public string ConfirmPassword { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string FirstName { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string LastName { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        public string CreditCard { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string BillingAddress { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string ShippingAddress { get; set; }

        [Required]
        [DataType(DataType.PhoneNumber)]
        public string PhoneNumber { get; set; }

        // Photo upload - for Bookworms Online (similar to Fresh Farm Market)
        [Required(ErrorMessage = "Please upload a profile photo")]
        [DataType(DataType.Upload)]
        [AllowedExtensions(new[] { ".jpg", ".jpeg" }, ErrorMessage = "Only JPG images are allowed.")]
        [MaxFileSize(5 * 1024 * 1024, ErrorMessage = "Maximum file size is 5MB.")]
        public IFormFile Photo { get; set; }
    }
}