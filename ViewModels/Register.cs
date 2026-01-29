using System.ComponentModel.DataAnnotations;

namespace WebApplication1.ViewModels
{
    public class Register
    {
        [Required]
        [DataType(DataType.EmailAddress)] public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [RegularExpression("^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).*$", ErrorMessage = "Password must be at least 12 characters and include upper-case, lower-case, number and special character.")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match")]
        public string ConfirmPassword { get; set; }

        //New
        [Required]
        [DataType(DataType.Text)] public string FirstName { get; set; }

        [Required]
        [DataType(DataType.Text)] public string LastName { get; set; }

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
    }

}
