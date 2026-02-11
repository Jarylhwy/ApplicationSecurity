using System.Threading.Tasks;

namespace WebApplication1.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string to, string subject, string body);
    }
}
