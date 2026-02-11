using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace WebApplication1.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IConfiguration _config;

        public SmtpEmailSender(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            var smtpHost = _config["Smtp:Host"];
            var smtpPort = int.Parse(_config["Smtp:Port"] ?? "25");
            var smtpUser = _config["Smtp:Username"];
            var smtpPass = _config["Smtp:Password"];
            var from = _config["Smtp:From"] ?? "no-reply@example.com";

            using var client = new SmtpClient(smtpHost, smtpPort)
            {
                Credentials = new NetworkCredential(smtpUser, smtpPass),
                EnableSsl = true
            };

            using var msg = new MailMessage(from, to, subject, body) { IsBodyHtml = true };
            await client.SendMailAsync(msg);
        }
    }
}
