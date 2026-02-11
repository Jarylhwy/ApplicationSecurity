using System;

namespace WebApplication1.Model
{
    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string HashedPassword { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
}
