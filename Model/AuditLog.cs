using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Model
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Action { get; set; }
        public DateTime Timestamp { get; set; }
        public string? Details { get; set; }
    }
}
