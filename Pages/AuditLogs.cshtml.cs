using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Model;

namespace WebApplication1.Pages
{
    public class AuditLogsModel : PageModel
    {
        private readonly AuthDbContext _db;

        public AuditLogsModel(AuthDbContext db)
        {
            _db = db;
        }

        public List<AuditLog> Logs { get; set; } = new();

        public async Task OnGetAsync()
        {
            Logs = await _db.AuditLogs.OrderByDescending(a => a.Timestamp).Take(200).ToListAsync();
        }
    }
}
