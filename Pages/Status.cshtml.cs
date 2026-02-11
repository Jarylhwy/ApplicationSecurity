using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages
{
    public class StatusModel : PageModel
    {
        public int StatusCode { get; private set; }

        public void OnGet(int code)
        {
            StatusCode = code;
        }
    }
}
