using System.Text.RegularExpressions;

namespace WebApplication1.Utilities
{
    public static class InputSanitizer
    {
        // Very small, conservative sanitizer: removes <script> blocks and strips all HTML tags.
        // This is a pragmatic server-side sanitizer for common stored-XSS attack vectors.
        public static string Sanitize(string? input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;

            // Remove script tags and their content
            var noScript = Regex.Replace(input, @"(?is)<script.*?>.*?</script>", string.Empty);

            // Remove any on* attributes (e.g., onclick) - handle both double- and single-quoted attribute values
            noScript = Regex.Replace(noScript, @"(?i)on\w+\s*=\s*(""[^""]*""|'[^'']*')", string.Empty);

            // Strip all remaining HTML tags
            var stripped = Regex.Replace(noScript, @"<.*?>", string.Empty);

            // Normalize whitespace
            stripped = Regex.Replace(stripped, @"[\r\n\t]+", " ");
            stripped = Regex.Replace(stripped, @"\s{2,}", " ").Trim();

            return stripped;
        }
    }
}
