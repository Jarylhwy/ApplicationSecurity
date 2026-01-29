using System.Net.Http.Headers;
using System.Text.Json;

namespace WebApplication1.Services
{
    public class RecaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _config;

        public RecaptchaService(HttpClient httpClient, IConfiguration config)
        {
            _httpClient = httpClient;
            _config = config;
        }

        private class RecaptchaApiResponse
        {
            public bool success { get; set; }
            public float score { get; set; }
            public string action { get; set; }
            public DateTime challenge_ts { get; set; }
            public string hostname { get; set; }
            public string[] error_codes { get; set; }
        }

        public async Task<bool> ValidateAsync(string token, string expectedAction, double minimumScore = 0.5)
        {
            if (string.IsNullOrEmpty(token)) return false;

            var secret = _config["Recaptcha:Secret"];
            if (string.IsNullOrEmpty(secret))
            {
                // If secret not configured, fail closed
                return false;
            }

            var content = new FormUrlEncodedContent(new[] {
                new KeyValuePair<string, string>("secret", secret),
                new KeyValuePair<string, string>("response", token)
            });

            var res = await _httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            if (!res.IsSuccessStatusCode) return false;

            using var stream = await res.Content.ReadAsStreamAsync();
            var apiResp = await JsonSerializer.DeserializeAsync<RecaptchaApiResponse>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (apiResp == null) return false;

            if (!apiResp.success) return false;
            if (!string.Equals(apiResp.action, expectedAction, StringComparison.OrdinalIgnoreCase)) return false;
            if (apiResp.score < minimumScore) return false;

            return true;
        }
    }
}
