using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Middleware;
using WebApplication1.Model;
using WebApplication1.Services;

var builder = WebApplication.CreateBuilder(args);

// Week 14 
builder.Services.AddDataProtection();

// Add services to the container.
builder.Services.AddRazorPages(options =>
{
    // Validate antiforgery tokens for unsafe methods (POST/PUT/DELETE)
    options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());
});

builder.Services.AddDbContext<AuthDbContext>();
// Configure Identity with lockout settings (make minutes configurable via appsettings)
var lockoutMinutes = builder.Configuration.GetValue<int?>("Identity:LockoutMinutes") ?? 1;
var maxFailedAttempts = builder.Configuration.GetValue<int?>("Identity:MaxFailedAccessAttempts") ?? 3;

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(lockoutMinutes);
    options.Lockout.MaxFailedAccessAttempts = maxFailedAttempts;
    options.Lockout.AllowedForNewUsers = true;

    // Allow using 2FA providers
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
    options.Tokens.EmailConfirmationTokenProvider = "Email"; // THIS WAS MISSING
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders()
// register an explicit email token provider named "Email" to be used for 2FA via email
.AddTokenProvider<EmailTokenProvider<ApplicationUser>>("Email");

// Configure token lifespans (useful for password reset and authenticator tokens)
builder.Services.Configure<DataProtectionTokenProviderOptions>(opt =>
{
    opt.TokenLifespan = TimeSpan.FromMinutes(10);
});

// Recaptcha service
builder.Services.AddHttpClient<RecaptchaService>();

// Register email sender (SMTP) - configuration must be present in appsettings
builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();

// Session and in-memory cache for session state
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Bind recaptcha config section (user should set Recaptcha:Secret in appsettings)
builder.Configuration.GetSection("Recaptcha");

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
else
{
    // In development show detailed errors
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Enable session before authentication so session is available during auth checks
app.UseSession();

app.UseAuthentication();

// Add password expiration middleware
app.UseMiddleware<PasswordExpirationMiddleware>();

// Session validation to detect multiple logins
app.UseMiddleware<SessionValidationMiddleware>();

app.UseAuthorization();

// Handle status codes (404/403/etc.) with a friendly page
app.UseStatusCodePagesWithReExecute("/Status", "?code={0}");

app.MapRazorPages();

app.Run();