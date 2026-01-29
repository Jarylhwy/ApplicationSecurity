using Microsoft.AspNetCore.Identity;
using WebApplication1.Model;
using WebApplication1.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Week 14 
builder.Services.AddDataProtection();

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddDbContext<AuthDbContext>();
// Configure Identity with lockout settings
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<AuthDbContext>();

// Session and in-memory cache for session state
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // server-side session timeout
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Enable session before authentication so session is available during auth checks
app.UseSession();

app.UseAuthentication();

// Session validation to detect multiple logins
app.UseMiddleware<SessionValidationMiddleware>();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
