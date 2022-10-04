using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MvcUyelikSistemi.ClaimProviders;
using MvcUyelikSistemi.CustomValidation;
using MvcUyelikSistemi.Models;
using MvcUyelikSistemi.Models.Contexts;
using MvcUyelikSistemi.Requiredments;
using MvcUyelikSistemi.TwoFactorServices;
using System;

namespace MvcUyelikSistemi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<TwoFactorOptions>(Configuration.GetSection("TwoFactorOptions"));
            services.AddScoped<TwoFactorService>();
            services.AddScoped<EmailSender>();
            services.AddScoped<SmsSender>();
            services.AddTransient<IAuthorizationHandler, ExpireDateExchangeHandler>();
            services.AddDbContext<IdentityContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnectionString"));
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("AnkaraPolicy", policy =>
                {
                    policy.RequireClaim("city", "ankara");//þehir bilgisine göre caim bazlý yetkilendirme
                });
                options.AddPolicy("ViolancePolicy", policy =>
                {
                    policy.RequireClaim("violance");//yaþ bilgisine göre claim bazlý yetkilendirme
                });
                options.AddPolicy("ExchangePolicy", policy =>
                {
                    policy.AddRequirements(new ExpireDateExchangeRequirement());//belirli bir süre içerisinde claim bazlý yetkilendirme
                });
            });

            services.AddAuthentication().AddFacebook(options =>
            {
                options.AppId = Configuration["Authentication:Facebook:AppID"];
                options.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
            }).AddGoogle(options =>
            {
                options.ClientId = Configuration["Authentication:Google:ClientID"];
                options.ClientSecret = Configuration["Authentication:Coogle:ClientSecret"];
            }).AddMicrosoftAccount(options =>
            {
                options.ClientId = Configuration["Authentication:Microsoft:ClientID"];
                options.ClientSecret = Configuration["Authentication:Microsoft:ClientSecret"];
            });


            services.AddIdentity<AppUser, AppRole>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcçdefgðhýijklmnöopqrsþtuüvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";
                options.Password.RequiredLength = 4;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireDigit = false;
            }).AddPasswordValidator<CustomPasswordValidator>()
            .AddUserValidator<CustomUserValidator>()
            .AddErrorDescriber<CustomIdentityErrorDescriber>()
            .AddEntityFrameworkStores<IdentityContext>()
            .AddDefaultTokenProviders();


            CookieBuilder cookieBuilder = new CookieBuilder();
            cookieBuilder.Name = "MyBlog";
            cookieBuilder.HttpOnly = true;//ClientSide tarafýnda kötü niyetli kiþiler ulaþamasýn diye
            cookieBuilder.SameSite = SameSiteMode.Lax;//Cookie i kaydettikten sonra sadece o site üzerinden cookie bilgileri gelsin diye(strict)
            cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = new PathString("/Home/Login");
                options.LogoutPath = new PathString("/Member/Logout");
                options.Cookie = cookieBuilder;
                options.ExpireTimeSpan = TimeSpan.FromDays(5);
                options.SlidingExpiration = true;
                options.AccessDeniedPath = new PathString("/Member/AccessDenied");
            });
            services.AddScoped<IClaimsTransformation, ClaimProvider>();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.Name = "MainSession";
            });
            services.AddRazorPages().AddRazorRuntimeCompilation();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseStatusCodePages();
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseSession();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapAreaControllerRoute(
                 name: "Admin", areaName: "Admin", pattern: "Admin/{controller=Home}/{action=Index}/{id?}");//
                endpoints.MapControllerRoute(
                    name: "User", pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapDefaultControllerRoute();//
            });
        }
    }
}
