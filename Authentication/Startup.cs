using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using Authentication.IdentitySettings;
using Authentication.Repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;

namespace Authentication
{
    public class Startup
    {
        private IConfiguration Configuration { get; }
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        }
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IConfiguration>(Configuration);
            var authoritySettings = Configuration.GetSection("AuthoritySettings").Get<AuthoritySettings>() ??
                        throw new ArgumentNullException(
                            "AuthoritySettings section is empty, invalid, or not present");
            services.AddScoped<IUserRepository, UserRepository>();
            // .AddScoped<AuthoritySettings>(settings => authoritySettings);
            services.Configure<AuthoritySettings>(Configuration.GetSection("AuthoritySettings"));

            services.AddIdentityServer(options =>
            {
                //options.Endpoints = new IdentityServer4.Configuration.EndpointsOptions
                //{
                //    EnableAuthorizeEndpoint = true,
                //    EnableCheckSessionEndpoint = true,
                //    EnableEndSessionEndpoint = true,
                //    EnableUserInfoEndpoint = true,
                //    EnableDiscoveryEndpoint = true
                //    //EnableIntrospectionEndpoint = false,
                //    //EnableTokenEndpoint = false,
                //    //EnableTokenRevocationEndpoint = false
                //};
                
            })
                //.AddDeveloperSigningCredential()
                .AddSigningCredential(CertificateLoader.LoadFromStoreCert("Ws-PC-70", "Root", StoreLocation.LocalMachine, false))
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryApiScopes(Config.GetApiScopes())
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddResourceOwnerValidator<ResourceOwnerPasswordValidator>()
                .AddProfileService<ProfileService>()
                .AddClientStore<ClientsStore>();

            //services.ConfigureExternalCookie(options =>
            //{
            //    options.Cookie.IsEssential = true;
            //    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
            //});

            //services.ConfigureApplicationCookie(options =>
            //{
            //    options.Cookie.IsEssential = true;
            //    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
            //});

            services.AddAuthentication()
                .AddJwtBearer(jwt =>
               {
                   jwt.Authority = authoritySettings.AuthorityApiEndpoint;
                   jwt.TokenValidationParameters.ValidateAudience = true;
                   jwt.SaveToken = true;
               });
                //.AddCookie(IdentityConstants.ApplicationScheme, options =>
                //{
                //    options.SlidingExpiration = true;
                //});
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder
                        .WithOrigins(new[] {"https://ws-pc-70:5001" })
                        .WithHeaders("*")
                        .WithMethods("*")
                        .AllowCredentials());
            });
            services.AddRazorPages();
            services.AddSingleton<IActionContextAccessor, ActionContextAccessor>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseHttpsRedirection();
            app.UseCors("CorsPolicy");
            app.UseIdentityServer();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseCookiePolicy(new CookiePolicyOptions { MinimumSameSitePolicy = Microsoft.AspNetCore.Http.SameSiteMode.Lax });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
