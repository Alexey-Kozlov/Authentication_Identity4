using Authentication.Models;
using System;
using Authentication.Models.Account;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Net.Http;
using System.Linq;
using Authentication.IdentitySettings;
using System.Threading.Tasks;
using Authentication.Repositories;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using IdentityServer4;
using System.Security.Claims;
using Authentication.Helpers;

namespace Authentication.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IEventService _events;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IUserRepository _userRepository;
        private readonly ServiceUrls _serviceUrls;
        private readonly IActionContextAccessor _accessor;
        private readonly IAuthenticationSchemeProvider _schemeProvider;

        public AccountController(IEventService events,
            IIdentityServerInteractionService interaction,
            IOptions<ServiceUrls> serviceUrls,
            IUserRepository userRepository,
            IActionContextAccessor accessor,
            IAuthenticationSchemeProvider schemeProvider)
        {
            _events = events;
            _interaction = interaction;
            _userRepository = userRepository;
            _serviceUrls = serviceUrls.Value;
            _accessor = accessor;
            _schemeProvider = schemeProvider;
        }

        [HttpGet]
        [ProducesResponseType(typeof(LoginViewModel), 200)]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var vm = await BuildLoginViewModelAsync(returnUrl);
            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
            }
            return View(vm);
        }

        [HttpGet("Test")]
        public async Task<IActionResult> SignIn(string login, string password)
        {
            if (!string.IsNullOrEmpty(login))
            {
                var result_user = await _userRepository.AuthenticateAsync(0, login, password);
                if (!result_user.IsSuccess)
                {
                    return BadRequest(result_user.UserMessage);
                }


                return Ok(result_user.Entity.UserId);
            }
            HttpClient httpClient2 = new HttpClient();
            var response = Task.Run(async () => await httpClient2.GetAsync("http://ws-pc-70:5005/test2"));
            var ss = response.Result;
            var ww = Task.Run(async () => await ss.Content.ReadAsStringAsync());
            var kk = ww.Result;
            return Ok(kk);

            //HttpClient httpClient = new HttpClient();
            //var task =  await httpClient.GetDiscoveryDocumentAsync(_authoritySettings.AuthorityApiEndpoint);
            //DiscoveryDocumentResponse discoveryDocument = task;
            //var task2 = Task.Run(async () => await httpClient.RequestPasswordTokenAsync(new PasswordTokenRequest
            //{
            //    Address = discoveryDocument.TokenEndpoint,
            //    ClientId = result_user.Entity.Login,
            //    ClientSecret = result_user.Entity.UserId.ToString(),
            //    GrantType = "password",
            //    Password = password,
            //    UserName = result_user.Entity.Login
            //    //Scope = "api"
            //}));
            //HttpClient httpClient2 = new HttpClient();
            //var resp = task2.Result;

            //return Redirect("http://localhost:5000/home/index");

            //httpClient2.SetBearerToken(resp.AccessToken);
            
            //var response = Task.Run(async () => await httpClient2.GetAsync("http://localhost:5554/identity"));
            //var ss = response.Result;
            //var ww = Task.Run(async () => await ss.Content.ReadAsStringAsync());
            //var kk = ww.Result;


            //var result = new RedirectResult("http://localhost:5000", true);
            //result.UrlHelper = new UrlHelper(_accessor.ActionContext);

            //result.UrlHelper.ActionContext.HttpContext.Response.Headers.Add("Accept", "application/json");
            //result.UrlHelper.ActionContext.HttpContext.Response.Headers.Add("Authorization", "Bearer " + resp.AccessToken);
            //return result;
            //return new RedirectToPageResult("http://localhost:5000");
        }



        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (button != "login")
            {
                // the user clicked the "cancel" button
                return Redirect(model.ReturnUrl);                
            }

            if (ModelState.IsValid)
            {
                var result_user = await _userRepository.AuthenticateAsync(0, model.Username, model.Password);
                if (!result_user.IsSuccess)
                {
                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId: context?.Client.ClientId));
                    ModelState.AddModelError(string.Empty, result_user.UserMessage);
                    return View(await BuildLoginViewModelAsync(model.ReturnUrl));
                }

                await _events.RaiseAsync(new UserLoginSuccessEvent(result_user.Entity.UserName, result_user.Entity.Login,
                        result_user.Entity.UserName, clientId: context?.Client.ClientId));

                AuthenticationProperties props = null;
                if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                {
                    props = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration),                            
                    };
                };

                var isuser = new IdentityServerUser(result_user.Entity.Login)
                {
                    DisplayName = result_user.Entity.UserName,
                    AdditionalClaims =
                        {
                            new Claim(Keywords.SessionId, result_user.Entity.SessionId.Value.ToString()),
                            new Claim(Keywords.Login, result_user.Entity.Login),
                            new Claim(Keywords.UserName, result_user.Entity.UserName),
                        }
                };
                var roles = await _userRepository.GetUserRoles(result_user.Entity.UserId.Value);
                foreach (Role roleName in roles)
                {
                    isuser.AdditionalClaims.Add(new Claim(Keywords.Roles, roleName.Name));
                }

                await HttpContext.SignInAsync(isuser, props);

                if (context != null)
                {
                    return Redirect(model.ReturnUrl);
                }

                if (Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }
                else if (string.IsNullOrEmpty(model.ReturnUrl))
                {
                    return Redirect("~/");
                }
                else
                {
                    throw new Exception("invalid return URL");
                }
            }

            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }
        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            if (User.HasClaim(p=>p.Type == Keywords.SubjectId))
                vm.LogoutId = User.GetSubjectId();            
            return vm;
        }
        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId).ConfigureAwait(false);

            if (User?.Identity.IsAuthenticated == true)
            {
                await HttpContext.SignOutAsync().ConfigureAwait(false);
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
                HttpContext.User = new System.Security.Claims.ClaimsPrincipal(new ClaimsIdentity());
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            //var logout1 = User.GetSubjectId();
            //var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = $"{_serviceUrls.DefaultRedirectUri}/home/index",
                ClientName = "Test",
                SignOutIframeUrl = $"{_serviceUrls.DefaultRedirectUri}/home/logout",
                LogoutId = User.HasClaim(p => p.Type == Keywords.SubjectId)? User.GetSubjectId() : ""
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }


        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();


            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }


        private string GetReturnUrl(string clientId, string returnUrl)
        {
            if (clientId == null)
            {
                return _serviceUrls.DefaultRedirectUri;
            }
            return returnUrl;
        }
    }
}
