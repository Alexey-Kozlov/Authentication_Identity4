using System;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Authentication.Repositories;
using Client = IdentityServer4.Models.Client;
using System.Linq;
using System.Collections.Generic;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;
using IdentityServer4;

namespace Authentication.IdentitySettings
{
	public class ClientsStore : IClientStore
	{
		private readonly IUserRepository _userRepository;
		private readonly ServiceUrls _serviceUrls;
		private const int AbsoluteRefreshTokenLifetimeDefault = 2592000;

		public ClientsStore(IUserRepository userRepository, IOptions<ServiceUrls> serviceUrls)
		{
			_userRepository = userRepository;
			_serviceUrls = serviceUrls.Value;
		}

		public  Task<Client> FindClientByIdAsync(string clientId)
		{


			List<Client> clients = new List<Client>
			{
				new Client
				{
					ClientId = "Test",
					ClientName = "Client for authentication",
					AccessTokenLifetime = 3600,
					AllowAccessTokensViaBrowser = true,
					AlwaysIncludeUserClaimsInIdToken = true,
					AbsoluteRefreshTokenLifetime = AbsoluteRefreshTokenLifetimeDefault,
					SlidingRefreshTokenLifetime = 600,
					ClientSecrets = { new Secret("Test".Sha256()) },
					AllowedGrantTypes = { GrantType.AuthorizationCode } ,
					RedirectUris = { $"{_serviceUrls.DefaultRedirectUri}/signin-oidc", "http://localhost:56120/signin-oidc" },
					AllowPlainTextPkce = false,
					RequirePkce = true,
					PostLogoutRedirectUris = { $"{_serviceUrls.DefaultRedirectUri}/signout-callback-oidc" },
					AllowedScopes =
					{
						IdentityServer4.IdentityServerConstants.StandardScopes.OpenId,
						IdentityServer4.IdentityServerConstants.StandardScopes.Profile,
						"api"
					},
					AllowedCorsOrigins = { $"{_serviceUrls.AuthorityApiEndpoint}", $"{_serviceUrls.DefaultRedirectUri}" }
				}

				//new Client
				//{
				//	ClientId = "Test_jwt",
				//	ClientName = "Client for authentication by jwt",
				//	ClientSecrets =
				//	{
				//		new Secret
				//		{
				//			Type = IdentityServerConstants.SecretTypes.X509CertificateBase64,
				//			Value = Convert.ToBase64String(new X509Certificate2("MyBase64.cer").GetRawCertData())
				//		}
				//	},
				//	AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
				//	RedirectUris = {$"https://ws-pc-70:5005/home/index" },
				//	AllowedScopes = { "api" },
				//	Claims = { new ClientClaim("myClaim","+100555") },
				//	ClientClaimsPrefix = ""
				//}
			};
			var clnt = clients.Where(p => p.ClientId == clientId).FirstOrDefault();
			return Task.FromResult(clnt);
			
		}
	}
}
