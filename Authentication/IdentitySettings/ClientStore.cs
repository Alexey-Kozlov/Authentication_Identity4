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
		private readonly AuthoritySettings _authoritySettings;
		private const int AbsoluteRefreshTokenLifetimeDefault = 2592000;

		public ClientsStore(IUserRepository userRepository, IOptions<AuthoritySettings> authoritySettings)
		{
			_userRepository = userRepository;
			_authoritySettings = authoritySettings.Value;
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
					AllowedGrantTypes = { GrantType.ResourceOwnerPassword, GrantType.ClientCredentials, GrantType.AuthorizationCode } ,
					RedirectUris = { $"{_authoritySettings.DefaultRedirectUri}/signin-oidc", "http://localhost:56120/signin-oidc" },
					AllowPlainTextPkce = false,
					RequirePkce = true,
					PostLogoutRedirectUris = { $"{_authoritySettings.DefaultRedirectUri}/signout-callback-oidc" },
					AllowedScopes =
					{
						IdentityServer4.IdentityServerConstants.StandardScopes.OpenId,
						IdentityServer4.IdentityServerConstants.StandardScopes.Profile,
						"api"
					},
					AllowedCorsOrigins = { $"{_authoritySettings.AuthorityApiEndpoint}", $"{_authoritySettings.DefaultRedirectUri}" }
				},

				new Client
				{
					ClientId = "Test_jwt",
					ClientName = "Client for authentication by jwt",
					ClientSecrets =
					{
						new Secret
						{
							Type = IdentityServerConstants.SecretTypes.X509CertificateBase64,
							Value = Convert.ToBase64String(new X509Certificate2(@"C:\Certificates\WsCert.pfx").GetRawCertData())
						}
					},
					AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
					RedirectUris = {$"https://ws-pc-70:5005/signin-oidc" },
					AllowedScopes = { "openid","profile","api" }
				}
			};
			return Task.FromResult(clients.Where(p => p.ClientId == clientId).FirstOrDefault());


			//var secret = await _userRepository.GetClientSecretAsync(clientId);
			//if(!secret.IsSuccess)
   //         {
			//	throw new Exception(secret.UserMessage);
   //         }

			//var cl = new Client
			//{
			//	//ClientId = clientId,
			//	ClientId = "Test",
			//	ClientName = "Client for authentication",
			//	AccessTokenLifetime = 3600,
			//	AllowAccessTokensViaBrowser = true,
			//	AlwaysIncludeUserClaimsInIdToken = true,
			//	//RefreshTokenExpiration = 0,
			//	//RefreshTokenUsage = 0,
			//	AbsoluteRefreshTokenLifetime = AbsoluteRefreshTokenLifetimeDefault,
			//	SlidingRefreshTokenLifetime = 600,
			//	//ClientSecrets = { new Secret(secret.Entity.ToString().Sha256()) },

			//	ClientSecrets = { new Secret("Test".Sha256()) },
			//	AllowedGrantTypes = {  GrantType.ResourceOwnerPassword, GrantType.ClientCredentials, GrantType.AuthorizationCode } ,//.ResourceOwnerPasswordAndClientCredentials,
			//	//AllowedGrantTypes = GrantTypes.Implicit,
			//	RedirectUris = { "https://ws-pc-70:5005/signin-oidc" },		
			//	AllowPlainTextPkce = false,
			//	RequirePkce = true,
			//	AllowedScopes =
			//	{
			//		IdentityServer4.IdentityServerConstants.StandardScopes.OpenId,
			//		IdentityServer4.IdentityServerConstants.StandardScopes.Profile,
			//		"api"
			//	},
			//	PostLogoutRedirectUris = { "https://ws-pc-70:5005/home/logout" },
			//	//PostLogoutRedirectUris = { "https://localhost:5005/signout-callback-oidc" },
			//	AllowedCorsOrigins = { "http://localhost:5554", "https://ws-pc-70:5005" }
				
				
			//};
			//return cl;
		}
	}
}
