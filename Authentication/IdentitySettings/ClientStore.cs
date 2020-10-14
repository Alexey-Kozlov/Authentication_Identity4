using System;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Authentication.Repositories;
using Client = IdentityServer4.Models.Client;

namespace Authentication.IdentitySettings
{
	public class ClientsStore : IClientStore
	{
		private readonly IUserRepository _userRepository;
		private const int AbsoluteRefreshTokenLifetimeDefault = 2592000;

		public ClientsStore(IUserRepository userRepository)
		{
			_userRepository = userRepository;
		}

		public async Task<Client> FindClientByIdAsync(string clientId)
		{
			
			var secret = await _userRepository.GetClientSecretAsync(clientId);
			if(!secret.IsSuccess)
            {
				throw new Exception(secret.UserMessage);
            }

			var cl = new Client
			{
				//ClientId = clientId,
				ClientId = "Test",
				ClientName = "Client for authentication",
				AccessTokenLifetime = 3600,
				AllowAccessTokensViaBrowser = true,
				AlwaysIncludeUserClaimsInIdToken = true,
				//RefreshTokenExpiration = 0,
				//RefreshTokenUsage = 0,
				AbsoluteRefreshTokenLifetime = AbsoluteRefreshTokenLifetimeDefault,
				SlidingRefreshTokenLifetime = 600,
				//ClientSecrets = { new Secret(secret.Entity.ToString().Sha256()) },

				ClientSecrets = { new Secret("Test".Sha256()) },
				AllowedGrantTypes = {  GrantType.ResourceOwnerPassword, GrantType.ClientCredentials, GrantType.AuthorizationCode } ,//.ResourceOwnerPasswordAndClientCredentials,
				//AllowedGrantTypes = GrantTypes.Implicit,
				RedirectUris = { "https://ws-pc-70:5005/signin-oidc" },		
				AllowPlainTextPkce = false,
				RequirePkce = true,
				AllowedScopes =
				{
					IdentityServer4.IdentityServerConstants.StandardScopes.OpenId,
					IdentityServer4.IdentityServerConstants.StandardScopes.Profile,
					"api"
				},
				PostLogoutRedirectUris = { "https://ws-pc-70:5005/home/logout" },
				//PostLogoutRedirectUris = { "https://localhost:5005/signout-callback-oidc" },
				AllowedCorsOrigins = { "http://localhost:5554", "https://ws-pc-70:5005" }
				
				
			};
			return cl;
		}
	}
}
