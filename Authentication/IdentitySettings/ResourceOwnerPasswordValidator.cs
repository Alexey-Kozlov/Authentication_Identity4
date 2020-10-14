using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Http;
using Authentication.Helpers;
using Authentication.Repositories;
using System.Linq;

namespace Authentication.IdentitySettings
{
	public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator
	{
		private readonly IHttpContextAccessor _httpContextAccessor;
		private readonly IUserRepository _userRepository;
		public ResourceOwnerPasswordValidator( IHttpContextAccessor httpContextAccessor, IUserRepository userRepository)
		{
			_httpContextAccessor = httpContextAccessor;
			_userRepository = userRepository;
		}

		public async Task ValidateAsync(ResourceOwnerPasswordValidationContext context)
		{
			var result_user = await _userRepository.AuthenticateAsync(0, context.UserName, context.Password);
			if (!result_user.IsSuccess)
			{
				throw new Exception(result_user.UserMessage);
			}
			var roles = await _userRepository.GetUserRoles(result_user.Entity.UserId.Value);
			try
			{
				var claims = new List<Claim>();
				if (roles.Any())
				{
					claims.AddRange(roles.Select(x => new Claim(Keywords.Roles, x.Name)));
				}
				claims.Add(new Claim(Keywords.Login, result_user.Entity.Login));
				claims.Add(new Claim(Keywords.Id, result_user.Entity.UserId.Value.ToString()));
				claims.Add(new Claim(Keywords.SessionId, result_user.Entity.SessionId.Value.ToString()));
				claims.Add(new Claim(Keywords.UserName, result_user.Entity.UserName));
				context.Result = new GrantValidationResult(result_user.Entity.Login, "password", claims);

			}
			catch (Exception e)
			{
				context.Result = new GrantValidationResult(TokenRequestErrors.InvalidGrant, $"{e.Message ?? "Пользователь не найден"}");

			}
		}

	}
}
