using System;
using System.Collections.Generic;
using System.Linq;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System.Security.Claims;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Authentication.Helpers;

namespace Authentication.IdentitySettings
{
	public class ProfileService : IProfileService
	{
		public ProfileService()
		{

		}

		public virtual Task GetProfileDataAsync(ProfileDataRequestContext context)
		{
			AddIssuedClaims(context, Keywords.Login);
			AddIssuedClaims(context, Keywords.SessionId);
			AddIssuedClaims(context, Keywords.Roles);
			AddIssuedClaims(context, Keywords.Id);
			AddIssuedClaims(context, Keywords.UserName);
			return Task.CompletedTask;
		}

		public Task IsActiveAsync(IsActiveContext context)
		{
			return Task.CompletedTask;
		}

		private void AddIssuedClaims(ProfileDataRequestContext context, string claimType)
		{
			var claims = context.Subject?.Claims.Where(c => c.Type == claimType).ToList();
			if (claims != null && claims.Any())
			{
				claims.ForEach(claim => context.IssuedClaims.Add(new Claim(claimType, claim.Value)));				
			}
		}
	}
}
