using IdentityModel;
using IdentityServer4.Models;
using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer4.Test;

namespace Authentication
{
    public class Config
    {
        public static IEnumerable<ApiResource> GetApiResources()
        {

            var list = new List<ApiResource>
            {
                new ApiResource("api", "My api")
                {
                    Scopes = new List<string>()
                    {
                        "api"
                    }
                }
            };
            return list;
        }

        public static IEnumerable<ApiScope> GetApiScopes()
        {
            return new[]
            {
                new ApiScope(name: "api", displayName:"api backend")
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources() =>
        new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResource
            {
                Name = "role",
                UserClaims = new List<string>{"role"}
            }
        };
    }
}
