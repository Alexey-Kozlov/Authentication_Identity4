using System.Collections.Generic;
using System.Security.Claims;

namespace Authentication.Models
{
	public class TokenIdentity : ClaimsIdentity
	{
		/// <summary>
		/// 
		/// </summary>
		/// <param name="sessionId"></param>
		/// <param name="userName"></param>
		/// <param name="token"></param>
		/// <param name="claims"></param>
		public TokenIdentity(int sessionId, string userName, string login, string ipAddress, IEnumerable<Claim> claims)
			: base(claims, "token")
		{
			SessionId = sessionId;
			UserName = userName;
			Login = login;
			ClientIpAddress = ipAddress;
		}

		public int SessionId { get; }
		public string UserName { get; }
		public string ClientIpAddress { get; }
		public string Login { get; }
	}
}
