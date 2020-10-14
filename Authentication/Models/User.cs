using Newtonsoft.Json;
using System.Collections.Generic;
using System.Security.Claims;

namespace Authentication.Models
{
	public class User : ClaimsPrincipal
	{
		public string UserName { get; set; }
        public int? SessionId { get; set; }
		public int? UserId { get; set; }
		public string Login { get; set; }
		public IEnumerable<Role> Roles { get; set; }
	}
}
