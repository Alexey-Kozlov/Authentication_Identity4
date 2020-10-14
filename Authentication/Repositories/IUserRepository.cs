using System.Collections.Generic;
using Authentication.Models;
using AKDbHelpers.Helpers;
using System.Threading.Tasks;

namespace Authentication.Repositories
{
    public interface IUserRepository : IRepository
    {
        Task<GenericResult<User>> AuthenticateAsync(int sessionId, string login, string password);
        Task<GenericResult<int>> GetClientSecretAsync(string login);
        Task<IEnumerable<Role>> GetUserRoles(int userId);
    }
}
