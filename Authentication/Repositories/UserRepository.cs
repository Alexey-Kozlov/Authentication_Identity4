using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authentication.Models;
using Microsoft.Extensions.Configuration;
using System.Data;
using System.Threading;
using AKDbHelpers.DataBaseHelpers;
using AKDbHelpers.Helpers;

namespace Authentication.Repositories
{
    public class UserRepository : BaseRepository, IUserRepository
    {
        public UserRepository(IConfiguration configuration) : base(configuration)
        {

        }

        public async Task<GenericResult<User>> AuthenticateAsync(int sessionId, string login, string password)
        {
            var cmd = Db.CreateProcedureCommand("dbo.Login");
            cmd.Parameters.AddWithValue("@Login", login);
            cmd.Parameters.AddWithValue("@Password", password);
            cmd.Parameters.AddWithValue("@SessionId", sessionId);
            cmd.Parameters.Add("@UserId", SqlDbType.Int).Direction = ParameterDirection.Output;
            cmd.Parameters.Add("@UserName", SqlDbType.NVarChar, 50).Direction = ParameterDirection.Output;
            cmd.Parameters.Add("@SessionIdNew", SqlDbType.Int).Direction = ParameterDirection.Output;
            cmd.Parameters.Add("@Error_msg", SqlDbType.NVarChar, 50).Direction = ParameterDirection.Output;

            await Db.ExecuteNonQueryAsync(cmd, CancellationToken.None);
            var errMsg = cmd.ReadOutputValue<string>("@Error_msg");
            if (!string.IsNullOrEmpty(errMsg))
            {
                return GenericResult<User>.Error(errMsg);
            }
            if(!cmd.ReadOutputValue<int?>("@UserId").HasValue)
            {
                return GenericResult<User>.Error("Ошибка логина или пароля");
            }

            var user = new User
            {
                Login = login,
                SessionId = cmd.ReadOutputValue<int?>("@SessionIdNew"),
                UserId = cmd.ReadOutputValue<int?>("@UserId"),
                UserName = cmd.ReadOutputValue<string>("@UserName")                
            };
            return GenericResult<User>.Success(user);
        }

        public async Task<GenericResult<int>> GetClientSecretAsync(string login)
        {
            var cmd = Db.CreateProcedureCommand("dbo.GetClient");
            cmd.Parameters.AddWithValue("@Login", login);
            cmd.Parameters.Add("@UserId", SqlDbType.Int).Direction = ParameterDirection.Output;
            await Db.ExecuteNonQueryAsync(cmd, CancellationToken.None);
            if (!cmd.ReadOutputValue<int?>("@UserId").HasValue)
            {
                return GenericResult<int>.Error("Пользователь не найден");
            }
            return GenericResult<int>.Success(cmd.ReadOutputValue<int?>("@UserId").Value);
        }

        public async Task<IEnumerable<Role>> GetUserRoles(int userId)
        {
            var cmd = Db.CreateProcedureCommand("dbo.GetUserRoles");
            cmd.Parameters.AddWithValue("@UserId", userId);
            var roles = await Db.ExecuteReaderAsync(ds =>
                new Role
                {
                    Id = ds.GetValue<int>("Id"),
                    Name = ds.GetValue<string>("Name")                    
                }, cmd, CancellationToken.None);
            return roles;
        }
    }
}
