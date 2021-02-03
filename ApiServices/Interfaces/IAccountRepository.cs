using ClassLibrary.Model.Models.DbModel;
using System.Threading.Tasks;

namespace ApiServices.Interfaces
{
    public interface IAccountRepository
    {
        /// <summary>
        /// Update the user profile
        /// </summary>
        /// <param name="profile"></param>
        /// <returns><see cref="bool"/></returns>
        Task<bool> UpdateProfileAsync(Profile profile);
    }
}
