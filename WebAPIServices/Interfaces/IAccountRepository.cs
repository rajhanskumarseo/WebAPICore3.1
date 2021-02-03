using ClassLibrary.Model.Models.DbModel;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace WebAPIServices.Interfaces
{
    public interface IAccountRepository
    {
        /// <summary>
        /// Update the user profile
        /// </summary>
        /// <param name="profile"></param>
        /// <param name="currentUserId"></param>
        /// <returns><see cref="bool"/></returns>
        Task<bool> UpdateProfileAsync(Profile profile, string currentUserId);
    }
}
