using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using ClassLibrary.Model.Models.DbModel;

namespace RepositoryServices.Interfaces
{
    public interface IAccountRepository
    {
        Task<bool> UpdateProfileAsync(Profile profile, string currentUserId);
    }
}
