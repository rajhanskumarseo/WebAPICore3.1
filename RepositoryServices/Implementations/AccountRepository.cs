using ClassLibrary.Model.Models.DbModel;
using DataAccessLayer;
using RepositoryServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RepositoryServices.Implementations
{
    public class AccountRepository : IAccountRepository
    {
        private readonly ApplicationDbContext databaseContext;

        public AccountRepository(ApplicationDbContext databaseContext)
        {
            this.databaseContext = databaseContext;
        }

        public async Task<bool> UpdateProfileAsync(Profile profile, string currentUserId)
        {
            try
            {
                var profileInfo = databaseContext.Profiles.FirstOrDefault(x => x.UserId == currentUserId);

                if (profileInfo != null)
                {
                    profile.Id = profileInfo.Id;
                    profile.UserId = !string.IsNullOrEmpty(profile.UserId) ? profile.UserId : profileInfo.UserId;
                    profile.Address1 = !string.IsNullOrEmpty(profile.Address1) ? profile.Address1 : profileInfo.Address1;
                    profile.Address2 = !string.IsNullOrEmpty(profile.Address2) ? profile.Address2 : profileInfo.Address2;
                    profile.City = !string.IsNullOrEmpty(profile.City) ? profile.City : profileInfo.City;
                    profile.State = !string.IsNullOrEmpty(profile.State) ? profile.State : profileInfo.State;
                    profile.Landmark = !string.IsNullOrEmpty(profile.Landmark) ? profile.Landmark : profileInfo.Landmark;
                    profile.Pin = !string.IsNullOrEmpty(profile.Pin) ? profile.Pin : profileInfo.Pin;
                    profile.CountryCode = !string.IsNullOrEmpty(profile.CountryCode) ? profile.CountryCode : profileInfo.CountryCode;


                    databaseContext.Entry(profileInfo).CurrentValues.SetValues(profile);


                    await databaseContext.SaveChangesAsync();

                    return true;
                }

                return false;
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}
