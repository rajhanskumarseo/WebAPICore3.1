using System;
using System.Collections.Generic;
using System.Text;

namespace ClassLibrary.Model.Models
{
    /// <summary>
    /// Profile request model
    /// </summary>
    public class ProfileModel
    {
        public string Address1 { get; set; }

        public string Address2 { get; set; }

        public string City { get; set; }

        public string State { get; set; }

        public string Landmark { get; set; }

        public string Pin { get; set; }

        public string CountryCode { get; set; }
    }
}
