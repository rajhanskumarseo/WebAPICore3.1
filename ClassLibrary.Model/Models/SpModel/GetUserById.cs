namespace ClassLibrary.Model.Models.SpModel
{
	/// <summary>
	/// Model to bind the result of getProfile stored procedure
	/// </summary>
	public class GetUserById
	{
		public string Id { get; set; }
		public string UserName { get; set; }
		public bool EmailConfirmed { get; set; }
		public string PhoneNumber { get; set; }
		public bool PhoneNumberConfirmed { get; set; }
		public bool TwoFactorEnabled { get; set; }
		public string Name { get; set; }
		public string Address1 { get; set; }
		public string Address2 { get; set; }
		public string City { get; set; }
		public string State { get; set; }
		public string Landmark { get; set; }
		public string Pin { get; set; }
		public string CountryCode { get; set; }
	}
}
