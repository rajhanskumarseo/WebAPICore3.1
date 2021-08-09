using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace RepositoryServices.StaticMethods
{
    public static class EmailSender
    {
        public static async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            string fromMail = "rajhanskumarseo@gmail.com";
            string fromPassword = "ionrpfccxdpkurzh";

            MailMessage message = new MailMessage();
            message.From = new MailAddress(fromMail);
            message.Subject = subject;
            message.To.Add(new MailAddress(email));
            message.Body = "<html><body> " + htmlMessage + " </body></html>";
            message.IsBodyHtml = true;

            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential(fromMail, fromPassword),
                EnableSsl = true,
            };

            smtpClient.Send(message);
        }
    }
}
