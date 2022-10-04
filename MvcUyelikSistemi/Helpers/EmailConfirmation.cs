using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.Helpers
{
    public static class EmailConfirmation
    {

        public static void SendEmail(string link, string email)
        {
            MailMessage mail = new MailMessage();
            SmtpClient smtpClient = new SmtpClient("mail.tecnohub.net");
            mail.From = new MailAddress("fcakiroglu@tecnohub.net");
            mail.To.Add(email);
            mail.Subject = $"www.bıdıbıdı.com: Email Doğrulama";
            mail.Body = "<h2>Email adresinizi doğrulamak için lütfen aşağıdaki linki tıklayınız.</h3>";
            mail.Body += $"<a href='{link}'> email doğrulama linki";
            smtpClient.Port = 587;
            smtpClient.Credentials = new NetworkCredential("fcakiroglu@tecnohub.net", "FatihFatih30");
            smtpClient.Send(mail);
        }
    }
}
