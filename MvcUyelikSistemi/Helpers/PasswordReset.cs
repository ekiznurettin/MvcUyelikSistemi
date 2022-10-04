using System.Net;
using System.Net.Mail;

namespace MvcUyelikSistemi.Helpers
{
    public class PasswordReset
    {
        public static void PasswordResetSendEmail(string link,string email)
        {
            MailMessage mail = new MailMessage();
            SmtpClient smtpClient = new SmtpClient("mail.tecnohub.net");
            mail.From = new MailAddress("fcakiroglu@tecnohub.net");
            mail.To.Add(email);
            mail.Subject = $"www.bıdıbıdı.com: Şifre Sıfırlama";
            mail.Body = "<h2>Şifrenizi yenilemek için lütfen aşağıdaki linki tıklayınız.</h3>";
            mail.Body += $"<a href='{link}'> şifre yenileme linki";
            smtpClient.Port = 587;
            smtpClient.Credentials = new NetworkCredential("fcakiroglu@tecnohub.net","FatihFatih30");
            smtpClient.Send(mail);
        }
    }
}
