using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.TwoFactorServices
{
    public class EmailSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public EmailSender(IOptions<TwoFactorOptions> twoFactorOptions, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = twoFactorOptions.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string emailAddress)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();
            Execute(emailAddress, code).Wait();
            return code;
        }

        private async Task Execute(string Email, string Code)
        {
            var client = new SendGridClient(_twoFactorOptions.SendGrid_ApiKey);
            var from = new EmailAddress("ekiznurettin@hotmail.com");
            var subject = "İki adımlı kimlik doğrulama kodunuz";
            var to = new EmailAddress(Email);
            var htmlContent = $"<h2>Siteye girmek için doğrulama kodunuz aşagıdadır</h2></br><h3>Kodunuz: {Code}</h3>";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, null, htmlContent);
            var response = await client.SendEmailAsync(msg);
        }
    }
}
