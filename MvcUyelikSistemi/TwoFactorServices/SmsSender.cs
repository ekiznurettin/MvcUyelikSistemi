using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.TwoFactorServices
{
    public class SmsSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public SmsSender(IOptions<TwoFactorOptions> twoFactorOptions, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = twoFactorOptions.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string phoneNumber)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();
            //SMS provider kodları olacak sonra direkt olarak çalıştır
            return code;
        }
    }
}
