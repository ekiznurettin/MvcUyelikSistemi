using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MvcUyelikSistemi.Enums;
using MvcUyelikSistemi.Helpers;
using MvcUyelikSistemi.Models;
using MvcUyelikSistemi.TwoFactorServices;
using MvcUyelikSistemi.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.Controllers
{
    public class HomeController : BaseController
    {
        private readonly TwoFactorService _twoFactorService;
        private readonly EmailSender _emailSender;
        private readonly EmailSender _smsSender;

        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorService twoFactorService, EmailSender emailSender, EmailSender smsSender) : base(userManager, signInManager)
        {
            _twoFactorService = twoFactorService;
            _emailSender = emailSender;
            _smsSender = smsSender;
        }

        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Member");
            }
            return View();
        }
        public IActionResult Login(string ReturnUrl = "/")
        {
            TempData["ReturnUrl"] = ReturnUrl;
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel userLogin)
        {
            if (ModelState.IsValid)
            {
                AppUser user = await UserManager.FindByEmailAsync(userLogin.Email);
                if (user != null)
                {
                    if (await UserManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("", "Hesabınız bir süreliğine askıya alınmıştır. Lütfen daha sonra tekrar deneyiniz.");
                        return View(userLogin);
                    }
                    if (!UserManager.IsEmailConfirmedAsync(user).Result)
                    {
                        ModelState.AddModelError("", "Email adresiniz doğrulanmamıştır. Lütfen epostanızı kontrol ediniz.");
                        return View(userLogin);
                    }
                    bool userCheck = await UserManager.CheckPasswordAsync(user, userLogin.Password);
                    if (userCheck)
                    {
                        await UserManager.ResetAccessFailedCountAsync(user);
                        await SignInManager.SignOutAsync();
                        var result = await SignInManager.PasswordSignInAsync(user, userLogin.Password, userLogin.RememberMe, false);
                        if (result.RequiresTwoFactor)
                        {
                            if (user.TwoFactor == (int)TwoFactor.Email || user.TwoFactor == (int)TwoFactor.Phone)
                                HttpContext.Session.Remove("currentTime");
                            return RedirectToAction("TwoFactorLogin", "Home", new { ReturnUrl = TempData["ReturnUrl"].ToString() });
                        }
                        else
                        {
                            if (TempData["ReturnUrl"] != null)
                            {
                                return Redirect(TempData["ReturnUrl"].ToString());
                            }
                            return RedirectToAction("Index", "Member");
                        }
                    }
                    else
                    {
                        await UserManager.AccessFailedAsync(user);
                        int fail = await UserManager.GetAccessFailedCountAsync(user);
                        ModelState.AddModelError("", "Başarısız giriş sayısı: " + fail);

                        if (fail >= 3)
                        {
                            await UserManager.SetLockoutEndDateAsync(user, new DateTimeOffset(DateTime.Now.AddMinutes(10)));
                            ModelState.AddModelError("", "Hesabınız 3 başarısız giriş yapıldığı için 10 dakika askıya alınmıştır.");
                        }
                        ModelState.AddModelError("", "Geçersiz email adresi ya da şifre");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Geçersiz email adresi ya da şifre");
                }
            }
            return View(userLogin);
        }

        public async Task<IActionResult> TwoFactorLogin(string ReturnUrl = "/")
        {
            var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();
            TempData["ReturnUrl"] = ReturnUrl;
            switch ((TwoFactor)user.TwoFactor)
            {
                case TwoFactor.MicrosoftGoogle:
                    break;
                case TwoFactor.Email:
                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("Login");
                    }
                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                    HttpContext.Session.SetString("codeVerification", _emailSender.Send(user.Email));
                    break;
                case TwoFactor.Phone:
                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("Login");
                    }
                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                    HttpContext.Session.SetString("codeVerification", _smsSender.Send(user.PhoneNumber));
                    break;
            }
            return View(new TwoFactorLoginViewModel() { TwoFactorType = (TwoFactor)user.TwoFactor, IsRecoveryCode = false, IsRememberMe = false, VerificationCode = string.Empty });
        }
        [HttpPost]
        public async Task<IActionResult> TwoFactorLogin(TwoFactorLoginViewModel twoFactorLoginViewModel)
        {
            var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();
            ModelState.Clear();
            bool isSuccessAuth = false;
            if (user.TwoFactor == (sbyte)TwoFactor.MicrosoftGoogle)
            {
                Microsoft.AspNetCore.Identity.SignInResult result = null;
                if (twoFactorLoginViewModel.IsRecoveryCode)
                {
                    result = await SignInManager.TwoFactorRecoveryCodeSignInAsync(twoFactorLoginViewModel.VerificationCode);
                }
                else
                {
                    result = await SignInManager.TwoFactorAuthenticatorSignInAsync(twoFactorLoginViewModel.VerificationCode, twoFactorLoginViewModel.IsRememberMe, false);
                }
                if (result.Succeeded)
                {
                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama kodu yanlış");
                }
            }
            else if (user.TwoFactor == (sbyte)TwoFactor.Email || user.TwoFactor == (sbyte)TwoFactor.Phone)
            {
                ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                if (twoFactorLoginViewModel.VerificationCode == HttpContext.Session.GetString("codeVerification"))
                {
                    await SignInManager.SignOutAsync();
                    await SignInManager.SignInAsync(user, twoFactorLoginViewModel.IsRememberMe);
                    HttpContext.Session.Remove("currentTime");
                    HttpContext.Session.Remove("codeVerification");
                    isSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama kodunuz yanlış");
                }
            }
            if (isSuccessAuth)
            {
                return Redirect(TempData["ReturnUrl"].ToString());
            }
            twoFactorLoginViewModel.TwoFactorType = (TwoFactor)user.TwoFactor;
            return View(twoFactorLoginViewModel);
        }
        public IActionResult SignUp()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> SignUp(UserViewModel userViewModel)
        {
            if (ModelState.IsValid)
            {
                if (UserManager.Users.Any(u => u.PhoneNumber == userViewModel.PhoneNumber))
                {
                    ModelState.AddModelError("", "Bu telefon numarası daha önce eklenmiştir.");
                    return View(userViewModel);
                }

                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.TwoFactor = (int)TwoFactor.None;
                IdentityResult result = await UserManager.CreateAsync(user, userViewModel.Password);
                if (result.Succeeded)
                {
                    string confirmationToken = await UserManager.GenerateEmailConfirmationTokenAsync(user);
                    string link = Url.Action("ConfirmEmail", "Home", new { userId = user.Id, token = confirmationToken }, protocol: HttpContext.Request.Scheme);
                    //  EmailConfirmation.SendEmail(link, user.Email);//Mail servisi olmadığı için kapattım
                    return RedirectToAction("Login");
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(userViewModel);
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ResetPassword(PasswordResetViewModel passwordResetViewModel)
        {
            AppUser user = UserManager.FindByEmailAsync(passwordResetViewModel.Email).Result;
            if (user != null)
            {
                string passwordResetToken = UserManager.GeneratePasswordResetTokenAsync(user).Result;
                string passwordResetLink = Url.Action("PasswordResetConfirm", "Home", new { userId = user.Id, token = passwordResetToken }, HttpContext.Request.Scheme);
                PasswordReset.PasswordResetSendEmail(passwordResetLink, passwordResetViewModel.Email);
                ViewBag.status = "Success";
            }
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı email adresi bulunamamıştır.");
            }
            return View(passwordResetViewModel);
        }

        public IActionResult PasswordResetConfirm(string userId, string token)
        {
            TempData["UserId"] = userId;
            TempData["Token"] = token;

            return View();
        }
        [HttpPost]
        public async Task<IActionResult> PasswordResetConfirm([Bind("PasswordNew")] PasswordResetViewModel passwordResetViewModel)
        {
            string token = TempData["Token"].ToString();
            string userId = TempData["UserId"].ToString();
            AppUser user = await UserManager.FindByIdAsync(userId);
            if (user != null)
            {
                IdentityResult result = await UserManager.ResetPasswordAsync(user, token, passwordResetViewModel.PasswordNew);
                if (result.Succeeded)
                {
                    await UserManager.UpdateSecurityStampAsync(user);
                    ViewBag.status = "Success";
                }
                else
                {
                    AddModelError(result);
                }
            }
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı kullanıcı bulunamadı");
            }
            return View(passwordResetViewModel);
        }
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await UserManager.FindByIdAsync(userId);
            IdentityResult result = await UserManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                ViewBag.status = "Email adresiniz doğrulanmıştır. Login ekranından giriş yapabilirsiniz.";
            }
            else
            {
                ViewBag.status = "Bir sorun oluştu. Lütfen daha sonra yeniden deneyiniz";
            }

            return View();
        }
        //Facobook ile giriş işlemleri  
        public IActionResult FacebookLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var property = SignInManager.ConfigureExternalAuthenticationProperties("Facebook", RedirectUrl);

            return new ChallengeResult("Facebook", property);
        }

        public IActionResult GoogleLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var property = SignInManager.ConfigureExternalAuthenticationProperties("Google", RedirectUrl);

            return new ChallengeResult("Google", property);
        }

        public IActionResult MicrosoftLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var property = SignInManager.ConfigureExternalAuthenticationProperties("Microsoft", RedirectUrl);

            return new ChallengeResult("Microsoft", property);
        }

        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            ExternalLoginInfo info = await SignInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Login");
            }
            else
            {
                Microsoft.AspNetCore.Identity.SignInResult result = await SignInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                if (result.Succeeded)
                {
                    return Redirect(ReturnUrl);
                }
                else
                {
                    AppUser user = new AppUser();
                    user.Email = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    string ExternalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                    if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                    {
                        string userName = info.Principal.FindFirst(ClaimTypes.Name).Value;
                        userName = userName.Replace(' ', '_').ToLower() + ExternalUserId.Substring(0, 5).ToString();
                        user.UserName = userName;
                    }
                    else
                    {
                        user.UserName = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    }
                    AppUser user2 = await UserManager.FindByEmailAsync(user.Email);
                    if (user2 != null)
                    {
                        IdentityResult loginResult = await UserManager.AddLoginAsync(user, info);
                        await SignInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                        return Redirect(ReturnUrl);
                    }
                    IdentityResult createResult = await UserManager.CreateAsync(user);

                    if (createResult.Succeeded)
                    {
                        IdentityResult loginResult = await UserManager.AddLoginAsync(user, info);
                        if (loginResult.Succeeded)
                        {
                            // await SignInManager.SignInAsync(user, true);
                            await SignInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                            return Redirect(ReturnUrl);
                        }
                        else
                        {
                            AddModelError(loginResult);
                        }
                    }
                    else
                    {
                        AddModelError(createResult);
                    }
                }
            }
            List<string> errors = ModelState.Values.SelectMany(x => x.Errors).Select(y => y.ErrorMessage).ToList();
            return View("Error", errors);
        }
        public IActionResult Error()
        {
            return View();
        }

        public JsonResult AgainSendEmail()
        {
            try
            {
                var user = SignInManager.GetTwoFactorAuthenticationUserAsync().Result;
                HttpContext.Session.SetString("codeVerification", _emailSender.Send(user.Email));
                return Json(true);
            }
            catch (Exception)
            {
                //Loglama yap 
                return Json(false);
            }
        }
    }

}
