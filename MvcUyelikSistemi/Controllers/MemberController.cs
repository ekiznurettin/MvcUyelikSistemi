using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using MvcUyelikSistemi.Enums;
using MvcUyelikSistemi.Models;
using MvcUyelikSistemi.TwoFactorServices;
using MvcUyelikSistemi.ViewModels;
using System;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.Controllers
{
    [Authorize]
    public class MemberController : BaseController
    {
        private readonly TwoFactorService _twoFactorService;
        public MemberController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorService twoFactorService) : base(userManager, signInManager)
        {
            _twoFactorService = twoFactorService;
        }

        public IActionResult Index()
        {
            AppUser user = CurrentUser;
            UserViewModel userViewModel = user.Adapt<UserViewModel>();

            return View(userViewModel);
        }
        public IActionResult UserEdit()
        {
            AppUser user = CurrentUser;

            UserViewModel userViewModel = user.Adapt<UserViewModel>();
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));
            return View(userViewModel);
        }
        [HttpPost]
        public async Task<IActionResult> UserEdit(UserViewModel userViewModel, IFormFile UserPicture)
        {
            ModelState.Remove("Password");
            ViewBag.Gender = new SelectList(Enum.GetNames(typeof(Gender)));
            if (ModelState.IsValid)
            {
                AppUser user = CurrentUser;
                string phoneNumber = UserManager.GetPhoneNumberAsync(user).Result;
                if (phoneNumber != userViewModel.PhoneNumber)
                {
                    if (UserManager.Users.Any(s => s.PhoneNumber == userViewModel.PhoneNumber))
                    {
                        ModelState.AddModelError("", "Bu telefon numarası daha önce eklenmiştir.");
                        return View(userViewModel);
                    }
                }

                if (UserPicture != null && UserPicture.Length > 0)
                {
                    var fileName = Guid.NewGuid().ToString() + Path.GetExtension(UserPicture.FileName);
                    var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/UserPicture", fileName);
                    using (var stream = new FileStream(path, FileMode.Create))
                    {
                        await UserPicture.CopyToAsync(stream);
                        user.Picture = "/UserPicture/" + fileName;
                    }
                }

                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;


                user.City = userViewModel.City;
                user.BirthDay = userViewModel.BirthDay;
                user.Gender = (int)userViewModel.Gender;
                IdentityResult result = await UserManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    await UserManager.UpdateSecurityStampAsync(user);
                    await SignInManager.SignOutAsync();
                    await SignInManager.SignInAsync(user, true);
                    ViewBag.status = "Success";
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(userViewModel);
        }

        public IActionResult PasswordChange()
        {
            return View();
        }
        [HttpPost]
        public IActionResult PasswordChange(PasswordChangeViewModel passwordChangeViewModel)
        {
            if (ModelState.IsValid)
            {
                AppUser user = CurrentUser;
                if (user != null)
                {
                    bool exists = UserManager.CheckPasswordAsync(user, passwordChangeViewModel.OldPassword).Result;
                    if (exists)
                    {
                        IdentityResult result = UserManager.ChangePasswordAsync(user, passwordChangeViewModel.OldPassword, passwordChangeViewModel.NewPassword).Result;
                        if (result.Succeeded)
                        {
                            UserManager.UpdateSecurityStampAsync(user);
                            SignInManager.SignOutAsync();
                            SignInManager.PasswordSignInAsync(user, passwordChangeViewModel.NewPassword, true, false);
                            ViewBag.status = "Success";
                        }
                        else
                        {
                            AddModelError(result);
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "Eski şifreniz yanlış");
                    }
                }
            }
            return View(passwordChangeViewModel);
        }

        public IActionResult AccessDenied(string ReturnUrl)
        {
            if (ReturnUrl.Contains("Violance"))
            {
                ViewBag.Message = "Erişmeye şalıştığınız sayfa şiddet videoları içerdiğinden dolayı 15 yaşından büyük olmanız gerekmektedir.";
            }
            else if (ReturnUrl.Contains("AnkaraSayfasi"))
            {
                ViewBag.Message = "Bu sayfaya erişebilmeniz için şehir alanınızın ankara olması gerekmektedir.";
            }
            else if (ReturnUrl.Contains("ExChange"))
            {
                ViewBag.Message = "30 günlük deneme süreniz sona ermiştir.";
            }
            else
            {
                ViewBag.Message = "Bu sayfaya erişim izniniz yoktur. İzin almak için site yöneticiniz ile görüşünüz.";
            }
            return View();
        }

        public void Logout()
        {
            SignInManager.SignOutAsync();
        }
        [Authorize(Roles = "Editor,Admin")]
        public IActionResult Editor()
        {
            return View();
        }
        [Authorize(Roles = "Manager,Admin")]
        public IActionResult Manager()
        {
            return View();
        }
        [Authorize(Policy = "AnkaraPolicy")]
        public IActionResult AnkaraSayfasi()
        {
            return View();
        }

        [Authorize(Policy = "ViolancePolicy")]
        public IActionResult Violance()
        {
            return View();
        }

        public async Task<IActionResult> ExchangeRedirect()
        {
            bool result = User.HasClaim(x => x.Type == "ExpireDateExchange");
            if (!result)
            {
                Claim ExpireDateExchange = new Claim("ExpireDateExchange", DateTime.Now.AddDays(30).Date.ToShortDateString(), ClaimValueTypes.String, "Internal");
                await UserManager.AddClaimAsync(CurrentUser, ExpireDateExchange);
                await SignInManager.SignOutAsync();
                await SignInManager.SignInAsync(CurrentUser, true);
            }
            return RedirectToAction("ExChange");
        }
        [Authorize(Policy = "ExchangePolicy")]
        public IActionResult ExChange()
        {
            return View();
        }

        public async Task<IActionResult> TwoFactorWithAuthenticator()
        {
            string unformattedKey = await UserManager.GetAuthenticatorKeyAsync(CurrentUser);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await UserManager.ResetAuthenticatorKeyAsync(CurrentUser);
                unformattedKey = await UserManager.GetAuthenticatorKeyAsync(CurrentUser);
            }
            AuthenticatorViewModel authenticatorViewModel = new AuthenticatorViewModel();
            authenticatorViewModel.SharedKey = unformattedKey;
            authenticatorViewModel.AuthenticationUri = _twoFactorService.GenerateQrCodeUrl(CurrentUser.Email, unformattedKey);
            return View(authenticatorViewModel);
        }
        [HttpPost]
        public async Task<IActionResult> TwoFactorWithAuthenticator(AuthenticatorViewModel authenticatorViewModel)
        {
            var verificationCode = authenticatorViewModel.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);
            var is2FATokenValid = await UserManager.VerifyTwoFactorTokenAsync(CurrentUser, UserManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
            if (is2FATokenValid)
            {
                CurrentUser.TwoFactorEnabled = true;
                CurrentUser.TwoFactor = (sbyte)TwoFactor.MicrosoftGoogle;
                var recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(CurrentUser, 5);
                TempData["recoveryCodes"] = recoveryCodes;
                TempData["message"] = "İki Adımlı Kimlik Doğrumala Tipiniz Google/Microsoft Olarak Belirlenmiştir.";
                return RedirectToAction("TwoFactorAuth");
            }
            else
            {
                ModelState.AddModelError("", "Girdiğiniz kurtarma kodu yanlıştır");
                return View(authenticatorViewModel);
            }
        }

        public IActionResult TwoFactorAuth()
        {
            return View(new AuthenticatorViewModel() { TwoFactorType = (TwoFactor)CurrentUser.TwoFactor });
        }
        [HttpPost]
        public async Task<IActionResult> TwoFactorAuth(AuthenticatorViewModel authenticatorViewModel)
        {
            switch (authenticatorViewModel.TwoFactorType)
            {
                case TwoFactor.None:
                    CurrentUser.TwoFactorEnabled = false;
                    TempData["message"] = "İki Adımlı Kimlik Doğrumala Tipiniz Hiçbiri olarak Belirlenmiştir.";
                    break;
                case TwoFactor.Phone:
                    if (string.IsNullOrEmpty(CurrentUser.PhoneNumber))
                    {
                        ViewBag.warning = "Sistemde telefon numaranız kayıtlı değil. Lütfen kullanıcı güncelleme sayfasından telefon numaranızı belirtiniz";
                    }
                    CurrentUser.TwoFactorEnabled = true;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.Phone;
                    TempData["message"] = "İki Adımlı Kimlik Doğrumala Tipiniz Telefon olarak Belirlenmiştir.";
                    break;
                case TwoFactor.Email:
                    CurrentUser.TwoFactorEnabled = true;
                    CurrentUser.TwoFactor = (sbyte)TwoFactor.Email;
                    TempData["message"] = "İki Adımlı Kimlik Doğrumala Tipiniz Email olarak Belirlenmiştir.";
                    break;
                case TwoFactor.MicrosoftGoogle:
                    return RedirectToAction("TwoFactorWithAuthenticator");
                default:
                    CurrentUser.TwoFactorEnabled = false;
                    break;
            }
            await UserManager.UpdateAsync(CurrentUser);
            return View(authenticatorViewModel);
        }
    }
}
