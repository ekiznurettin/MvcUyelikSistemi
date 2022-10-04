using Mapster;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MvcUyelikSistemi.Models;
using MvcUyelikSistemi.ViewModels;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : BaseController
    {
        public AdminController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager) : base(userManager, null, roleManager)
        {
        }

        public IActionResult Index()
        {
            return View();
        }
        public IActionResult Users()
        {

            return View(UserManager.Users.ToList());
        }
        public IActionResult RoleCreate()
        {
            return View();
        }
        [HttpPost]
        public IActionResult RoleCreate(RoleViewModel roleViewModel)
        {
            AppRole role = new AppRole();
            role.Name = roleViewModel.Name;
            IdentityResult result = RoleManager.CreateAsync(role).Result;
            if (result.Succeeded)
            {
                return RedirectToAction("Roles", "Admin");
            }
            else
            {
                AddModelError(result);
            }
            return View(roleViewModel);
        }
        public IActionResult Roles()
        {

            return View(RoleManager.Roles.ToList());
        }
        [HttpPost]
        public IActionResult Delete(string Id)
        {
            AppRole role = RoleManager.FindByIdAsync(Id).Result;
            if (role != null)
            {
                IdentityResult result = RoleManager.DeleteAsync(role).Result;
            }
            return RedirectToAction("Roles");
        }
        public IActionResult Update(string Id)
        {
            AppRole role = RoleManager.FindByIdAsync(Id).Result;

            return View(role.Adapt<RoleViewModel>());
        }
        [HttpPost]
        public IActionResult Update(RoleViewModel roleViewModel)
        {
            AppRole role = RoleManager.FindByIdAsync(roleViewModel.Id).Result;

            IdentityResult result = RoleManager.UpdateAsync(role).Result;
            role.Name = roleViewModel.Name;
            if (result.Succeeded)
            {
                return RedirectToAction("Roles");
            }
            else
            {
                AddModelError(result);
            }

            return View(roleViewModel);
        }
        public IActionResult RoleAssign(string Id)
        {
            TempData["UserId"] = Id;
            AppUser user = UserManager.FindByIdAsync(Id).Result;
            ViewBag.UserName = user.UserName;
            IQueryable<AppRole> roles = RoleManager.Roles;
            IList<string> userRoles = UserManager.GetRolesAsync(user).Result;
            List<RoleAssignViewModel> roleAssignViewModels = new List<RoleAssignViewModel>();
            foreach (var role in roles)
            {
                RoleAssignViewModel roleAssignViewModel = new RoleAssignViewModel();
                roleAssignViewModel.RoleId = role.Id;
                roleAssignViewModel.RoleName = role.Name;
                if (userRoles.Contains(role.Name))
                {
                    roleAssignViewModel.Exists = true;
                }
                else
                {
                    roleAssignViewModel.Exists = false;
                }
                roleAssignViewModels.Add(roleAssignViewModel);
            }
            return View(roleAssignViewModels);
        }
        [HttpPost]
        public async Task<IActionResult> RoleAssign(List<RoleAssignViewModel> roleAssignViewModels)
        {
            AppUser user = await UserManager.FindByIdAsync(TempData["UserId"].ToString());
            foreach (var item in roleAssignViewModels)
            {
                if (item.Exists)
                {
                    await UserManager.AddToRoleAsync(user, item.RoleName);
                }
                else
                {
                    await UserManager.RemoveFromRoleAsync(user, item.RoleName);
                }
            }
            return RedirectToAction("Users");
        }
        public IActionResult Claims()
        {
            return View(User.Claims.ToList());
        }

        public async Task<IActionResult> ResetUserPassword(string Id)
        {
            AppUser user = await UserManager.FindByIdAsync(Id);
            PasswordResetByAdminViewModel passwordResetByAdminViewModel = new PasswordResetByAdminViewModel();
            passwordResetByAdminViewModel.UserId = user.Id;
            return View(passwordResetByAdminViewModel);
        }
        [HttpPost]
        public async Task<IActionResult> ResetUserPassword(PasswordResetByAdminViewModel passwordResetByAdminViewModel)
        {
            AppUser user = await UserManager.FindByIdAsync(passwordResetByAdminViewModel.UserId);
            string token = await UserManager.GeneratePasswordResetTokenAsync(user);
            await UserManager.ResetPasswordAsync(user, token, passwordResetByAdminViewModel.NewPassword);
            await UserManager.UpdateSecurityStampAsync(user);
            return RedirectToAction("Users");
        }
    }
}
