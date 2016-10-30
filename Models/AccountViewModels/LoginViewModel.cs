using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApplication.Models.AccountViewModels
{
    public class LoginViewModel
    {
        [Display(Name = "账号[邮箱]")]
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Display(Name = "密码")]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "记住我?")]
        public bool RememberMe { get; set; }
    }
}
