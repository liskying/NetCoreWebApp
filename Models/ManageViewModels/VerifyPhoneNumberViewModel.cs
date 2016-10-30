using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebApplication.Models.ManageViewModels
{
    public class VerifyPhoneNumberViewModel
    {
        [Display(Name = "验证码")]
        [Required]
        public string Code { get; set; }

        [Required]
        [Phone]
        [Display(Name = "电话号码")]
        public string PhoneNumber { get; set; }
    }
}
