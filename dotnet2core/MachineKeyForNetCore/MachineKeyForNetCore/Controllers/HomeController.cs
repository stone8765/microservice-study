using NetStandardLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace MachineKeyForNetCore.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var purpose = "AA";
            var text = "StoneLi";
            var buffer = Encoding.UTF8.GetBytes(text);
            var protectBuffer = MachineKey.Protect(buffer, purpose);
            ViewBag.AspNet = Convert.ToBase64String(protectBuffer);

            return View();
        }
    }
}