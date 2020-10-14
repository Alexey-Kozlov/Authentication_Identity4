#pragma checksum "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "ae0e876872a3ab88b3488b3c0b18168d1a670895"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Shared__ScopeListItem), @"mvc.1.0.view", @"/Views/Shared/_ScopeListItem.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Shared/_ScopeListItem.cshtml", typeof(AspNetCore.Views_Shared__ScopeListItem))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"ae0e876872a3ab88b3488b3c0b18168d1a670895", @"/Views/Shared/_ScopeListItem.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"b35857dd199098649926cf8d40cf1622e149676b", @"/Views/_ViewImports.cshtml")]
    public class Views_Shared__ScopeListItem : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<Authentication.Models.ScopeViewModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(44, 152, true);
            WriteLiteral("\n<li class=\"list-group-item\">\n    <label>\n        <input class=\"consent-scopecheck\"\n               type=\"checkbox\"\n               name=\"ScopesConsented\"");
            EndContext();
            BeginWriteAttribute("id", "\n               id=\"", 196, "\"", 235, 2);
            WriteAttributeValue("", 216, "scopes_", 216, 7, true);
#line 8 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
WriteAttributeValue("", 223, Model.Value, 223, 12, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginWriteAttribute("value", "\n               value=\"", 236, "\"", 271, 1);
#line 9 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
WriteAttributeValue("", 259, Model.Value, 259, 12, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginWriteAttribute("checked", "\n               checked=\"", 272, "\"", 311, 1);
#line 10 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
WriteAttributeValue("", 297, Model.Checked, 297, 14, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginWriteAttribute("disabled", "\n               disabled=\"", 312, "\"", 353, 1);
#line 11 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
WriteAttributeValue("", 338, Model.Required, 338, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(354, 4, true);
            WriteLiteral(" />\n");
            EndContext();
#line 12 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
         if (Model.Required)
        {

#line default
#line hidden
            BeginContext(397, 74, true);
            WriteLiteral("            <input type=\"hidden\"\n                   name=\"ScopesConsented\"");
            EndContext();
            BeginWriteAttribute("value", "\n                   value=\"", 471, "\"", 510, 1);
#line 16 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
WriteAttributeValue("", 498, Model.Value, 498, 12, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(511, 4, true);
            WriteLiteral(" />\n");
            EndContext();
#line 17 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
        }

#line default
#line hidden
            BeginContext(525, 16, true);
            WriteLiteral("        <strong>");
            EndContext();
            BeginContext(542, 17, false);
#line 18 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
           Write(Model.DisplayName);

#line default
#line hidden
            EndContext();
            BeginContext(559, 10, true);
            WriteLiteral("</strong>\n");
            EndContext();
#line 19 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
         if (Model.Emphasize)
        {

#line default
#line hidden
            BeginContext(609, 71, true);
            WriteLiteral("            <span class=\"glyphicon glyphicon-exclamation-sign\"></span>\n");
            EndContext();
#line 22 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
        }

#line default
#line hidden
            BeginContext(690, 13, true);
            WriteLiteral("    </label>\n");
            EndContext();
#line 24 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
     if (Model.Required)
    {

#line default
#line hidden
            BeginContext(734, 41, true);
            WriteLiteral("        <span><em>(required)</em></span>\n");
            EndContext();
#line 27 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
    }

#line default
#line hidden
            BeginContext(781, 4, true);
            WriteLiteral("    ");
            EndContext();
#line 28 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
     if (Model.Description != null)
    {

#line default
#line hidden
            BeginContext(823, 60, true);
            WriteLiteral("        <div class=\"consent-description\">\n            <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 883, "\"", 908, 2);
            WriteAttributeValue("", 889, "scopes_", 889, 7, true);
#line 31 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
WriteAttributeValue("", 896, Model.Value, 896, 12, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(909, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(911, 17, false);
#line 31 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
                                        Write(Model.Description);

#line default
#line hidden
            EndContext();
            BeginContext(928, 24, true);
            WriteLiteral("</label>\n        </div>\n");
            EndContext();
#line 33 "C:\Users\akozlov\source\repos\TestAuthentication\Authentication\Authentication\Views\Shared\_ScopeListItem.cshtml"
    }

#line default
#line hidden
            BeginContext(958, 5, true);
            WriteLiteral("</li>");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<Authentication.Models.ScopeViewModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
